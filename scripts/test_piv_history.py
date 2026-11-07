# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""History replay and reduction controls, without importing USB transports."""

import importlib.util
from pathlib import Path
import sys

import pytest

path = Path(__file__).resolve().parents[1] / "tests/piv_history.py"
spec = importlib.util.spec_from_file_location("piv_history_model", path)
history = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = history
spec.loader.exec_module(history)


def test_full_width_seed_and_parameters_survive_round_trip():
    seed = 2**64 - 1
    operations = history.generate(seed, 256, True)
    assert history.decode(history.manifest(seed, operations, {})) == (seed, operations)
    assert history.generate(seed, 256, True) == operations
    assert any(item.kind == history.Kind.RSA for item in operations)
    assert any(item.kind == history.Kind.REBOOT for item in operations)


def test_removing_operations_keeps_payloads_and_stable_ids():
    operations = history.generate(7, 128)
    kept = [item for item in operations if item.kind == history.Kind.PUT][::2]
    assert kept
    before = {item.id: history.payload(7, item) for item in operations}
    assert all(history.payload(7, item) == before[item.id] for item in kept)


@pytest.mark.parametrize("field,value", [("id", 0), ("kind", "unknown"),
                                         ("argument", 100), ("length", 999999)])
def test_malformed_operations_are_rejected(field, value):
    document = history.manifest(1, [history.Operation(1, history.Kind.PUT, 0, 1)], {})
    document["operations"][0][field] = value
    with pytest.raises(ValueError):
        history.decode(document)


def test_reducer_preserves_cause_and_refuses_earlier_errors():
    operations = [history.Operation(index, history.Kind.PUT, 0, 1) for index in range(1, 10)]
    target = history.Failure("reset", 0xFB, 0x6581, ("retained", 0xD671))
    calls = []
    def execute(items):
        ids = {item.id for item in items}
        calls.append(ids)
        if {2, 7} <= ids:
            return target
        if 2 not in ids:
            return history.Failure("history", 0xDB, 0x6982)
        return history.Failure("reset", 0xFB, 0x6581, ("reserve", 0xD1FE))
    reduced = history.minimize(operations, target, execute)
    assert {item.id for item in reduced} == {2, 7}
    assert any(2 not in ids for ids in calls)
    assert any(7 not in ids for ids in calls)


@pytest.mark.parametrize("failure", [history.Failure("reset", 0xFB, 0x6A80),
                                     history.Failure("history", 0xDB, 0x6581)])
def test_non_target_failures_cannot_be_reduced(failure):
    with pytest.raises(ValueError):
        history.minimize([], failure, lambda items: failure)


@pytest.mark.parametrize("seed", [0, 1, 400, 2**64 - 1])
def test_arm_backend_receives_a_full_width_hex_seed(tmp_path, seed):
    import json
    import subprocess

    root = Path(__file__).resolve().parents[1]
    image = tmp_path / "image.elf"
    image.write_bytes(b"synthetic image placeholder")
    captured = tmp_path / "arguments.json"
    emulator = tmp_path / "capture-emulator"
    emulator.write_text(
        f"#!{sys.executable}\n"
        "# SPDX-License-Identifier: AGPL-3.0-only\n"
        "# Copyright (C) 2026 RS-Key contributors\n"
        "import json,sys\n"
        f"from pathlib import Path\nPath({str(captured)!r}).write_text(json.dumps(sys.argv[1:]))\n"
    )
    emulator.chmod(0o755)
    result = subprocess.run(
        [sys.executable, str(root / "tools/diagnostics/piv_history.py"),
         "--emulator", str(emulator), "--image", str(image), "--seed", str(seed),
         "--seeds", "1", "--steps", "1", "--output", str(tmp_path / "history")],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "emulator exited:" in result.stderr, result.stderr
    arguments = json.loads(captured.read_text())
    encoded = arguments[arguments.index("--seed") + 1]
    assert len(bytes.fromhex(encoded)) == 8
    assert int(encoded, 16) == seed


def test_replay_refuses_a_changed_emulator_transport(tmp_path, monkeypatch, capsys):
    import json

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location(
        "piv_history_diagnostic", root / "tools/diagnostics/piv_history.py")
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    for relative in ("tools/diagnostics/piv_history.py", "tools/emu/Cargo.lock",
                     "tests/piv_history.py", "tests/piv_history_run.py",
                     "tests/102_piv_factory_reset.py", "tests/80_piv.py", "tests/emu.py"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / relative).read_bytes())
    emulator = tmp_path / "emulator"
    emulator.write_bytes(b"unused emulator placeholder")
    monkeypatch.setattr(diagnostic, "ROOT", tmp_path)
    monkeypatch.setattr(diagnostic, "__file__", str(tmp_path / "tools/diagnostics/piv_history.py"))
    monkeypatch.setattr(diagnostic.subprocess, "check_output", lambda *args, **kwargs: "fixed-head\n")
    records = []
    monkeypatch.setattr(diagnostic, "run_case", lambda args, directory, seed, operations, identity:
                        records.append(diagnostic.manifest(seed, operations, identity)))
    common = ["piv_history.py", "--emulator", str(emulator), "--seeds", "1", "--steps", "1"]
    monkeypatch.setattr(sys, "argv", [*common, "--output", str(tmp_path / "generated")])
    assert diagnostic.main() == 0
    assert len(records) == 1
    replay = tmp_path / "history.json"
    replay.write_text(json.dumps(records[0]))
    (tmp_path / "tests/emu.py").write_text("# Changed emulator transport\n")
    monkeypatch.setattr(sys, "argv", [*common, "--output", str(tmp_path / "replayed"),
                                    "--replay", str(replay)])
    with pytest.raises(SystemExit) as error:
        diagnostic.main()
    assert error.value.code == 2
    assert "replay identity differs: runner_sha256" in capsys.readouterr().err
    assert len(records) == 1, "changed transport must be rejected before executing the history"


def test_image_reboots_and_new_seeds_do_not_rebind_retained_listener_ports(tmp_path, monkeypatch):
    from types import SimpleNamespace

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location(
        "piv_history_ports", root / "tools/diagnostics/piv_history.py")
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    bound = set()
    launches = []

    class Probe:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            if address in bound:
                raise OSError("image listener still in TIME_WAIT")
            bound.add(address)

    def launch(command, **kwargs):
        launches.append(command)
        return SimpleNamespace(poll=lambda: None, terminate=lambda: None,
                               wait=lambda **kwargs: None)

    monkeypatch.setattr(diagnostic.socket, "socket", lambda *args: Probe())
    monkeypatch.setattr(diagnostic.subprocess, "Popen", launch)
    monkeypatch.setattr(diagnostic.Backend, "inspect", lambda *args: "ok ready=true dead=false")
    monkeypatch.setattr(diagnostic.emu, "EmuCard", lambda: SimpleNamespace(
        connect=lambda: None, disconnect=lambda: None))
    monkeypatch.setenv("RSK_EMU_CCID", "unused")
    args = SimpleNamespace(port=20029, image=tmp_path / "image", emulator=tmp_path / "emulator")
    first = diagnostic.Backend(args, tmp_path, 1)
    first.reboot(first.start())
    first.stop()
    second = diagnostic.Backend(args, tmp_path, 2)
    second.start()
    second.stop()
    ports = [int(command[command.index("--inspect-port") + 1]) for command in launches]
    assert len(ports) == len(set(ports)) == 3
    assert diagnostic.os.environ["RSK_EMU_CCID"] == f"127.0.0.1:{ports[-1] - 1}"
