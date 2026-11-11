# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Refused image commands cannot leak an accumulated response body."""

import argparse
import errno
import importlib.util
import os
from pathlib import Path
from queue import SimpleQueue
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def laboratory(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tests"))
    monkeypatch.syspath_prepend(str(ROOT / "tools/emu"))
    spec = importlib.util.spec_from_file_location("image_assurance", ROOT / "tools/emu/image_assurance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    device = module.Device.__new__(module.Device)
    device.hid = object()
    device.cid = bytes(4)
    device.image = None
    return module, device


@pytest.fixture
def hostile():
    spec = importlib.util.spec_from_file_location("hostile", ROOT / "tests/97_trustzone_isolation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("chained", [False, True])
def test_apdu_refusal_does_not_return_direct_or_chained_plaintext(laboratory, chained):
    _, device = laboratory
    replies = iter([([0x5A], 0x61, 1), ([0xA5], 0x69, 0x82)] if chained else
                   [([0x5A], 0x69, 0x82)])

    class Card:
        def transmit(self, command):
            return next(replies)

    device.card = Card()
    with pytest.raises(AssertionError, match="APDU refusal 6982 returned"):
        device.apdu(bytes.fromhex("0087119d"), 0x6982)


def test_ctap_refusal_does_not_return_a_decodable_partial_map(laboratory, monkeypatch):
    module, device = laboratory
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x33\xa0")
    with pytest.raises(AssertionError, match="CTAP refusal returned a partial response"):
        device.ctap(2, expected=0x33)


def test_empty_refusals_and_successful_payloads_still_pass(laboratory, monkeypatch):
    module, device = laboratory

    class Card:
        def transmit(self, command):
            return [], 0x69, 0x82

    device.card = Card()
    assert device.apdu(bytes.fromhex("0087119d"), 0x6982) == b""
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x33")
    assert device.ctap(2, expected=0x33) is None
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x00\xa0")
    assert device.ctap(2) == {}


@pytest.mark.parametrize("response,error", [
    (b"\x00\x00\x00\x00\xbf\x00\x01\x01", "diagnostic missing"),
    (b"\x00\x00\x00\x00\xfe\x00\x04\x00\x00\x00\x00", "did not complete"),
    (b"\x00\x00\x00\x00\xfe\x00\x04\x01\x00\x00\x00", None),
])
def test_gateway_image_requires_completed_probes_and_a_live_worker(laboratory, monkeypatch, response, error):
    module, device = laboratory
    writes, commands = [], []
    monkeypatch.setattr(module, "write", lambda hid, payload: writes.append(payload))
    monkeypatch.setattr(module, "read", lambda hid: response)
    monkeypatch.setattr(device, "ctap", lambda command: commands.append(command) or {})
    if error:
        with pytest.raises(AssertionError, match=error):
            module.gateway_probes(device)
        assert commands == []
    else:
        module.gateway_probes(device)
        assert commands == [4]
    assert writes == [device.cid + b"\xfe\x00\x08gateways"]


def test_msc_waits_until_the_owned_disk_can_be_opened(laboratory, tmp_path, monkeypatch):
    import image_msc

    node = tmp_path / "vhci_hcd.0" / "5-1"
    interface = node / "5-1:1.0"
    block = interface / "host0" / "block" / "sda"
    block.mkdir(parents=True)
    (block / "size").write_text("262144\n")
    (block / "dev").write_text("8:0\n")
    (interface / "driver").symlink_to(tmp_path / "usb-storage")
    disk = tmp_path / "sda"
    disk.touch()
    info = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 0))
    original_stat = Path.stat

    def disk_stat(path, **kwargs):
        return info if path == disk else original_stat(path, **kwargs)

    handle = MagicMock()
    not_registered = OSError(errno.ENXIO, "No such device or address", disk)
    open_disk = Mock(side_effect=[not_registered, 42])
    with monkeypatch.context() as patch:
        patch.setattr(image_msc, "Path", lambda _: tmp_path)
        patch.setattr(Path, "stat", disk_stat)
        patch.setattr(os, "open", open_disk)
        patch.setattr(os, "fdopen", Mock(return_value=handle))
        patch.setattr(os, "fstat", Mock(return_value=info))
        patch.setattr(image_msc.time, "sleep", Mock())
        with image_msc.open_block_device(node, Mock()) as opened:
            assert opened == (disk, 262144, handle.__enter__.return_value)
        assert open_disk.call_args_list == [call(disk, os.O_RDWR | os.O_SYNC)] * 2
        handle.__exit__.assert_called_once()

        open_disk.side_effect = not_registered
        patch.setattr(image_msc.time, "monotonic", Mock(side_effect=[0, 1, image_msc.ENUMERATION_TIMEOUT]))
        with pytest.raises(TimeoutError) as timeout, image_msc.open_block_device(node, Mock()):
            pytest.fail("unregistered disk opened")
        assert timeout.value.__cause__ is not_registered


@pytest.mark.parametrize("suite,failure", [
    (None, failure) for failure in (
        "gateways", "usbctrl-read", "usbctrl-write", "dma-write", "matrix-read",
        "matrix-write", "rsa-events", "fault-recovery", None,
    )
] + [
    ("platform", None), ("platform", "otp-seal"),
    ("operations", None), ("operations", "operations"),
])
def test_image_suite_requires_its_separate_probe_images(tmp_path, suite, failure):
    script = tmp_path / "scripts/image-suites.sh"
    script.parent.mkdir()
    shutil.copyfile(ROOT / "scripts/image-suites.sh", script)
    binary = tmp_path / "tools/emu/target/test-host/release/rsk-emu"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"emulator")
    commands = tmp_path / "bin"
    commands.mkdir()
    build = commands / "bash"
    build.write_text(f"#!{sys.executable}\n" + '''
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
import os
from pathlib import Path
out = Path("target/trustzone")
out.mkdir(parents=True, exist_ok=True)
name = os.environ.get("RSK_TZ_PROBE_NAME")
image = b"hostile-" + name.encode() if name else b"probes" if os.environ.get("RSK_TZ_GATEWAY_PROBES") == "1" else b"ordinary"
out.joinpath("combined.elf").write_bytes(image)
out.joinpath("import.elf").write_bytes(b"import")
ns = out / "nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns"
ns.parent.mkdir(parents=True, exist_ok=True)
ns.write_bytes(image)
''')
    build.chmod(0o755)
    cargo = commands / "cargo"
    cargo.write_text("#!/bin/sh\n# SPDX-License-Identifier: AGPL-3.0-only\n"
                     "# Copyright (C) 2026 RS-Key contributors\nexit 0\n")
    cargo.chmod(0o755)
    runner = commands / "python"
    runner.write_text(f"#!{sys.executable}\n" + '''
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
import os, sys
from pathlib import Path
args = sys.argv[1:]
PROBES = {
    "usbctrl-read": ("read", 19359, "0x50110000"),
    "usbctrl-write": ("write", 19362, "0x50110000"),
    "dma-write": ("write", 19365, "0x50000400"),
    "matrix-read": ("read", 19368, "0"),
    "matrix-write": ("write", 20392, "0"),
}
if args[0] in ("tests/106_trustzone_rsa_events.py", "tests/107_trustzone_fault_recovery.py"):
    name = "rsa-events" if args[0].startswith("tests/106_") else "fault-recovery"
    if os.environ["PROBE_FAILURE"] == name:
        sys.exit(name + " regression failed")
    sys.exit(0)
if args[0] == "tests/97_trustzone_isolation.py":
    image = Path(args[args.index("--image") + 1])
    name = image.name.removeprefix("hostile-").removesuffix(".elf")
    access, port, address = PROBES[name]
    assert image.read_bytes() == b"hostile-" + name.encode(), "missing hostile build"
    assert Path(args[args.index("--ns-image") + 1]).read_bytes() == b"hostile-" + name.encode(), "wrong NS symbols"
    assert args[args.index("--address") + 1] == address
    assert args[args.index("--access") + 1] == access
    assert args[args.index("--cfsr") + 1] == "0x8200"
    assert int(args[args.index("--base-port") + 1]) == port
    assert "--require-fenced" in args
    assert ("--matrix" in args) == name.startswith("matrix-")
    with open(os.environ["HOSTILE_RAN"], "a") as log:
        log.write(name + "\\n")
    if os.environ["PROBE_FAILURE"] == name:
        sys.exit(f"protected {access} succeeded: post-probe marker reached")
    sys.exit(0)
assert Path(args[args.index("--image") + 1]).read_bytes() == b"ordinary"
if args[0] == "tools/emu/image_otp_seal.py":
    scenario = "otp-seal"
else:
    assert args[0] == "tools/emu/image_assurance.py"
    scenario = args[args.index("--only") + 1]
with open(os.environ["IMAGE_SCENARIOS"], "a") as log:
    log.write(scenario + "\\n")
if scenario == "basic":
    assert Path(args[args.index("--gateway-image") + 1]).read_bytes() == b"probes", "missing probe build"
    assert Path(args[args.index("--import-image") + 1]).read_bytes() == b"import", "missing import ELF"
    if os.environ["PROBE_FAILURE"] == "gateways":
        sys.exit("gateway startup probes did not complete")
if os.environ["PROBE_FAILURE"] == scenario:
    sys.exit(scenario + " regression failed")
''')
    runner.chmod(0o755)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("RSK_TZ_") and key != "CARGO_TARGET_DIR"}
    hostile = tmp_path / "hostile-ran"
    scenarios = tmp_path / "scenarios-ran"
    env.update(PATH=f"{commands}:{env['PATH']}", HOST_TARGET="test-host",
               RSK_TZ_GATEWAY_PROBES="1", RSK_TZ_PROBE_ADDRESS="0xdeadbeef",
               RSK_TZ_PROBE_ACCESS="invalid",
               PROBE_FAILURE=failure or "", HOSTILE_RAN=str(hostile), IMAGE_SCENARIOS=str(scenarios))
    work = tmp_path / "report"
    result = subprocess.run(["/bin/bash", str(script), str(work), *([suite] if suite else [])], cwd=tmp_path,
                            env=env, text=True, capture_output=True, check=False)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
    assert (work / "firmware-pt.elf").read_bytes() == b"ordinary"
    order = ["usbctrl-read", "usbctrl-write", "dma-write", "matrix-read", "matrix-write"]
    if suite == "operations":
        assert not hostile.exists()
        assert not (work / "gateway.elf").exists()
    else:
        expected = order[:order.index(failure) + 1] if failure in order else order
        assert hostile.read_text().splitlines() == expected
    if failure is None or failure in ("otp-seal", "operations"):
        assert scenarios.read_text().splitlines() == {
            None: ["basic", "stack", "operations", "cuts", "otp-seal"],
            "platform": ["basic", "stack", "cuts", "otp-seal"],
            "operations": ["operations"],
        }[suite]
    if failure == "gateways":
        assert "gateway startup probes did not complete" in result.stdout
    elif failure in ("rsa-events", "fault-recovery", "otp-seal", "operations"):
        assert failure + " regression failed" in result.stdout
    elif failure is not None:
        access = "read" if failure.endswith("read") else "write"
        assert f"protected {access} succeeded: post-probe marker reached" in result.stdout


@pytest.mark.parametrize("access,encoding,operation,accepted", [
    ("read", "6801", "ldr", True),
    ("write", "6001", "str", True),
    ("read", "f8d0 1000", "ldr.w", True),
    ("write", "f8c0 1000", "str.w", True),
    ("write", "6801", "ldr", False),
    ("read", "6001", "str", False),
])
def test_hostile_mode_requires_the_actual_load_or_store(hostile, tmp_path, monkeypatch, access, encoding, operation, accepted):
    outputs = iter(["20070000 B RSK_NS_PROBE_PROGRESS\n10084000 T RSK_NS_PROBE_ACCESS\n",
                    f"10084000:\t{encoding}\t{operation}\tr1, [r0]\n"])
    monkeypatch.setattr(hostile.subprocess, "check_output", lambda *args, **kwargs: next(outputs))
    if accepted:
        assert hostile.load_probe(tmp_path / "ns.elf", access) == 0x20070000
    else:
        with pytest.raises(AssertionError, match=f"hostile {access} probe is not"):
            hostile.load_probe(tmp_path / "ns.elf", access)


def test_hostile_entrypoint_rejects_a_read_labeled_as_write_before_opening_ports(hostile, tmp_path, monkeypatch):
    args = hostile.argparse.Namespace(ns_image=tmp_path / "ns.elf", access="write")
    monkeypatch.setattr(hostile, "arguments", lambda: args)
    outputs = iter(["20070000 B RSK_NS_PROBE_PROGRESS\n10084000 T RSK_NS_PROBE_ACCESS\n",
                    "10084000:\t6801\tldr\tr1, [r0]\n"])
    monkeypatch.setattr(hostile.subprocess, "check_output", lambda *args, **kwargs: next(outputs))
    with pytest.raises(AssertionError, match="hostile write probe is not STR"):
        hostile.main()


@pytest.mark.parametrize("actual", [b"\x12\x34\0\0", b"\x12\x34\0\xff"])
def test_scratch_check_includes_padding_bytes(laboratory, actual):
    _, device = laboratory
    device.image = Path("combined.elf")
    device.scratch = (0x20080100, b"\x12\x34\0\0")
    commands = []

    def inspect(command):
        commands.append(command)
        return actual.hex()

    device.inspect = inspect
    if actual[-1]:
        with pytest.raises(AssertionError, match="scratch code/padding differs"):
            device.check_scratch_code()
    else:
        device.check_scratch_code()
    assert commands == ["read 20080100 4"]


@pytest.mark.parametrize("failure", [False, True])
def test_hostile_matrix_joins_every_isolated_case_and_propagates_failure(hostile, monkeypatch, failure):
    args = argparse.Namespace(ns_image=Path("ns.elf"), matrix=True, access="write",
                              address=0, base_port=20000)
    marker, target = 0x20070000, 0x20070004
    calls = SimpleQueue()
    monkeypatch.setattr(hostile, "arguments", lambda: args)
    monkeypatch.setattr(hostile, "load_probe", lambda *args: marker)
    monkeypatch.setattr(hostile, "load_target", lambda *args: target)
    monkeypatch.setattr(hostile, "RESOURCES", [("usbctrl", 0x50110000)])
    monkeypatch.setattr(hostile, "MEMORY_RESOURCES", [("scratch", 0x20080100)])

    def probe(args, marker, address, port, **kwargs):
        calls.put((address, port, kwargs.get("allowed", False), kwargs.get("secure_fault", False)))
        assert kwargs["target"] == target
        if failure and address == 0x50110000:
            raise AssertionError("protected write succeeded")

    monkeypatch.setattr(hostile, "run_probe", probe)
    if failure:
        with pytest.raises(AssertionError, match="protected write succeeded"):
            hostile.main()
    else:
        hostile.main()
        assert sorted(calls.get_nowait() for _ in range(3)) == sorted([
            (target, 20000, True, False), (0x50110000, 20003, False, False),
            (0x20080100, 20006, False, True),
        ])
        assert calls.empty()


def test_device_context_rejects_padding_changed_during_work(laboratory, monkeypatch):
    module, device = laboratory
    actual = bytearray(b"\x12\x34\0\0")
    device.image = Path("combined.elf")
    device.scratch = (0x20080100, bytes(actual))
    device.inspect = lambda command: actual.hex()
    closed = []
    device.close = lambda: closed.append(True)
    monkeypatch.setattr(module, "Device", lambda: device)
    with pytest.raises(AssertionError, match="scratch code/padding differs"):
        with module.device():
            actual[-1] = 0xff
    assert closed == [True]


@pytest.mark.parametrize("secure,body,error", [
    (False, "CFSR 0x00008200, BFAR 0x50110000", None),
    (False, "CFSR 0x00008200, BFAR 0x50110004", "address differs"),
    (True, "SFSR 0x00000048, SFAR 0x20080100", None),
    (True, "SFSR 0x00000000, SFAR 0x20080100", "status differs"),
    (True, "CFSR 0x00008200, BFAR 0x20080100", "address differs"),
])
def test_hostile_fault_identifies_bus_and_sau_denial(hostile, secure, body, error):
    address = 0x20080100 if secure else 0x50110000
    if error:
        with pytest.raises(AssertionError, match=error):
            hostile.check_fault(body, address, "write", 0x8200, secure)
    else:
        hostile.check_fault(body, address, "write", 0x8200, secure)


@pytest.mark.parametrize("state", [b"\x02\x00", b"\x02\x01"])
def test_image_boot_checks_ready_without_issuing_a_setup_command(laboratory, monkeypatch, state):
    _, device = laboratory
    commands = []

    class Card:
        def transmit(self, command):
            commands.append(bytes(command))
            return list(state), 0x90, 0

    device.card = Card()
    monkeypatch.setattr(device, "select", lambda aid: None)
    if state[1]:
        device.check_storage_ready()
    else:
        with pytest.raises(AssertionError, match="automatic storage boot failed"):
            device.check_storage_ready()
    assert commands == [bytes.fromhex("801e080000")]


@pytest.mark.parametrize("nonsecure", [None, 150, 99])
def test_measured_operations_refuse_an_ns_stack_underflow(laboratory, monkeypatch, nonsecure):
    _, device = laboratory
    measurement = "core0_low=100 core0_min=150 core1_low=200 core1_min=250"
    if nonsecure is not None:
        measurement += f" ns0_low=100 ns0_min={nonsecure}"
    calls = []

    def inspect(command):
        calls.append(command)
        return measurement if command == "end" else "cycle=0"

    monkeypatch.setattr(device, "inspect", inspect)
    report = {}
    if nonsecure == 99:
        with pytest.raises(AssertionError, match="sample"):
            device.measured("sample", lambda: 42, report)
    else:
        assert device.measured("sample", lambda: 42, report) == 42
    assert calls == ["begin", "end"]
    if nonsecure is not None:
        assert report["sample"]["ns0_min"] == nonsecure


@pytest.mark.parametrize("wall,image_ns,changes,error", [
    (121, 11_000_000_000, {}, None),
    (1200, 0, {}, "host watchdog"),
    (1, 120_000_000_000, {}, "image deadline"),
    (1, 1, {"dead": "true"}, "image faulted"),
    (1, 1, {"power_ups": "2"}, "image rebooted"),
    (1, -1, {}, "clock moved backwards"),
])
def test_image_ctap_has_independent_image_and_host_bounds(laboratory, monkeypatch, wall, image_ns, changes, error):
    module, device = laboratory
    clock = {"wall": 0}
    state = {"dead": "false", "power_ups": "1", "emulated_ns": "0"}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["wall"])
    monkeypatch.setattr(device, "inspect", lambda command: " ".join(f"{k}={v}" for k, v in state.items()))
    deadline = module.ImageDeadline(device)
    clock["wall"] = wall
    state.update(changes, emulated_ns=str(image_ns))
    if error:
        with pytest.raises(AssertionError, match=error):
            deadline.check()
    else:
        deadline.check()


def test_image_clock_cannot_go_backwards_after_initial_progress(laboratory, monkeypatch):
    module, device = laboratory
    states = iter([0, 10, 9])
    monkeypatch.setattr(device, "inspect", lambda command:
                        f"dead=false power_ups=1 emulated_ns={next(states)}")
    deadline = module.ImageDeadline(device)
    deadline.check()
    with pytest.raises(AssertionError, match="clock moved backwards"):
        deadline.check()


def test_inspection_cannot_outlive_the_host_watchdog(laboratory, monkeypatch):
    module, device = laboratory
    clock = {"wall": 0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["wall"])
    monkeypatch.setattr(device, "inspect", lambda command: "dead=false power_ups=1 emulated_ns=0")
    deadline = module.ImageDeadline(device)

    def inspect(command):
        clock["wall"] = module.CTAP_HOST_TIMEOUT_S
        return "dead=false power_ups=1 emulated_ns=0"

    monkeypatch.setattr(device, "inspect", inspect)
    with pytest.raises(AssertionError, match="host watchdog"):
        deadline.check()


@pytest.mark.parametrize("custom_deadline", [False, True])
def test_native_keepalive_wall_bound_is_replaced_only_when_requested(laboratory, monkeypatch, custom_deadline):
    module, device = laboratory
    times = iter([0, 121])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    frames = [device.cid + b"\xbb\x00\x01\x01", device.cid + b"\x90\x00\x02\x00\xa0"]

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            return list(frames.pop(0).ljust(64, b"\x00"))

    device.hid = Hid()
    if custom_deadline:
        assert module.send_cbor(device.hid, device.cid, b"\x04", check_deadline=lambda: None) == b"\x00\xa0"
    else:
        with pytest.raises(IOError, match="keepalives past the deadline"):
            module.send_cbor(device.hid, device.cid, b"\x04")


@pytest.mark.parametrize("continuation", [False, True])
def test_image_deadline_checks_the_final_hid_read(laboratory, monkeypatch, continuation):
    module, device = laboratory
    device.image = True
    clock = {"ns": 0}
    answer = b"\x00" + (b"\xa0" * 69 if continuation else b"\xa0")
    frames = [device.cid + bytes([0x90]) + len(answer).to_bytes(2, "big") + answer[:57]]
    if continuation:
        frames.append(device.cid + b"\x00" + answer[57:])

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            frame = frames.pop(0)
            if not frames:
                clock["ns"] = module.CTAP_IMAGE_TIMEOUT_NS
            return list(frame.ljust(64, b"\x00"))

    device.hid = Hid()
    monkeypatch.setattr(device, "inspect", lambda command:
                        "elapsed_ns=1 keepalives=0 max_gap_ns=1" if command == "transport-end" else
                        f"dead=false power_ups=1 emulated_ns={clock['ns']}")
    with pytest.raises(AssertionError, match="CTAP image deadline expired"):
        device.ctap(4)


def test_a_falsy_deadline_callable_still_runs(laboratory):
    module, device = laboratory

    class Deadline:
        def __bool__(self):
            return False

        def __call__(self):
            raise AssertionError("custom clock expired")

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            raise AssertionError("expired operation reached a HID read")

    with pytest.raises(AssertionError, match="custom clock expired"):
        module.send_cbor(Hid(), device.cid, b"\x04", check_deadline=Deadline())


def test_image_ctap_keeps_all_transport_measurements_in_the_operation(laboratory, monkeypatch):
    module, device = laboratory
    device.image = True
    commands = []

    def inspect(command):
        commands.append(command)
        if command == "status":
            return "dead=false power_ups=1 emulated_ns=0"
        if command == "transport-end":
            return "elapsed_ns=100 keepalives=0 max_gap_ns=100"
        return "core0_low=100 core0_min=150 core1_low=200 core1_min=250"

    def send(*args, check_deadline):
        check_deadline()
        return b"\x00\xa0"

    monkeypatch.setattr(device, "inspect", inspect)
    monkeypatch.setattr(module, "send_cbor", send)
    report = {}
    device.measured("sample", lambda: (device.ctap(4), device.ctap(6)), report)
    assert [row["command"] for row in report["sample_ctap"]] == [4, 6]
    assert all(row["max_gap_ns"] == 100 for row in report["sample_ctap"])
    assert commands.count("transport-begin") == commands.count("transport-end") == 2


@pytest.mark.parametrize("gap", [499_999_999, 500_000_000, 500_000_001])
def test_image_ctap_refuses_usb_starvation(laboratory, monkeypatch, gap):
    module, device = laboratory
    device.image = True
    monkeypatch.setattr(module, "send_cbor", lambda *args, **kwargs: b"\x00\xa0")
    monkeypatch.setattr(device, "inspect", lambda command:
                        f"elapsed_ns={gap} keepalives=0 max_gap_ns={gap}" if command == "transport-end" else
                        "dead=false power_ups=1 emulated_ns=0")
    if gap > module.USB_MAX_GAP_NS:
        with pytest.raises(AssertionError, match="starved USB"):
            device.ctap(4)
    else:
        assert device.ctap(4) == {}


def test_stack_measurement_cleanup_preserves_the_operation_failure(laboratory, monkeypatch):
    _, device = laboratory

    def inspect(command):
        if command == "end":
            raise OSError("inspection stopped")
        return ""

    def operation():
        raise AssertionError("command oracle failed")

    monkeypatch.setattr(device, "inspect", inspect)
    report = {}
    with pytest.raises(AssertionError, match="command oracle failed"):
        device.measured("sample", operation, report)
    assert report["sample_measurement_error"] == "inspection stopped"
