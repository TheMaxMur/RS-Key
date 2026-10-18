# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Sequence faults survive fresh semantic replay and shrink only the same property."""
import json

import pytest

import oracle
from oracle_lib import codec, oath_sequences
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace, recover
from test_oracle_expanded import apdu_parts
from test_oracle_oath_semantics import Peer as Oath


class Peer(Oath):
    offline = True

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 1 and data == b"\x71\xff":
            if self.defect == "refusal-spends-HOTP":
                for record in self.records.values():
                    if record["hotp"]:
                        record["counter"] += 1
            observe("tx", wire)
            observe("rx", b"\x6a\x80")
            return Reply(b"\x6a\x80", status=0x6a80)
        if ins == 0xa4 and self.defect == "SELECT-resets-HOTP":
            for record in self.records.values():
                record["counter"] = 0
        return super().transfer(wire, deadline, observe)

    def close(self):
        pass


@pytest.mark.parametrize("defect", [None, "refusal-spends-HOTP", "SELECT-resets-HOTP"])
def test_seeded_sequences_use_exact_private_counters_after_each_transition(tmp_path, defect):
    peer = Peer(defect)
    trace = Trace(tmp_path / "sequences", {"profile": "rsk", "backend": "synthetic"})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True))
    oracle.execute(session, ["oath-sequences"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert failed and all("preserves HOTP private state" in row["reason"] for row in failed), failed
    else:
        assert len(trace.cases) == oath_sequences.SEQUENCE_COUNT and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert not peer.records
    first = list(oath_sequences.recipes("stable"))
    assert first == list(oath_sequences.recipes("stable")) != list(oath_sequences.recipes("different"))
    assert all(len(row["steps"]) == oath_sequences.SEQUENCE_LENGTH for row in first)


def source(tmp_path, defect="refusal-spends-HOTP", samples=1):
    recipe = {"model": "oath-v1", "seed": "stable", "steps": ["select", "put", "calculate", "select", "refuse", "calculate"]}
    trace = Trace(tmp_path / "original", {"profile": "rsk", "backend": "synthetic"})
    session = Session(trace, card=Peer(defect), profile="rsk", options=Options(exercise=True, seed="stable"))
    for sample in range(samples):
        trace.sample = sample
        oath_sequences.replay(session, recipe, "sequence.reproduce")
    trace.finish()
    return trace.directory


def factory(path, defect):
    path.write_text("from test_oracle_sequences import Peer\n"
                    "from oracle_lib.runner import Session, Options\n"
                    "def make_session(trace, seed):\n"
                    f"    return Session(trace, card=Peer({defect!r}), profile='rsk', options=Options(exercise=True, seed=seed))\n")
    return path


def test_minimizer_cli_preserves_original_and_same_failure_with_fresh_sessions(tmp_path, monkeypatch, capsys):
    original = source(tmp_path)
    original_bytes = (original / "events.jsonl").read_bytes()
    script = factory(tmp_path / "offline.py", "refusal-spends-HOTP")
    output = tmp_path / "minimized"
    monkeypatch.setattr(oracle, "inventory", lambda: pytest.fail("offline minimizer attempted discovery"))
    assert oracle.main(["minimize", str(original), "--scenario", "sequence.reproduce", "--factory", str(script), "--out", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["steps"] == 2
    report = json.loads((output / "reproducer.json").read_text())
    assert report["minimized_recipe"]["steps"] == ["put", "refuse"]
    assert report["valid_single_step_deletion_minimal"]
    assert (original / "events.jsonl").read_bytes() == original_bytes
    captures = [recover(row["trace"]) for row in report["trials"]]
    assert len({row["run_id"] for row in captures}) == len(captures)
    assert all(row["manifest"]["recipe"]["seed"] == "stable" for row in captures)
    assert all(row["same_failure"] for row in report["trials"][-2:])


def test_minimizer_does_not_accept_an_unrelated_red_result(tmp_path):
    original = source(tmp_path)
    script = factory(tmp_path / "wrong-defect.py", "SELECT-resets-HOTP")
    assert oracle.main(["minimize", str(original), "--scenario", "sequence.reproduce", "--factory", str(script), "--out", str(tmp_path / "wrong")]) == 2
    assert not (tmp_path / "wrong" / "reproducer.json").exists()


def test_invalid_transition_and_wallet_source_fail_before_factory_loading(tmp_path):
    with pytest.raises(ValueError, match="existing owned record"):
        oath_sequences.steps({"model": "oath-v1", "seed": "s", "steps": ["delete"]})
    original = source(tmp_path)
    manifest = original / "manifest.json"
    value = json.loads(manifest.read_text())
    value["profile"] = "trezor"
    manifest.write_text(json.dumps(value))
    assert oracle.main(["minimize", str(original), "--scenario", "sequence.reproduce", "--factory", str(tmp_path / "must-not-be-read.py"), "--out", str(tmp_path / "wallet")]) == 2
    assert not (tmp_path / "wallet").exists()


def test_minimizer_selects_a_failed_sample_without_modifying_the_source(tmp_path):
    original = source(tmp_path, samples=2)
    script = factory(tmp_path / "offline.py", "refusal-spends-HOTP")
    base = ["minimize", str(original), "--scenario", "sequence.reproduce", "--factory", str(script)]
    assert oracle.main(base + ["--out", str(tmp_path / "ambiguous")]) == 2
    assert not (tmp_path / "ambiguous").exists()
    output = tmp_path / "selected"
    assert oracle.main(base + ["--out", str(output), "--sample", "1"]) == 0
    report = json.loads((output / "reproducer.json").read_text())
    assert report["source_sample"] == 1 and report["minimized_recipe"]["steps"] == ["put", "refuse"]
    assert len(recover(original)["cases"]) == 2
