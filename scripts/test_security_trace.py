# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import copy
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import security_trace

TRACE = pathlib.Path(__file__).parents[1] / "formal" / "traces" / "security-phase4.jsonl"


def events():
    return security_trace.load_events([TRACE])


def test_the_recorded_trace_is_exactly_what_the_ratchets_claim(tmp_path):
    # Equality, not a floor: a richer recording has to move `floors.txt` in the
    # same commit, and the numbers live in one place instead of here as well.
    report = security_trace.generate(events(), tmp_path / "TraceSecurityData.tla")
    assert report["commands"] == security_trace.ratchet(security_trace.COMMANDS_RATCHET)
    assert report["steps"] == security_trace.ratchet(security_trace.STEPS_RATCHET)
    assert len(report["reached"]) == security_trace.ratchet(security_trace.ACTIONS_RATCHET)
    assert report["ambiguous"] <= security_trace.ratchet(security_trace.AMBIGUOUS_RATCHET)
    assert "CmNext" in report["unreached"]


def test_a_missing_ratchet_is_fatal_rather_than_permissive(monkeypatch, tmp_path):
    floors = tmp_path / "floors.txt"
    floors.write_text("Shipped.cfg GREEN 1\n", encoding="utf-8")
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    with pytest.raises(SystemExit, match="no @TraceSecurityActionsMin"):
        security_trace.ratchet(security_trace.ACTIONS_RATCHET)


def test_mapper_infers_set_pin_without_using_the_hint():
    event = events()[2]
    assert [name for name, _ in security_trace.infer(event, security_trace.new_ledger())] == [
        "SetPinStart",
        "SetPinClearPpuat",
        "SetPinWrite",
    ]


def test_a_power_cycle_is_one_power_cut_and_reads_no_state_difference():
    event = copy.deepcopy(events()[0])
    event["command_raw"] = security_trace.POWER_CYCLE
    # The event kind alone selects it: the raw sides are identical here, and the
    # unchanged-state arm below would otherwise claim it as a stutter.
    event["post"] = copy.deepcopy(event["pre"])
    assert [n for n, _ in security_trace.infer(event, security_trace.new_ledger())] == ["PowerCut"]


def test_the_secret_sweep_does_not_grow_with_the_records_the_seed_opens():
    # `ResetSweepSecrets`'s seed arm is `KeepOpen([store EXCEPT !.seed = FALSE],
    # ram)` over a `ram` that `ResetConfirmed` has already cleared, so `cred` and
    # `rpent` go with the seed in ONE step. A step per record is what wedged the
    # replay fifteen steps from the end of the recording.
    ledger = security_trace.new_ledger()
    ledger["cred"].update({"rp1", "rp2"})
    ledger["rpent"].update({"rp1", "rp2"})
    ledger["pin_set"] = True
    names = [n for n, _ in security_trace.reset_path(ledger)]
    assert names.count("ResetSweepSecrets") == 2  # the seed, then the advance
    assert names.count("ResetSweepGates") == 2  # pin + advance
    assert names[0] == "ResetStart" and names[-2] == "ResetFinish"
    # The grant is its own arm (`PpuatIsASecret`), so it does add a step.
    ledger["ppuat"] = True
    assert [n for n, _ in security_trace.reset_path(ledger)].count("ResetSweepSecrets") == 3
    assert security_trace.reset_path(security_trace.new_ledger()).count(
        ("ResetSweepGates", "ResetSweepGates")
    ) == 1  # nothing to delete: the advance step alone


def test_each_gate_the_sweep_deletes_costs_its_own_step():
    # `always_uv` and `sealed` are `GatesLive` terms the recording never sets, so
    # nothing else here would notice one moved to the secrets phase.
    for gate in ("pin_set", "always_uv", "sealed"):
        ledger = security_trace.new_ledger()
        ledger[gate] = True
        names = [n for n, _ in security_trace.reset_path(ledger)]
        assert names.count("ResetSweepGates") == 2, gate
        assert names.count("ResetSweepSecrets") == 2, gate


def test_a_seedless_store_holding_records_has_no_sweep_length():
    ledger = security_trace.new_ledger()
    ledger["seed"] = False
    ledger["cred"].add("rp1")
    with pytest.raises(SystemExit, match="no modelled sweep length"):
        security_trace.reset_path(ledger)
    # And the other direction: nothing to open is not the same as a lost seed.
    ledger["cred"].clear()
    assert [n for n, _ in security_trace.reset_path(ledger)].count("ResetSweepSecrets") == 1


def test_a_wrong_pin_needs_both_counters_to_move():
    # A retry drop alone is what a *correct* PIN shows on the attempt before the
    # budget is restored, so either half on its own must stay unmapped.
    for retries, mismatches in ((7, 0), (8, 1)):
        event = copy.deepcopy(events()[16])
        event["post"]["pin_retries_raw"] = retries
        event["post"]["pin_mismatches_raw"] = mismatches
        with pytest.raises(SystemExit, match="no independent B mapping"):
            security_trace.infer(event, security_trace.new_ledger())


def test_an_unknown_raw_state_change_is_never_a_stutter():
    event = copy.deepcopy(events()[1])
    event["post"]["backup_sealed_record"] = True
    with pytest.raises(SystemExit, match="no independent B mapping"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_discontinuous_raw_trace_is_refused(tmp_path):
    broken = copy.deepcopy(events()[:2])
    broken[1]["pre"]["pin_mismatches_raw"] = 1
    path = tmp_path / "broken.jsonl"
    path.write_text("".join(f"{json.dumps(e)}\n" for e in broken))
    with pytest.raises(SystemExit, match="raw discontinuity"):
        security_trace.load_events([path])


def test_a_shifted_action_hint_cannot_select_another_transition():
    event = copy.deepcopy(events()[3])
    event["action_hint"] = "makeCredential"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event, security_trace.new_ledger())


def test_r4b_event_reports_ambiguous_instead_of_choosing_a_witness():
    event = copy.deepcopy(events()[4])
    assert security_trace.event_consensus(
        event, {"RegisterWriteB", "RegisterRefused"}
    ) == "AMBIGUOUS"
