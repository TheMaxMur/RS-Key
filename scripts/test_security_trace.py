# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import security_trace

TRACE = pathlib.Path(__file__).parents[1] / "formal" / "traces" / "security-phase4.jsonl"


def events():
    return security_trace.load_events([TRACE])


def resets():
    """The two authenticatorReset boundaries, in order: the one the power-up
    window admits, then the one it has closed.

    By SHAPE and not by index. These were `resets()[0]` and `resets()[1]`, and
    every case that used them broke the day the recorded session grew a suite —
    which is a test suite that reads the recording positionally, not a finding.
    """
    found = [e for e in events() if e["command_raw"] == 0x07]
    assert len(found) == 2, [e["sequence"] for e in found]
    return found


def clay():
    """Raw material for a case that builds its own event. Any boundary will do —
    every field those cases care about is overwritten before the assertion."""
    return events()[0]


def set_pin():
    """The boundary where the PIN record appears. By SHAPE, for `resets()`' reason."""
    found = [e for e in events()
             if e["pre"]["pin_record_len"] is None and e["post"]["pin_record_len"] == 35]
    assert len(found) == 1, [e["sequence"] for e in found]
    return found[0]


def wrong_pin():
    """The boundary where BOTH PIN counters move — the only shape `WrongPin` maps."""
    found = [e for e in events()
             if e["pre"]["pin_retries_raw"] is not None
             and e["post"]["pin_retries_raw"] is not None
             and e["post"]["pin_retries_raw"] < e["pre"]["pin_retries_raw"]
             and e["post"]["pin_mismatches_raw"] > e["pre"]["pin_mismatches_raw"]]
    assert found, "the recording carries no wrong-PIN boundary"
    return found[0]


def issued_token(perms):
    """The first clientPIN boundary that issues a token carrying `perms`."""
    found = [e for e in events()
             if e["command_raw"] == 0x06 and not e["pre"]["token_in_use_raw"]
             and e["post"]["token_in_use_raw"]
             and e["post"]["token_permissions_raw"] == perms]
    assert found, f"the recording issues no token carrying {perms}"
    return found[0]


def first_register():
    """The first makeCredential that actually stored a credential."""
    found = [e for e in events()
             if e["command_raw"] == 0x01
             and e["post"]["credential_slots_raw"] > e["pre"]["credential_slots_raw"]]
    assert found, "the recording registers nothing"
    return found[0]


def mc_gate(rk, always_uv=False, pin_set=True):
    """The token-less makeCredential boundary filling one cell of the gate grid."""
    found = [e for e in events()
             if e["command_raw"] == 0x01
             and e["request"] == {"rk": rk, "pin_uv_auth": False}
             and not (security_trace.raw_changes(e) - {"channel_raw"})
             and bool(e["pre"]["always_uv_raw"]) == always_uv
             and (e["pre"]["pin_record_len"] is not None) == pin_set]
    assert found, f"no gate cell rk={rk} alwaysUv={always_uv} pinSet={pin_set}"
    return found[0]


def test_the_recorded_trace_is_exactly_what_the_ratchets_claim(tmp_path):
    # Equality, not a floor: a richer recording has to move `floors.txt` in the
    # same commit, and the numbers live in one place instead of here as well.
    report = security_trace.generate(events(), tmp_path / "TraceSecurityData.tla")
    assert report["commands"] == security_trace.ratchet(security_trace.COMMANDS_RATCHET)
    assert report["steps"] == security_trace.ratchet(security_trace.STEPS_RATCHET)
    assert len(report["reached"]) == security_trace.ratchet(security_trace.ACTIONS_RATCHET)
    assert report["gates"] == security_trace.ratchet(security_trace.GATES_RATCHET)
    assert report["ambiguous"] == security_trace.ratchet(security_trace.AMBIGUOUS_RATCHET)
    assert "CmNext" in report["unreached"]


@pytest.mark.parametrize(
    "name",
    ["ACTIONS_RATCHET", "GATES_RATCHET", "AMBIGUOUS_RATCHET", "STEPS_RATCHET",
     "COMMANDS_RATCHET"],
)
def test_a_missing_ratchet_is_fatal_rather_than_permissive(monkeypatch, tmp_path, name):
    floors = tmp_path / "floors.txt"
    floors.write_text("Shipped.cfg GREEN 1\n", encoding="utf-8")
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    ratchet = getattr(security_trace, name)
    with pytest.raises(SystemExit, match=f"no {ratchet}"):
        security_trace.ratchet(ratchet)


def names_of(event, ledger=None):
    actions, _ = security_trace.infer(event, ledger or security_trace.new_ledger())
    return [name for name, _ in actions]


def test_mapper_infers_set_pin_without_using_the_hint():
    ledger = security_trace.new_ledger()
    assert names_of(set_pin(), ledger) == ["SetPinStart", "SetPinClearPpuat", "SetPinWrite"]
    # `SetPinClearPpuat` deletes the grant record, so the next reset sweeps one less.
    assert ledger["ppuat_rec"] is False


def test_a_power_cycle_is_one_power_cut_and_reads_no_state_difference():
    event = copy.deepcopy(clay())
    event["command_raw"] = security_trace.POWER_CYCLE
    # The event kind alone selects it: the raw sides are identical here, and the
    # unchanged-state arm below would otherwise claim it as a stutter.
    event["post"] = copy.deepcopy(event["pre"])
    assert names_of(event) == ["PowerCut"]


def test_the_secret_sweep_does_not_grow_with_the_records_the_seed_opens():
    # `ResetSweepSecrets`'s seed arm is `KeepOpen([store EXCEPT !.seed = FALSE],
    # ram)` over a `ram` that `ResetConfirmed` has already cleared, so `cred` and
    # `rpent` go with the seed in ONE step. A step per record is what wedged the
    # replay fifteen steps from the end of the recording.
    ledger = security_trace.new_ledger()
    ledger["cred"].update({"rp1", "rp2"})
    ledger["rpent"].update({"rp1", "rp2"})
    ledger["pin_set"] = True
    ledger["ppuat_rec"] = False  # the setPIN revoked it
    names = [n for n, _ in security_trace.reset_path(ledger)]
    assert names.count("ResetSweepSecrets") == 2  # the seed, then the advance
    assert names.count("ResetSweepGates") == 2  # pin + advance
    assert names[0] == "ResetStart" and names[-2] == "ResetFinish"
    # The grant is its own arm (`PpuatIsASecret`), so it does add a step.
    ledger["ppuat_rec"] = True
    assert [n for n, _ in security_trace.reset_path(ledger)].count("ResetSweepSecrets") == 3
    assert security_trace.reset_path(security_trace.new_ledger()).count(
        ("ResetSweepGates", "ResetSweepGates")
    ) == 1  # nothing to delete: the advance step alone


def test_a_seedless_store_holding_records_has_no_sweep_length():
    ledger = security_trace.new_ledger()
    ledger["seed"] = False
    ledger["ppuat_rec"] = False  # `ensure_seed` mints the record only beside a seed
    ledger["cred"].add("rp1")
    with pytest.raises(SystemExit, match="no modelled sweep length"):
        security_trace.reset_path(ledger)
    # And the other direction: nothing to open is not the same as a lost seed.
    ledger["cred"].clear()
    assert [n for n, _ in security_trace.reset_path(ledger)].count("ResetSweepSecrets") == 1


def test_each_gate_the_sweep_deletes_costs_its_own_step():
    # `always_uv` and `sealed` are `GatesLive` terms the recording never sets, so
    # nothing else here would notice one moved to the secrets phase.
    base = [n for n, _ in security_trace.reset_path(security_trace.new_ledger())]
    assert base.count("ResetSweepGates") == 1
    assert base.count("ResetSweepSecrets") == 3  # the seed, the grant record, the advance
    for gate in ("pin_set", "always_uv", "sealed"):
        ledger = security_trace.new_ledger()
        ledger[gate] = True
        names = [n for n, _ in security_trace.reset_path(ledger)]
        assert names.count("ResetSweepGates") == 2, gate
        assert names.count("ResetSweepSecrets") == 3, gate


def test_a_wrong_pin_needs_both_counters_to_move():
    # A retry drop alone is what a *correct* PIN shows on the attempt before the
    # budget is restored, so either half on its own must stay unmapped.
    for retries, mismatches in ((7, 0), (8, 1)):
        event = copy.deepcopy(wrong_pin())
        event["post"]["pin_retries_raw"] = retries
        event["post"]["pin_mismatches_raw"] = mismatches
        with pytest.raises(SystemExit, match="no independent B mapping"):
            security_trace.infer(event, security_trace.new_ledger())


def test_an_unknown_raw_state_change_is_never_a_stutter():
    event = copy.deepcopy(clay())
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
    event = copy.deepcopy(issued_token(3))
    event["action_hint"] = "makeCredential"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event, security_trace.new_ledger())


def test_r4b_event_reports_ambiguous_instead_of_choosing_a_witness():
    event = copy.deepcopy(first_register())
    assert security_trace.event_consensus(
        event, {"RegisterWriteB", "RegisterRefused"}
    ) == "AMBIGUOUS"


# --- R4c: the gate answers -------------------------------------------------
#
# Each rule below is pierced in both directions: the mapper must produce a gate
# row where one belongs, and must refuse the event where the rule does not reach.
# The TLA+ half — B's own answer disagreeing with the recording — is
# `TraceSecurityBadUvNotRqd.cfg` and `TraceSecurityBadResetWindow.cfg`, both
# required RED by `floors.txt`.


def test_a_token_less_make_credential_is_answered_by_the_gate_and_rk_decides():
    # The same request twice with a PIN set, once with `rk` and once without, and
    # neither writes anything: the raw sides are identical and only the INPUT
    # separates them.
    refused, allowed = mc_gate(True), mc_gate(False)
    for event, rk, code in ((refused, True, 0x36), (allowed, False, 0x00)):
        assert event["request"] == {"rk": rk, "pin_uv_auth": False}
        assert event["outcome_raw"] == code
        actions, gate = security_trace.infer(event, security_trace.new_ledger())
        assert [n for n, _ in actions] == ["Stutter"]
        assert gate == ("mc", rk)


def test_a_make_credential_refused_below_the_gate_is_not_predicted():
    # An excludeList hit (0x19) leaves the same empty footprint and this rule
    # does not explain it. Predicting it would make R4c cry wolf on a recording
    # that is perfectly correct.
    event = copy.deepcopy(mc_gate(False))
    event["outcome_raw"] = 0x19
    with pytest.raises(SystemExit, match="downstream of the gate"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_token_bearing_make_credential_is_not_a_gate_row():
    event = copy.deepcopy(mc_gate(False))
    event["request"] = {"rk": False, "pin_uv_auth": True}
    # Nothing moved and a token was offered, so B has no rule for it and the
    # ordinary stutter arm takes it — with no outcome claimed.
    actions, gate = security_trace.infer(event, security_trace.new_ledger())
    assert gate is None and [n for n, _ in actions] == ["Stutter"]


def test_a_reset_outside_the_window_is_a_refusal_and_not_a_second_wipe():
    ledger = security_trace.new_ledger()
    actions, gate = security_trace.infer(resets()[1], ledger)
    assert [n for n, _ in actions] == ["Stutter"]
    assert gate == ("reset", False)


def test_the_clock_advances_from_now_ms_and_not_from_the_branch_it_answers():
    # Spending the ticks inside the out-of-window branch made B's answer true by
    # construction. They come from elapsed time, so a mis-read branch meets a B
    # that disagrees.
    ledger = security_trace.new_ledger()
    assert security_trace.clock_ticks(resets()[0], ledger) == []  # now_ms = 1
    assert ledger["clock"] == 0
    assert [n for n, _ in security_trace.clock_ticks(resets()[1], ledger)] == ["Tick"]
    assert ledger["clock"] == 1
    # `MaxClock = 1` allows no second one, so a further late boundary spends none.
    assert security_trace.clock_ticks(resets()[1], ledger) == []


def test_the_reset_gate_carries_the_answer_the_device_gave_either_way():
    # The refusing direction is what the recording holds; this is the other one,
    # and it is the only shape in which R4c's reset arm can go red on a real
    # recording — B says Rejected because the window is shut, C says served.
    served = copy.deepcopy(resets()[1])
    served["outcome_raw"] = 0x00
    _, gate = security_trace.infer(served, security_trace.new_ledger())
    assert gate == ("reset", False)
    ledger = security_trace.new_ledger()
    security_trace.clock_ticks(served, ledger)
    assert ledger["clock"] == 1  # so `~InResetWindowGuard` holds and B refuses


def test_a_reset_gate_row_is_held_to_the_action_hint_too():
    event = copy.deepcopy(resets()[1])
    event["action_hint"] = "clientPin"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event, security_trace.new_ledger())


def test_the_tick_count_comes_from_the_configuration_and_not_from_a_literal(monkeypatch, tmp_path):
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    (tmp_path / "TraceSecurity.cfg").write_text(
        "CONSTANTS\n    ResetWindow = 2\n    MaxClock = 4\n", encoding="utf-8"
    )
    ledger = security_trace.new_ledger()
    ticks = security_trace.clock_ticks(resets()[1], ledger)
    assert [n for n, _ in ticks] == ["Tick", "Tick", "Tick"]
    assert ledger["clock"] == 3


def test_a_clock_that_cannot_outrun_the_window_is_fatal(monkeypatch, tmp_path):
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    (tmp_path / "TraceSecurity.cfg").write_text(
        "CONSTANTS\n    ResetWindow = 1\n    MaxClock = 1\n", encoding="utf-8"
    )
    with pytest.raises(SystemExit, match="never closes"):
        security_trace.clock_ticks(resets()[1], security_trace.new_ledger())


def test_an_unassigned_constant_is_fatal_rather_than_a_default(monkeypatch, tmp_path):
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    (tmp_path / "TraceSecurity.cfg").write_text("CONSTANTS\n    MaxClock = 1\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="does not assign ResetWindow"):
        security_trace.cfg_constant("ResetWindow")


def test_a_reset_inside_the_window_that_kept_state_is_fatal():
    event = copy.deepcopy(resets()[0])
    event["post"]["credential_slots_raw"] = 1
    with pytest.raises(SystemExit, match="left state behind"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_refused_reset_that_moved_state_is_fatal():
    event = copy.deepcopy(resets()[1])
    event["post"]["pin_mismatches_raw"] = 1
    with pytest.raises(SystemExit, match="refused reset moved raw state"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_reset_refused_for_another_reason_is_not_predicted():
    event = copy.deepcopy(resets()[1])
    event["outcome_raw"] = 0x2E
    with pytest.raises(SystemExit, match="does not explain"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_gate_row_is_held_to_the_action_hint_too():
    # The exemption is for a BARE stutter, which claims no family. A gate row
    # names one, so a shifted hint must still be caught.
    event = copy.deepcopy(mc_gate(False))
    event["action_hint"] = "clientPin"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event, security_trace.new_ledger())


def test_the_power_cycle_reopens_the_reset_window_for_b_as_well():
    ledger = security_trace.new_ledger()
    ledger["clock"] = 1
    ledger["ppuat_rec"] = False
    event = copy.deepcopy(clay())
    event["command_raw"] = security_trace.POWER_CYCLE
    event["post"] = copy.deepcopy(event["pre"])
    actions, _ = security_trace.infer(event, ledger)
    assert ledger["clock"] == 0
    # And predicts the mint of the grant record a PIN change had revoked. B's boot
    # MAY skip it, and R4a is an invariant, so an unpinned `PowerCut` would leave TLC
    # a successor the recording contradicts.
    assert ledger["ppuat_rec"] is True
    assert actions == [("PowerCut", "/\\ PowerCut /\\ gate'.ppuatRec = TRUE")]


def test_an_older_schema_is_refused_rather_than_read(tmp_path):
    event = copy.deepcopy(clay())
    event["schema"] = 3
    path = tmp_path / "old.jsonl"
    path.write_text(f"{json.dumps(event)}\n")
    with pytest.raises(SystemExit, match="unsupported schema"):
        security_trace.load_events([path])


def test_a_trace_with_no_request_record_is_refused(tmp_path):
    event = copy.deepcopy(clay())
    del event["request"]
    path = tmp_path / "norequest.jsonl"
    path.write_text(f"{json.dumps(event)}\n")
    with pytest.raises(SystemExit, match="no request record"):
        security_trace.load_events([path])


@pytest.mark.parametrize(
    "request_record",
    [
        {"resident": True, "pin_uv_auth": False},  # renamed
        {"rk": True},  # one short
        {"rk": True, "pin_uv_auth": False, "uv": False},  # one extra
    ],
)
def test_a_changed_request_shape_is_refused_rather_than_read(tmp_path, request_record):
    event = copy.deepcopy(mc_gate(True))
    event["request"] = request_record
    path = tmp_path / "changed.jsonl"
    path.write_text(f"{json.dumps(event)}\n")
    with pytest.raises(SystemExit, match="request fields changed"):
        security_trace.load_events([path])


def test_every_trace_configuration_has_a_verdict_and_the_roster_is_derived():
    verdicts = security_trace.trace_verdicts()
    assert verdicts["TraceSecurity.cfg"] == "GREEN"
    assert verdicts["TraceSecurityBadOutcome.cfg"] == "RED"
    assert set(verdicts) == {p.name for p in security_trace.FORMAL.glob("TraceSecurity*.cfg")}


def test_a_configuration_floors_txt_names_no_verdict_for_is_fatal(monkeypatch, tmp_path):
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    (tmp_path / "TraceSecurity.cfg").write_text("", encoding="utf-8")
    (tmp_path / "floors.txt").write_text("Shipped.cfg GREEN 1\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="names no verdict"):
        security_trace.trace_verdicts()


def test_check_sh_runs_this_row():
    """`NAMED` says this table exists; only this says the guard is wired in."""
    check = (pathlib.Path(__file__).parents[1] / "scripts/check.sh").read_text()
    assert gate_lines.runs(check, "scripts/security_trace.py --check-data")


# --- the alwaysUv arm, and the branches the session that recorded it needed ---


def configs():
    """The two authenticatorConfig boundaries: alwaysUv on, then off again."""
    found = [e for e in events() if e["command_raw"] == 0x0D]
    assert len(found) == 2, [e["sequence"] for e in found]
    return found


def gate_rows():
    """(kind, rk, alwaysUv, pinSet, recorded outcome) per gate boundary, in order.

    `pinSet` joined the tuple when the PIN-less cells did: without it the new
    (FALSE, rk FALSE, Authorized) row and the old (TRUE, rk FALSE, Authorized)
    one are the same tuple, and a grid assertion could not tell six cells from
    four.
    """
    ledger = security_trace.new_ledger()
    rows = []
    for event in events():
        security_trace.clock_ticks(event, ledger)
        _actions, gate = security_trace.infer(event, ledger)
        if gate is not None:
            rows.append((gate[0], gate[1], ledger["always_uv"], ledger["pin_set"],
                         security_trace.delta_c(event["outcome_raw"])))
    return rows


def test_a_config_op_toggling_always_uv_is_mapped():
    ledger = security_trace.new_ledger()
    on, off = configs()
    assert names_of_with(on, ledger) == ["ConfigOp"] and ledger["always_uv"]
    assert names_of_with(off, ledger) == ["ConfigOp"] and not ledger["always_uv"]


def names_of_with(event, ledger):
    return [name for name, _ in security_trace.infer(event, ledger)[0]]


def test_a_token_issued_with_another_permission_set_is_still_an_issuance():
    """It read `token_permissions_raw == 3` and nothing else, so the `acfg` token
    the config op needs would have died as "no independent B mapping"."""
    issued = [
        e for e in events()
        if e["command_raw"] == 0x06 and e["post"]["token_permissions_raw"] == 32
        and e["pre"]["token_permissions_raw"] != 32
    ]
    assert len(issued) == 1, [e["sequence"] for e in issued]
    actions, _ = security_trace.infer(issued[0], security_trace.new_ledger())
    assert actions == [("GetPinToken", 'GetPinToken({"acfg"}, NoRp)')]


def test_a_refusal_over_an_already_live_token_is_not_an_issuance():
    """The conjunct that had to join it. A clientPIN answering PIN_AUTH_INVALID
    while a token is live moves NOTHING, so on permissions alone it matched the
    issuance branch and B claimed Authorized against a refusal — measured, on the
    first recording that fetched an `acfg` token before an `mc|ga` one."""
    refusals = [
        e for e in events()
        if e["command_raw"] == 0x06 and e["outcome_raw"] == 0x33
        and e["post"]["token_in_use_raw"]
        and e["post"]["token_permissions_raw"] in security_trace.ISSUED_PERMS
        and not security_trace.raw_changes(e)
    ]
    assert refusals, "the recording no longer holds the shape this rule is for"
    actions, gate = security_trace.infer(refusals[0], security_trace.new_ledger())
    assert gate is None and [n for n, _ in actions] == ["Stutter"]


def test_a_token_less_make_credential_on_a_build_with_a_pad_is_refused():
    """§6.1.2 step 6.3 UPGRADES it to built-in UV there, so the answer stops being
    a function of `rk` and `alwaysUv`. Refused rather than guessed — which is what
    lets the rule state the alwaysUv arm at all."""
    event = copy.deepcopy(mc_gate(False))
    event["builtin_uv"] = True
    with pytest.raises(SystemExit, match="built-in UV pad"):
        security_trace.infer(event, security_trace.new_ledger())


def test_the_recording_carries_every_cell_of_the_gate_grid():
    """`gate.alwaysUv` was FALSE at every gate boundary until one session, and
    `pin.set` TRUE at every one until `09_tokenless_gate_no_pin.py` — an arm the
    recording cannot contradict is prose, whichever arm it is.

    The count comes from the ratchet rather than a literal here, so a recording
    that loses a cell fails in one place instead of two.
    """
    rows = gate_rows()
    assert len(rows) == security_trace.ratchet(security_trace.GATES_RATCHET), rows
    # (kind, rk, alwaysUv, pinSet, outcome)
    assert ("mc", True, False, False, "Authorized") in rows   # makeCredUvNotRqd, rk
    assert ("mc", False, False, False, "Authorized") in rows  # and without it
    assert ("mc", True, False, True, "Rejected") in rows      # step 10, rk
    assert ("mc", False, False, True, "Authorized") in rows   # step 10, no rk
    assert ("mc", False, True, True, "Rejected") in rows      # step 6, rk says served
    assert ("mc", True, True, True, "Rejected") in rows       # step 6, whatever rk says
    # `pinSet` FALSE here and not an oversight: the refused reset is the one that
    # ends `27_reset_window`, and the wipe it follows took the PIN with it.
    assert ("reset", False, False, False, "Rejected") in rows


def reissued_token():
    """The clientPIN boundary that re-issues a token over the permissions it
    already holds — the one shape the raw side cannot see."""
    found = [e for e in events()
             if e["command_raw"] == 0x06
             and e["subcommand"] in security_trace.TOKEN_SUBCOMMANDS
             and not (security_trace.raw_changes(e) - {"channel_raw"})
             and e["outcome_raw"] == 0x00 and e["post"]["token_in_use_raw"]]
    assert found, "the recording re-issues no token"
    return found[0]


def test_a_token_reissued_over_its_own_permissions_is_still_an_issuance():
    """It moves no raw field — every one it would move already holds that value —
    so the SUBCOMMAND is the only thing that says an issuance happened."""
    event = reissued_token()
    assert security_trace.raw_changes(event) - {"channel_raw"} == set()
    assert names_of(event) == ["GetPinToken"]
    assert security_trace.event_consensus(event, {"GetPinToken"}) == "OK"


def test_without_the_subcommand_that_re_issuance_is_a_bare_stutter():
    """The other arm, so the field is a rule and not a decoration: read as the
    `getKeyAgreement` it shares a footprint with, B claims nothing at all."""
    event = copy.deepcopy(reissued_token())
    event["subcommand"] = 0x02
    assert names_of(event) == ["Stutter"]
    assert security_trace.event_consensus(event, set()) == "NO-OPINION"


def test_a_re_issuance_the_device_refused_is_a_disagreement_and_not_a_shrug():
    """B commits to Authorized here, which is what gives R4b something to catch."""
    event = copy.deepcopy(reissued_token())
    event["outcome_raw"] = 0x31  # PIN_INVALID
    assert security_trace.event_consensus(event, {"GetPinToken"}) == "VIOLATION"


@pytest.mark.parametrize(
    "field,value",
    [("token_in_use_raw", False), ("token_permissions_raw", 1)],
)
def test_an_issuance_door_without_a_mappable_token_claims_nothing(field, value):
    """The rule reads the POST state as well as the subcommand: an issuance door
    that ends with no live token is not an issuance, and `PermSets` has no member
    for 1. B falls back to the stutter it was before the field existed rather
    than to a guess — measured, because the first version of this case expected a
    refusal and the mapper is right to answer a no-change boundary with a
    stutter."""
    event = copy.deepcopy(reissued_token())
    event["pre"][field] = value
    event["post"][field] = value
    actions, gate = security_trace.infer(event, security_trace.new_ledger())
    assert gate is None and [n for n, _ in actions] == ["Stutter"]
    assert security_trace.event_consensus(event, set()) == "NO-OPINION"


def test_a_trace_without_the_subcommand_field_is_refused(tmp_path):
    """A schema-5 recording read as a schema-6 one would put every re-issuance
    back under the stutter it cannot be told from."""
    event = copy.deepcopy(clay())
    del event["subcommand"]
    path = tmp_path / "trace.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="no subcommand record"):
        security_trace.load_events([path])


def test_an_event_without_the_pad_field_is_refused(tmp_path):
    """A schema-4 recording read as a schema-5 one would leave the arm unchecked
    and the mapper unable to refuse a display build."""
    event = copy.deepcopy(clay())
    del event["builtin_uv"]
    path = tmp_path / "trace.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="builtin_uv"):
        security_trace.load_events([path])


def test_a_permission_set_of_zero_is_not_an_issuance():
    """`ISSUED_PERMS` leaves the empty set out on purpose and nothing drove it.

    A token spent down to no permissions lands on 0 with `in_use` still TRUE and
    only token fields moved — every other conjunct of the issuance branch — so
    admitting 0 would map a CONSUMPTION as a grant. Built rather than found: no
    suite spends a token through clientPIN, which is why the omission had no
    case, and the guard is for the shape and not for the scenario.
    """
    spent = copy.deepcopy(issued_token(3))  # the getPinToken that issued mc|ga
    spent["command_raw"] = 0x06
    spent["action_hint"] = "clientPin"
    spent["pre"] = copy.deepcopy(spent["post"])
    spent["post"]["token_permissions_raw"] = 0
    assert spent["pre"]["token_permissions_raw"] == 3
    assert spent["post"]["token_in_use_raw"]
    assert security_trace.raw_changes(spent) == {"token_permissions_raw"}
    # Refused, not guessed: no branch claims it, which is the mapper's discipline.
    with pytest.raises(SystemExit, match="no independent B mapping"):
        security_trace.infer(spent, security_trace.new_ledger())


def test_admitting_a_zero_permission_set_would_map_a_consumption_as_a_grant(monkeypatch):
    """The other arm, so the omission is a rule and not a comment."""
    spent = copy.deepcopy(issued_token(3))
    spent["command_raw"] = 0x06
    spent["action_hint"] = "clientPin"
    spent["pre"] = copy.deepcopy(spent["post"])
    spent["post"]["token_permissions_raw"] = 0
    monkeypatch.setitem(security_trace.ISSUED_PERMS, 0, "{}")
    actions, _gate = security_trace.infer(spent, security_trace.new_ledger())
    assert actions == [("GetPinToken", "GetPinToken({}, NoRp)")], actions
    assert security_trace.event_consensus(spent, {"GetPinToken"}) == "OK"


def test_a_green_trace_row_floored_below_the_step_ratchet_is_fatal(tmp_path, monkeypatch):
    """`run-tlc.sh` compares a floor with `-lt`, so a GREEN trace row left at a
    minimum could stop short of its evidence and read GREEN — the "44 of 59 for
    three days" failure verbatim. The two numbers are related here."""
    floors = tmp_path / "floors.txt"
    floors.write_text(
        "TraceSecurity.cfg GREEN 30\n"
        f"{security_trace.STEPS_RATCHET} 60\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(security_trace, "FORMAL", tmp_path)
    with pytest.raises(SystemExit, match="pinned, not floored"):
        security_trace.check_green_floors_pin_the_replay()


def test_the_real_floors_pin_every_green_trace_row():
    security_trace.check_green_floors_pin_the_replay()


# --- the action roster, read out of the model instead of listed here ----------

MODULE = """\
---- MODULE Probe ----
Otp     == "otp"           \\* SCOPE_OTP, and the comment under it carries an
\\* apostrophe: without the comment cut the prime test matches THAT and a string
\\* constant reads as an action. Measured on the real module -- 54 instead of 53.
Transports == {Otp, "hid"}
Idle    == UNCHANGED <<state>>
PressDown == /\\ state' = "down"
             /\\ UNCHANGED <<gate>>
Unreached == state' = "never"
Next == \\/ PressDown \\/ Idle \\/ \\E t \\in Transports : Otp
====
"""


@pytest.fixture
def module(tmp_path):
    path = tmp_path / "Probe.tla"
    path.write_text(MODULE)
    return path


def test_only_the_definitions_that_step_are_actions(module):
    """A set and a string constant are named by `Next` too, and neither steps."""
    assert security_trace.model_actions(module, floor=1) == {"PressDown", "Idle"}


def test_a_definition_outside_next_is_not_in_the_roster(module):
    """`Unreached` primes a variable and no disjunct names it — the roster is the
    model's own `Next`, not every stepping definition in the file."""
    assert "Unreached" not in security_trace.model_actions(module, floor=1)


def test_a_comment_cannot_promote_a_constant_to_an_action(module):
    """The measured trap, pinned: leave the comments in and `Otp` reads as an
    action off an apostrophe in the prose below it."""
    derived = security_trace.model_actions(module, floor=1)
    assert "Otp" not in derived
    assert "Transports" not in derived


def test_a_broken_derivation_is_fatal_rather_than_an_empty_roster(module):
    """An empty roster satisfies "every action was reached" over nothing, which is
    the silent green this file exists against. The floor is a PARAMETER so this
    drives the real comparison rather than monkeypatching the shipped value down —
    which is how a ceiling gets shipped never having been exercised."""
    with pytest.raises(RuntimeError, match="under the floor"):
        security_trace.model_actions(module, floor=3)


def test_the_shipped_roster_is_the_shipped_module(module):
    """And the real one, so a module edit that drops an action is visible here
    rather than only in a shorter `unreached` list."""
    live = security_trace.model_actions()
    assert live == security_trace.MODEL_ACTIONS
    # AT the count, not merely above it: a floor with headroom is a floor nothing
    # has to move, and the shipped roster shrinking is a deliberate edit.
    assert len(live) == security_trace.MODEL_ACTION_FLOOR
    # Named because they are the arms whose absence would be read as coverage:
    # the token-less carve-out is UNREACHED by construction.
    assert {"RegisterNdStart", "RegisterNdTouched", "RegisterNdRefused"} <= live


# --- what the recording never varies ------------------------------------------


def constant_fields():
    """Every field the committed session gives one value to, over all its events.

    Flattened, because the raw/abstract halves are nested and a conjunct's
    antecedent lives in one of them.
    """
    import json

    rows = [json.loads(line) for line in TRACE.read_text().splitlines() if line.strip()]

    def flat(obj, prefix=""):
        for key, value in obj.items():
            if isinstance(value, dict):
                yield from flat(value, prefix + key + ".")
            else:
                yield prefix + key, repr(value)

    seen: dict[str, set[str]] = {}
    for row in rows:
        for key, value in flat(row):
            seen.setdefault(key, set()).add(value)
    return rows, seen, {k for k, v in seen.items() if len(v) == 1}


def test_the_fields_the_recording_never_varies_are_the_registered_ones():
    """`PLAT-TRACE-001`. A conjunct is checked by the replay only where its
    antecedent is true somewhere in the recording, so a field with one value is a
    clause the replay agrees with for free — and the agreement reads exactly like
    evidence. Two members of the class had rows of their own (`keydev_ram_raw`,
    `builtin_uv`); this holds the class.

    Both directions on purpose. A field that STARTS varying is good news that has
    to be recorded, and a field that stops varying is the gap arriving.
    """
    rows, seen, constant = constant_fields()
    assert len(rows) == 40, len(rows)
    # 35 until provisioning minted the grant record (0x09CB): the recording opens
    # with one and setPIN deletes it, so pre and post, raw and abstract, vary.
    assert (len(seen), len(constant)) == (81, 31), (len(seen), len(constant))
    # The ones a P0-launch conjunct reads. `token_user_present_raw` and
    # `soft_lock_raw` are the antecedents of BOTH clauses of
    # `NoAuthorizationBypass`, which is the flagship row.
    named = {
        "pre.soft_lock_raw",
        "post.soft_lock_raw",
        "pre.token_user_present_raw",
        "post.token_user_present_raw",
        "pre.warm_boot_raw",
        "post.warm_boot_raw",
        "pre.backup_sealed_record",
        "post.backup_sealed_record",
        "pre.keydev_ram_raw",
        "post.keydev_ram_raw",
        "builtin_uv",
    }
    assert named <= constant, sorted(named - constant)


# --- stage 4's "no NO-OPINION on outcome boundaries", and the table that ------
# --- proves the row it lives in can go red -----------------------------------


def test_the_shrug_classes_are_at_the_counts_they_excuse(tmp_path):
    """AT the count, not merely above it — `run_count_gate`'s measured lesson:
    "a cap with headroom is a cap nothing has to move". This is what catches a
    cap WIDENED in the source, which the `check.sh` row below cannot: raising one
    leaves the recording under it and the row green, so the pin lives here."""
    report = security_trace.generate(events(), tmp_path / "TraceSecurityData.tla")
    for name, (why, cap) in security_trace.NO_OPINION_EXEMPTIONS.items():
        assert report["no_opinion"][name] == cap, (name, report["no_opinion"][name], cap)
        # The registry's other half: a class that buys silence without saying why
        # is a class nobody is reading. `run_count_gate.LABEL_WORDS` is 8.
        assert len(why.split()) >= 8, name
    # DERIVED from the caps, not typed beside them: a re-recording then moves the
    # class it actually changed and nothing else.
    want = sum(cap for _why, cap in security_trace.NO_OPINION_EXEMPTIONS.values())
    assert sum(report["no_opinion"].values()) == want, report["no_opinion"]


def test_the_audit_floor_is_a_parameter_and_not_a_global_a_case_lowers():
    """Driven with a SMALLER registry passed in, rather than by monkeypatching the
    shipped caps down — which is how three ceilings one file over shipped never
    having been exercised against the tree they ship with."""
    shrugs = [(1, 0, "only-class"), (2, 0, "only-class")]
    security_trace.audit_no_opinion(shrugs, {"only-class": ("because measured", 2)})
    with pytest.raises(SystemExit, match=r"exemption grew: only-class=2 > 1"):
        security_trace.audit_no_opinion(shrugs, {"only-class": ("because measured", 1)})
    with pytest.raises(SystemExit, match="not registered"):
        security_trace.audit_no_opinion(shrugs, {})


def test_an_unexcused_shrug_names_the_event_and_the_direction_c_answered():
    """The message carries C's side, because a red run is not evidence until you
    know which way it fell — 2 of 24 co-refutation kills in this tree were kills
    for the inverse defect, and a verdict column hides that either way."""
    with pytest.raises(SystemExit, match=r"event 36 \(C=Rejected\), event 39 \(C=Authorized\)"):
        security_trace.audit_no_opinion([(36, 0x31, None), (39, 0x00, None)])


def test_a_power_cycle_carrying_a_status_is_not_the_pseudo_command_excused():
    """`tools/emu/src/device.rs:816-817` passes the literal 0 as the status of a
    replug, so `delta_c` of it is a placeholder, not the device answering — and
    THAT is the class's whole reason, so the arm asserts it.

    This case used to pin the hole instead: it asserted 0x36 was excused too, over
    an arm that never read the byte. Measured then: a power cycle carrying 0x31
    left the row green at 15/18. The widest arm is the one with no bare-stutter
    requirement, so it is the one that has to check its own premise.
    """
    event = copy.deepcopy(clay())
    event["command_raw"] = security_trace.POWER_CYCLE
    event["outcome_raw"] = 0x00
    assert security_trace.no_opinion_class(event, {"PowerCut"}) == "pseudo-command"
    for raw in (0x31, 0x36):
        event["outcome_raw"] = raw
        with pytest.raises(SystemExit, match="a power cycle answered"):
            security_trace.no_opinion_class(event, {"PowerCut"})


def test_the_two_newly_mapped_boundaries_now_refuse_their_inverse_defects():
    """What the mapping bought beyond closing the criterion, pinned.

    A shrug is not just missing evidence — it disables `R4b-event`'s VIOLATION arm
    at that boundary. Before `WrongPin` and `ResetFinish` were mapped, a device
    that wiped the store and answered `0x30`, or that moved BOTH PIN counters and
    answered `0x00`, replayed green. Both are disagreements now, and the message
    says which way each fell rather than only that something fell.
    """
    reset = copy.deepcopy(resets()[0])
    reset["outcome_raw"] = 0x30  # wiped, and then claimed NOT_ALLOWED
    with pytest.raises(SystemExit, match=r"violation — B=\['Authorized'\], C=Rejected"):
        security_trace.generate([reset], pathlib.Path("/dev/null"))

    event = copy.deepcopy(wrong_pin())
    event["outcome_raw"] = 0x00  # both counters moved, and then answered OK
    assert security_trace.event_consensus(event, {"WrongPin"}) == "VIOLATION"


def test_a_boundary_where_real_actions_ran_has_no_excuse_at_all():
    """The bare-stutter coupling, which is BELT and not the mechanism.

    Measured, against the claim this docstring first made: deleting the check
    leaves the `check.sh` row GREEN, and dropping `WrongPin` on top of it reddens
    at `refusal-is-a-disabled-action=2 > 1` — the CAP — rather than at the
    unexcused list. So the caps are what catch an unmapped action today; this
    holds the shape that would still catch one if a cap were widened.
    """
    event = copy.deepcopy(clay())
    event["command_raw"] = 0x04
    assert security_trace.no_opinion_class(event, {"Stutter"}) == "unmodelled-command"
    assert security_trace.no_opinion_class(event, {"Stutter", "Tick"}) is None
    assert security_trace.no_opinion_class(event, {"WrongPin"}) is None


# --- the mutation table, driven through the `check.sh` row itself -------------

#: What the row copies into its own work directory, plus what the mapper reads
#: back out of `formal/`. A throwaway tree rather than the real one, because
#: `ROOT = Path(__file__).resolve().parents[1]` is how the script finds `formal/`
#: — so a copy at the same relative depth IS the row, and the real checkout is
#: never patched by a test that another agent could be running rows against.
ROW_FORMAL = (
    "floors.txt", "TraceSecurityData.tla", "RSKeySecurityState.tla",
    "RSKeyTokenView.tla", "TraceSecurity.tla",
)


class Row:
    """The `security trace refinement` row of `check.sh`, over a copied tree."""

    def __init__(self, root):
        self.root = root
        real = pathlib.Path(__file__).parents[1]
        (root / "scripts").mkdir(parents=True)
        (root / "formal/traces").mkdir(parents=True)
        shutil.copy2(real / "scripts/security_trace.py", root / "scripts")
        for name in ROW_FORMAL:
            shutil.copy2(real / "formal" / name, root / "formal" / name)
        for cfg in sorted((real / "formal").glob("TraceSecurity*.cfg")):
            shutil.copy2(cfg, root / "formal" / cfg.name)
        shutil.copy2(TRACE, root / "formal/traces" / TRACE.name)

    def edit(self, old, new, count=1):
        """Patch the copied mapper, failing loudly if the anchor did not resolve.

        A `str.replace` that matches nothing leaves the fixture UNPATCHED and the
        case then proves nothing while reading green — measured in this tree
        before, which is why every row below goes through here.
        """
        path = self.root / "scripts/security_trace.py"
        text = path.read_text()
        assert text.count(old) == count, f"anchor {old!r} appears {text.count(old)}x, not {count}"
        path.write_text(text.replace(old, new))

    def run(self, flag="--check-data", env=None):
        """The row's own command, argument for argument."""
        return subprocess.run(
            [sys.executable, str(self.root / "scripts/security_trace.py"), flag,
             str(self.root / "formal/TraceSecurityData.tla"),
             str(self.root / "formal/traces" / TRACE.name)],
            capture_output=True, text=True, check=False, env=env,
        )


#: (id, patch, expected exit, expected message). A GREEN row is `0` and its
#: message must NOT appear; a red one is `1` and the message is what says the row
#: fell for the defect this case models rather than for something adjacent.
SHRUG_MUTANTS = [
    # The finding itself, restored: an action with a live B interpretation that
    # nothing maps. `@TraceSecurityOutcomesMin` is BLIND to it — 14 over a floor
    # of 13 — which is why the rule is per-event and not another count.
    ("wrong-pin-unmapped", ('    "WrongPin": "Rejected",\n', ""), 1,
     "no-opinion on event 36 (C=Rejected)"),
    ("reset-finish-unmapped", ('    "ResetFinish": "Authorized",\n', ""), 1,
     "no-opinion on event 39 (C=Authorized)"),
    # The class derivations, one command and one subcommand: both are read off the
    # event's own fields, so narrowing either leaves a real boundary unexcused.
    ("get-next-assertion-unregistered",
     ("MODEL_SILENT_COMMANDS = {0x04, 0x08}", "MODEL_SILENT_COMMANDS = {0x04}"), 1,
     "no-opinion on event 18 (C=Authorized)"),
    ("get-pin-retries-unregistered",
     ("MODEL_SILENT_SUBCOMMANDS = {0x01, 0x02}", "MODEL_SILENT_SUBCOMMANDS = {0x02}"), 1,
     "no-opinion on event 35 (C=Authorized), event 37 (C=Authorized)"),
    # The cap, and its direction. Lowering it by one can only go red if the cap is
    # AT the count — headroom would absorb it, which is the defect the equality
    # test above pins from the other side.
    ("cap-lowered-by-one", ("        10,\n", "        9,\n"), 1,
     "exemption grew: unmodelled-command=10 > 9"),
    # And the registry is READ, not decoration: a class the derivation still
    # returns but nobody registered is a reason nobody wrote down.
    ("class-deregistered", ('    "unmodelled-command": (', '    "unregistered-name": ('), 1,
     "no-opinion class ['unmodelled-command'] is not registered"),
    # CONTROLS. The first two REWRITE EXECUTING CODE on the audited path and must
    # stay green; a table whose only controls are a comment and a dict-key
    # reorder proves nothing, because neither ever executes differently — which
    # is what the first two of these were until it was pointed out.
    #
    # The accumulation runs once per shrug on every run of the row, and the
    # refusal test is what event 33 is classified by, so both are reached.
    ("control-accumulator-rewritten",
     ("    counted: dict[str, int] = {}\n"
      "    for _seq, _raw, excuse in shrugs:\n"
      "        counted[excuse] = counted.get(excuse, 0) + 1\n",
      "    counted = {name: sum(1 for _s, _r, e in shrugs if e == name)\n"
      "               for _s, _r, name in shrugs}\n"), 0,
     "no-opinion"),
    ("control-refusal-test-rewritten",
     ('    if event["outcome_raw"] != 0x00:\n        return "refusal-is-a-disabled-action"',
      '    if event["outcome_raw"] not in (0x00,):\n        return "refusal-is-a-disabled-action"'), 0,
     "no-opinion"),
    # And the spelling baseline, kept for what it actually shows and nothing more:
    # a pure comment edit does not move the row.
    ("control-comment-rewritten",
     ("    The order is narrow-first, and what it separates is measured",
      "    The ordering here is narrow-first, and what it splits is measured"), 0,
     "no-opinion"),
]


@pytest.mark.parametrize("name,patch,code,message", SHRUG_MUTANTS,
                         ids=[m[0] for m in SHRUG_MUTANTS])
def test_the_check_sh_row_falls_for_each_shrug_mutant(tmp_path, name, patch, code, message):
    row = Row(tmp_path)
    row.edit(*patch)
    done = row.run()
    assert done.returncode == code, (done.returncode, done.stdout[-800:], done.stderr[-800:])
    if code:
        assert message in done.stderr, done.stderr[-800:]
    else:
        assert message not in done.stderr, done.stderr[-800:]
        assert "GREEN commands=40" in done.stdout, done.stdout[-800:]


def test_the_row_keeps_a_java_io_tmpdir_of_its_own(tmp_path):
    """SANY writes each standard module into java.io.tmpdir, so TLCs sharing one
    parsed each other's half-written Naturals.tla (exit 150). A default nothing can
    be written to stands in for a shared one, without a race."""
    absent = tmp_path / "no-such-tmp"
    poisoned = {**os.environ, "JAVA_TOOL_OPTIONS": f"-Djava.io.tmpdir={absent}"}
    done = Row(tmp_path).run(env=poisoned)
    assert done.returncode == 0, done.stderr[-800:]


def test_the_unpatched_copy_of_the_row_is_green(tmp_path):
    """The table's own baseline: without a patch the copied tree is the shipped
    row, so every red above is the mutation and not the copying."""
    done = Row(tmp_path).run()
    assert done.returncode == 0, done.stderr[-800:]
    assert "no-opinion: pseudo-command=1/1" in done.stdout, done.stdout[-800:]


def test_the_arm_that_was_a_bare_pass_is_what_catches_the_defect(tmp_path):
    """The wiring, proven the only way it can be: put the arm back to `pass`, keep
    the defect, and watch the row go GREEN.

    A guard whose call site nothing exercises can be deleted with the suite still
    green. `wrong-pin-unmapped` above shows the defect caught; this shows what
    catches it. The data module is regenerated first because the defect moves it
    and a stale-data refusal would be a red for the wrong reason — which is
    exactly the routine `--keep-data` regeneration that made the retreat free.
    """
    row = Row(tmp_path)
    row.edit('    "WrongPin": "Rejected",\n', "")
    row.edit("                shrugs.append(", "                _ = (")
    assert row.run("--keep-data").returncode == 0
    done = row.run()
    assert done.returncode == 0, done.stderr[-800:]
    assert "outcomes=14" in done.stdout, done.stdout[-800:]
