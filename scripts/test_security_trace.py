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
    assert names_of(events()[2]) == ["SetPinStart", "SetPinClearPpuat", "SetPinWrite"]


def test_a_power_cycle_is_one_power_cut_and_reads_no_state_difference():
    event = copy.deepcopy(events()[0])
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


def test_a_seedless_store_holding_records_has_no_sweep_length():
    ledger = security_trace.new_ledger()
    ledger["seed"] = False
    ledger["cred"].add("rp1")
    with pytest.raises(SystemExit, match="no modelled sweep length"):
        security_trace.reset_path(ledger)
    # And the other direction: nothing to open is not the same as a lost seed.
    ledger["cred"].clear()
    assert [n for n, _ in security_trace.reset_path(ledger)].count("ResetSweepSecrets") == 1


def test_each_gate_the_sweep_deletes_costs_its_own_step():
    # `always_uv` and `sealed` are `GatesLive` terms the recording never sets, so
    # nothing else here would notice one moved to the secrets phase.
    base = security_trace.new_ledger()
    assert [n for n, _ in security_trace.reset_path(base)].count("ResetSweepGates") == 1
    for gate in ("pin_set", "always_uv", "sealed"):
        ledger = security_trace.new_ledger()
        ledger[gate] = True
        names = [n for n, _ in security_trace.reset_path(ledger)]
        assert names.count("ResetSweepGates") == 2, gate
        assert names.count("ResetSweepSecrets") == 2, gate


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


# --- R4c: the gate answers -------------------------------------------------
#
# Each rule below is pierced in both directions: the mapper must produce a gate
# row where one belongs, and must refuse the event where the rule does not reach.
# The TLA+ half — B's own answer disagreeing with the recording — is
# `TraceSecurityBadUvNotRqd.cfg` and `TraceSecurityBadResetWindow.cfg`, both
# required RED by `floors.txt`.


def test_a_token_less_make_credential_is_answered_by_the_gate_and_rk_decides():
    # Seq 11 and 12 are the same request twice, once with `rk` and once without,
    # and neither writes anything: the raw sides are identical and only the
    # INPUT separates them.
    refused, allowed = events()[10], events()[11]
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
    event = copy.deepcopy(events()[11])
    event["outcome_raw"] = 0x19
    with pytest.raises(SystemExit, match="downstream of the gate"):
        security_trace.infer(event, security_trace.new_ledger())


def test_a_token_bearing_make_credential_is_not_a_gate_row():
    event = copy.deepcopy(events()[11])
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
    event = copy.deepcopy(events()[11])
    event["action_hint"] = "clientPin"
    with pytest.raises(SystemExit, match="action_hint disagrees"):
        security_trace.infer(event, security_trace.new_ledger())


def test_the_power_cycle_reopens_the_reset_window_for_b_as_well():
    ledger = security_trace.new_ledger()
    ledger["clock"] = 1
    event = copy.deepcopy(events()[0])
    event["command_raw"] = security_trace.POWER_CYCLE
    event["post"] = copy.deepcopy(event["pre"])
    security_trace.infer(event, ledger)
    assert ledger["clock"] == 0


def test_an_older_schema_is_refused_rather_than_read(tmp_path):
    event = copy.deepcopy(events()[0])
    event["schema"] = 3
    path = tmp_path / "old.jsonl"
    path.write_text(f"{json.dumps(event)}\n")
    with pytest.raises(SystemExit, match="unsupported schema"):
        security_trace.load_events([path])


def test_a_trace_with_no_request_record_is_refused(tmp_path):
    event = copy.deepcopy(events()[0])
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
    event = copy.deepcopy(events()[10])
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
    assert "scripts/security_trace.py --check-data" in check


# --- the alwaysUv arm, and the branches the session that recorded it needed ---


def configs():
    """The two authenticatorConfig boundaries: alwaysUv on, then off again."""
    found = [e for e in events() if e["command_raw"] == 0x0D]
    assert len(found) == 2, [e["sequence"] for e in found]
    return found


def gate_rows():
    """(kind, rk, alwaysUv, recorded outcome) per gate boundary, in order."""
    ledger = security_trace.new_ledger()
    rows = []
    for event in events():
        security_trace.clock_ticks(event, ledger)
        _actions, gate = security_trace.infer(event, ledger)
        if gate is not None:
            rows.append((gate[0], gate[1], ledger["always_uv"],
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
    event = copy.deepcopy(events()[11])
    event["builtin_uv"] = True
    with pytest.raises(SystemExit, match="built-in UV pad"):
        security_trace.infer(event, security_trace.new_ledger())


def test_the_recording_carries_both_arms_of_the_gate_rule():
    """`gate.alwaysUv` was FALSE at every gate boundary until this session, so the
    arm the rule was missing could not be seen — and `pin.set /\\ rk` predicts
    SERVED for the row that matters here."""
    rows = gate_rows()
    assert len(rows) == 5, rows
    assert ("mc", True, False, "Rejected") in rows      # step 10, rk
    assert ("mc", False, False, "Authorized") in rows   # step 10, no rk
    assert ("mc", False, True, "Rejected") in rows      # step 6, and rk says served
    assert ("mc", True, True, "Rejected") in rows       # step 6, whatever rk says
    assert ("reset", False, False, "Rejected") in rows


def test_an_event_without_the_pad_field_is_refused(tmp_path):
    """A schema-4 recording read as a schema-5 one would leave the arm unchecked
    and the mapper unable to refuse a display build."""
    event = copy.deepcopy(events()[0])
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
    spent = copy.deepcopy(events()[3])  # the getPinToken that issued mc|ga
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
    spent = copy.deepcopy(events()[3])
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
