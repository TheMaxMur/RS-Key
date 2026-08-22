#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Map raw emulator security snapshots to RSKeySecurityState trace actions."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"

RAW_FIELDS = {
    "pin_record_len": "pinRecordLen",
    "pin_retries_raw": "pinRetriesRaw",
    "always_uv_record_len": "alwaysUvRecordLen",
    "always_uv_raw": "alwaysUvRaw",
    "persistent_grant_record": "persistentGrantRecord",
    "backup_sealed_record": "backupSealedRecord",
    "seed_plain_record": "seedPlainRecord",
    "seed_encrypted_record": "seedEncryptedRecord",
    "credential_slots_raw": "credentialSlotsRaw",
    "rp_slots_raw": "rpSlotsRaw",
    "token_in_use_raw": "tokenInUseRaw",
    "token_permissions_raw": "tokenPermissionsRaw",
    "token_has_rp_id_raw": "tokenHasRpIdRaw",
    "token_user_present_raw": "tokenUserPresentRaw",
    "token_user_verified_raw": "tokenUserVerifiedRaw",
    "soft_lock_raw": "softLockRaw",
    "pin_mismatches_raw": "pinMismatchesRaw",
    "cm_channel_raw": "cmChannelRaw",
    "cm_rp_counter_raw": "cmRpCounterRaw",
    "cm_rp_total_raw": "cmRpTotalRaw",
    "cm_cred_counter_raw": "cmCredCounterRaw",
    "cm_cred_total_raw": "cmCredTotalRaw",
    "warm_boot_raw": "warmBootRaw",
    "channel_raw": "channelRaw",
    "keydev_ram_raw": "keydevRamRaw",
}

ABSTRACT_FIELDS = {
    "live": "live",
    "permission_mc": "permissionMc",
    "permission_ga": "permissionGa",
    "permission_cm": "permissionCm",
    "permission_acfg": "permissionAcfg",
    "rp_bound": "rpBound",
    "pin_set": "pinSet",
    "persistent_grant": "persistentGrant",
}

MODEL_ACTIONS = {
    "PressDown", "PressUp", "HostCancel", "HostCancelLatched", "TouchConfirm",
    "TouchCancel", "TouchTimeout", "LocalCeremonyStart", "LocalCeremonyEnds",
    "OtpCancelWait", "GetPinToken", "WrongPin", "MintPpuat", "LocalPinWrong",
    "LocalPinOk", "SetPinStart", "SetPinClearPpuat", "SetPinWrite",
    "ChangePinStart", "ChangePinClearPpuat", "ChangePinWrite",
    "ChangePinRotateToken", "StopUsingToken", "RegisterStart", "RegisterTouched",
    "RegisterRefused", "RegisterWriteA", "RegisterWriteB", "AssertStart",
    "AssertFinish", "ConfigOp", "BackupFinalize", "DeviceUnlock",
    "CmBeginViaToken", "CmBeginViaPpuat", "CmNext", "DeleteCredStart",
    "DeleteCredWriteA", "DeleteCredWriteB", "ResetStart", "ResetRefused",
    "ResetConfirmed", "ResetSweepSecrets", "ResetSweepGates", "ResetFinish",
    "ResetAborts", "PowerCut", "WarmReset", "Tick", "WalkExpires",
}

OUTCOME_BY_ACTION = {
    "GetPinToken": "Authorized",
    "MintPpuat": "Authorized",
    "SetPinWrite": "Authorized",
    "RegisterWriteB": "Authorized",
    "AssertFinish": "Authorized",
    "ConfigOp": "Authorized",
    "CmBeginViaToken": "Authorized",
    "CmBeginViaPpuat": "Authorized",
    "CmNext": "Authorized",
    "DeleteCredStart": "Authorized",
    "RegisterRefused": "Rejected",
    "ResetRefused": "Rejected",
}

AMBIGUOUS_RATCHET = "@TraceSecurityAmbiguousMax"
COMMANDS_RATCHET = "@TraceSecurityCommandsMin"
STEPS_RATCHET = "@TraceSecurityStepsMin"
ACTIONS_RATCHET = "@TraceSecurityActionsMin"

# The pseudo-command `tools/emu` records a power cycle under — outside the CTAP
# command space, so it cannot collide with a real command byte.
POWER_CYCLE = 0xFF


def die(message: str) -> None:
    raise SystemExit(f"security-trace: {message}")


def load_events(paths: list[Path]) -> list[dict]:
    events: list[dict] = []
    for path in paths:
        with path.open(encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    die(f"{path}:{line_no}: invalid JSON: {error}")
                if event.get("schema") != 3:
                    die(f"{path}:{line_no}: unsupported schema")
                if event.get("boundary") != {"mode": "coarse", "k": 8}:
                    die(f"{path}:{line_no}: boundary must be coarse with k=8")
                if set(event.get("pre", {})) != set(RAW_FIELDS):
                    die(f"{path}:{line_no}: raw pre fields changed")
                if set(event.get("post", {})) != set(RAW_FIELDS):
                    die(f"{path}:{line_no}: raw post fields changed")
                if set(event.get("abstract_pre", {})) != set(ABSTRACT_FIELDS):
                    die(f"{path}:{line_no}: abstract pre fields changed")
                if set(event.get("abstract_post", {})) != set(ABSTRACT_FIELDS):
                    die(f"{path}:{line_no}: abstract post fields changed")
                if not isinstance(event.get("outcome_raw"), int):
                    die(f"{path}:{line_no}: outcome_raw must be the real integer response code")
                events.append(event)
    if not events:
        die("no trace events")
    for previous, current in zip(events, events[1:]):
        if previous["post"] != current["pre"]:
            die(f"raw discontinuity before event {current['sequence']}")
        if previous["abstract_post"] != current["abstract_pre"]:
            die(f"abstract discontinuity before event {current['sequence']}")
    return events


def raw_changes(event: dict) -> set[str]:
    return {
        field for field in RAW_FIELDS
        if event["pre"][field] != event["post"][field]
    }


def new_ledger() -> dict:
    """What B's store holds, tracked from the actions the replayer itself emits.

    The reset sweeps run once per live record, so their length is B's count, not
    the device's: `RegisterStart("rp1", …)` folds every real credential of one
    relying party onto one model element, and the raw slot counters cannot say
    how many that is. Nothing here is read back from the trace.
    """
    return {"seed": True, "cred": set(), "rpent": set(), "pin_set": False,
            "always_uv": False, "ppuat": False, "sealed": False}


def reset_path(ledger: dict) -> list[tuple[str, str]]:
    """`ResetStart` through `ResetFinish`, one sweep step per live SECRET.

    The seed is not one record among many: `ResetSweepSecrets`'s first arm is
    `store' = KeepOpen([store EXCEPT !.seed = FALSE], ram)`, and `ResetConfirmed`
    has already cleared `ram` — so deleting it empties `cred` and `rpent` in the
    SAME step, because nothing without the seed can be opened. The sweep's length
    therefore does not grow with the number of credentials B holds.

    Counting one step per record is what this used to do, and the model had been
    refusing the surplus — see `run_tlc` for the half of the repair that makes
    that impossible to miss.

    Each phase ends with one extra step: the `ELSE` arm that advances `op.step`
    once nothing is left to delete.
    """
    if not ledger["seed"] and (ledger["cred"] or ledger["rpent"]):
        die("a store with records but no seed has no modelled sweep length")
    # `SealedIsASecret` needs `BugBackupSealedNotAGate`, which no trace
    # configuration sets, so the seal is counted with the gates below.
    secrets = int(ledger["seed"]) + int(ledger["ppuat"])
    gates = int(ledger["pin_set"]) + int(ledger["always_uv"]) + int(ledger["sealed"])
    steps = [
        ("ResetStart", "ResetStart"),
        ("PressDown", "PressDown"),
        ("TouchConfirm", "/\\ TouchConfirm /\\ pres'.pressing = TRUE"),
        ("ResetConfirmed", "ResetConfirmed"),
    ]
    steps += [("ResetSweepSecrets", "ResetSweepSecrets")] * (secrets + 1)
    steps += [("ResetSweepGates", "ResetSweepGates")] * (gates + 1)
    return steps + [("ResetFinish", "ResetFinish"), ("PressUp", "PressUp")]


def infer(event: dict, ledger: dict) -> list[tuple[str, str]]:
    """Infer B actions from raw before/after state; action_hint is diagnostic."""
    before, after = event["pre"], event["post"]
    changed = raw_changes(event)
    command = event["command_raw"]

    if before["pin_record_len"] is None and after["pin_record_len"] == 35:
        actions = [
            ("SetPinStart", "SetPinStart"),
            ("SetPinClearPpuat", "SetPinClearPpuat"),
            ("SetPinWrite", "SetPinWrite"),
        ]
        ledger["pin_set"] = True
    elif (
        command == 0x06
        and after["token_in_use_raw"]
        and after["token_permissions_raw"] == 3
        and changed <= {
            "token_in_use_raw", "token_permissions_raw", "token_has_rp_id_raw",
            "token_user_present_raw", "token_user_verified_raw", "pin_retries_raw",
            "cm_channel_raw", "cm_rp_counter_raw", "cm_rp_total_raw",
            "cm_cred_counter_raw", "cm_cred_total_raw",
        }
    ):
        actions = [("GetPinToken", 'GetPinToken({"mc", "ga"}, NoRp)')]
    elif command == 0x01 and after["credential_slots_raw"] > before["credential_slots_raw"]:
        actions = presence_path("register")
        ledger["cred"].add("rp1")
        ledger["rpent"].add("rp1")
    elif (
        command == 0x02
        and before["token_permissions_raw"] == 3
        and after["token_permissions_raw"] == 0
    ):
        actions = presence_path("assert")
    elif (
        command == 0x06
        and before["pin_retries_raw"] is not None
        and after["pin_retries_raw"] < before["pin_retries_raw"]
        and after["pin_mismatches_raw"] > before["pin_mismatches_raw"]
    ):
        # Both counters move together only on a comparison that failed; a correct
        # PIN restores the retry budget and leaves the mismatch count alone.
        actions = [("WrongPin", "WrongPin")]
    elif command == 0x07 and after["credential_slots_raw"] == 0 \
            and after["pin_record_len"] is None and after["rp_slots_raw"] == 0:
        actions = reset_path(ledger)
        ledger.update(new_ledger())
    elif command == POWER_CYCLE:
        # The event kind is the signature, not any state difference: the replayer
        # is told a power cycle happened and R4a then checks that the raw state
        # matches what `PowerCut` says one does.
        actions = [("PowerCut", "PowerCut")]
    elif not changed or changed == {"channel_raw"}:
        actions = [("Stutter", "TraceStutter")]
    else:
        die(
            f"event {event['sequence']}: no independent B mapping for command "
            f"0x{command:02x}, changed={sorted(changed)}"
        )

    if actions[0][0] != "Stutter":
        expected = {
            0x01: "makeCredential",
            0x02: "getAssertion",
            0x06: "clientPin",
        }.get(command)
        if expected is not None and event.get("action_hint") != expected:
            die(f"event {event['sequence']}: action_hint disagrees with inferred family")
    return actions


def presence_path(kind: str) -> list[tuple[str, str]]:
    if kind == "register":
        middle = [
            ("RegisterStart", 'RegisterStart("rp1", Fido)'),
            ("PressDown", "PressDown"),
            ("TouchConfirm", "/\\ TouchConfirm /\\ pres'.pressing = TRUE"),
            ("RegisterTouched", "RegisterTouched"),
            ("RegisterWriteA", "RegisterWriteA"),
            ("RegisterWriteB", "RegisterWriteB"),
        ]
    else:
        middle = [
            ("AssertStart", 'AssertStart("rp1", Fido)'),
            ("PressDown", "PressDown"),
            ("TouchConfirm", "/\\ TouchConfirm /\\ pres'.pressing = TRUE"),
            ("AssertFinish", "AssertFinish"),
        ]
    return middle + [("PressUp", "PressUp")]


def delta_c(outcome_raw: int) -> str:
    return "Authorized" if outcome_raw == 0 else "Rejected"


def inferred_outcomes(action_names: set[str], command: int) -> set[str]:
    outcomes = {OUTCOME_BY_ACTION[name] for name in action_names if name in OUTCOME_BY_ACTION}
    if action_names == {"Stutter"} and command in {0x01, 0x02, 0x07, 0x0A, 0x0D}:
        outcomes.update({"Authorized", "Rejected"})
    return outcomes


def event_consensus(event: dict, action_names: set[str]) -> str:
    outcomes = inferred_outcomes(action_names, event["command_raw"])
    if len(outcomes) > 1:
        return "AMBIGUOUS"
    if outcomes != {delta_c(event["outcome_raw"])}:
        return "VIOLATION"
    return "OK"


def ratchet(name: str) -> int:
    """One `@Name value` line from `floors.txt`.

    The coverage floors live beside every other ratchet rather than as literals
    here, for the reason that file's own header gives: a number nobody has to
    open a script to change is a number that gets changed in passing.
    """
    for line in (FORMAL / "floors.txt").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if parts[:1] == [name] and len(parts) == 2:
            return int(parts[1])
    die(f"floors.txt has no {name} ratchet")


def tla_value(value: object) -> str:
    if value is None:
        return "-1"
    if value is True:
        return "TRUE"
    if value is False:
        return "FALSE"
    if isinstance(value, int):
        return str(value)
    die(f"cannot encode TLA+ value {value!r}")


def tla_record(data: dict, fields: dict[str, str]) -> str:
    parts = [f"{tla} |-> {tla_value(data[source])}" for source, tla in fields.items()]
    return "[ " + ",\n        ".join(parts) + " ]"


def case_operator(name: str, values: list[tuple[int, str]]) -> str:
    arms = []
    for index, value in values:
        marker = "CASE" if not arms else "  []"
        arms.append(f"    {marker} i = {index} -> {value}")
    arms.append('      [] OTHER -> CHOOSE x : FALSE')
    return f"{name}(i) ==\n" + "\n".join(arms)


def generate(events: list[dict], output: Path) -> dict:
    actions: list[tuple[str, str]] = []
    boundaries: list[tuple[int, dict, dict]] = [
        (0, events[0]["pre"], events[0]["abstract_pre"])
    ]
    beta_boundary = None
    alpha_boundary = None
    outcome_boundaries: list[tuple[int, str, str]] = []
    ambiguous = 0
    ledger = new_ledger()
    for event in events:
        inferred = infer(event, ledger)
        actions.extend(inferred)
        pc = len(actions)
        boundaries.append((pc, event["post"], event["abstract_post"]))
        action_names = {name for name, _ in inferred}
        outcomes_b = inferred_outcomes(action_names, event["command_raw"])
        consensus = event_consensus(event, action_names)
        if consensus == "AMBIGUOUS":
            ambiguous += 1
        elif outcomes_b:
            if consensus != "OK":
                die(
                    f"event {event['sequence']}: R4b-event {consensus.lower()} — "
                    f"B={sorted(outcomes_b)}, C={delta_c(event['outcome_raw'])}"
                )
            outcome_boundaries.append((pc, delta_c(event["outcome_raw"]), next(iter(outcomes_b))))
        if beta_boundary is None and event["pre"]["pin_record_len"] is None \
                and event["post"]["pin_record_len"] == 35:
            beta_boundary = pc
        if alpha_boundary is None and not event["pre"]["token_in_use_raw"] \
                and event["post"]["token_in_use_raw"]:
            alpha_boundary = pc
    if beta_boundary is None or alpha_boundary is None:
        die("trace must include setPIN and first token issuance for the two mutations")

    raw_values = [(pc, tla_record(raw, RAW_FIELDS)) for pc, raw, _ in boundaries]
    abstract_values = [
        (pc, tla_record(abstract, ABSTRACT_FIELDS)) for pc, _, abstract in boundaries
    ]
    action_values = [(index, expression) for index, (_, expression) in enumerate(actions)]
    outcome_raw_values = [(pc, f'"{raw}"') for pc, raw, _ in outcome_boundaries]
    outcome_b_values = [(pc, f'"{model}"') for pc, _, model in outcome_boundaries]
    reached = {name for name, _ in actions if name != "Stutter"}
    floors = [
        ("commands", len(events), ratchet(COMMANDS_RATCHET)),
        ("steps", len(actions), ratchet(STEPS_RATCHET)),
        ("distinct-actions", len(reached), ratchet(ACTIONS_RATCHET)),
    ]
    short = [f"{what}={got} < {want}" for what, got, want in floors if got < want]
    if short:
        die("coverage ratchet missed: " + ", ".join(short))

    text = "\n".join([
        "------------------------- MODULE TraceSecurityData -------------------------",
        "(*****************************************************************************)",
        "(* SPDX-License-Identifier: AGPL-3.0-only                                    *)",
        "(* Copyright (C) 2026 RS-Key contributors                                    *)",
        "(* Generated by scripts/security_trace.py from raw emulator JSONL.            *)",
        "(*****************************************************************************)",
        "EXTENDS RSKeySecurityState, Integers",
        "",
        f"TraceSteps == {len(actions)}",
        "BoundaryPcs == {" + ", ".join(str(pc) for pc, _, _ in boundaries) + "}",
        f"BetaMutationBoundary == {beta_boundary}",
        f"AlphaMutationBoundary == {alpha_boundary}",
        "OutcomeBoundaryPcs == {" + ", ".join(str(pc) for pc, _, _ in outcome_boundaries) + "}",
        f"OutcomeMutationBoundary == {outcome_boundaries[0][0]}",
        "",
        "TraceStutter == UNCHANGED vars",
        "",
        case_operator("BoundaryRaw", raw_values),
        "",
        case_operator("BoundaryAbstract", abstract_values),
        "",
        case_operator("BoundaryOutcomeRaw", outcome_raw_values),
        "",
        case_operator("BoundaryOutcomeB", outcome_b_values),
        "",
        case_operator("TraceAction", action_values),
        "",
        "=============================================================================",
        "",
    ])
    output.write_text(text, encoding="utf-8")
    return {
        "commands": len(events),
        "steps": len(actions),
        "reached": sorted(reached),
        "unreached": sorted(MODEL_ACTIONS - reached),
        "ambiguous": ambiguous,
    }


DISTINCT = re.compile(r"([\d,]+) distinct states found")


def run_tlc(work: Path, config: str) -> tuple[int, int | None]:
    """One TLC run, and the number of distinct states it reported.

    `-deadlock` is NOT passed, and that is the point. A replay is forced step by
    step, so a step the model cannot take leaves TLC with nowhere to go — the
    divergence IS the deadlock, at the exact index. Suppressing the check turned
    every such divergence into a short run reporting "No error has been found":
    the recorded reset ran fifteen steps past where the model stopped following
    it. The count is the second half, because a replay is linear and its length
    is known in advance.
    """
    jar = os.environ.get("TLA2TOOLS_JAR")
    if not jar:
        die("TLA2TOOLS_JAR unset -- run inside `nix develop`")
    java = os.environ.get("JAVA") or shutil.which("java")
    if not java:
        die("java not found")
    result = subprocess.run(
        [java, "-XX:+UseParallelGC", "-Xmx2g", "-cp", jar, "tlc2.TLC",
         "-nowarning", "-workers", "2", "-config", config, "TraceSecurity"],
        cwd=work,
        check=False,
        capture_output=True,
        text=True,
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    found = DISTINCT.findall(result.stdout)
    distinct = int(found[-1].replace(",", "")) if found else None
    return result.returncode, distinct


def validate(
    paths: list[Path],
    keep_data: Path | None = None,
    check_data: Path | None = None,
    run_mutations: bool = False,
) -> None:
    events = load_events(paths)
    with tempfile.TemporaryDirectory(prefix="rsk-security-trace-") as tmp:
        work = Path(tmp)
        for name in ["RSKeySecurityState.tla", "RSKeyTokenView.tla", "TraceSecurity.tla"]:
            shutil.copy2(FORMAL / name, work / name)
        report = generate(events, work / "TraceSecurityData.tla")
        if keep_data is not None:
            shutil.copy2(work / "TraceSecurityData.tla", keep_data)
        if check_data is not None and (
            not check_data.exists()
            or check_data.read_bytes() != (work / "TraceSecurityData.tla").read_bytes()
        ):
            die(
                f"{check_data} is stale; regenerate with "
                "--keep-data formal/TraceSecurityData.tla"
            )
        configs = ["TraceSecurity.cfg"]
        if run_mutations:
            configs += [
                "TraceSecurityBadBeta.cfg",
                "TraceSecurityBadAlpha.cfg",
                "TraceSecurityBadAlphaNoR4b.cfg",
            ]
        for config in configs:
            shutil.copy2(FORMAL / config, work / config)
            rc, distinct = run_tlc(work, config)
            green = config in {"TraceSecurity.cfg", "TraceSecurityBadAlphaNoR4b.cfg"}
            expected = 0 if green else 12
            if rc != expected:
                die(f"{config}: TLC exit {rc}, expected {expected}")
            # A linear replay that reaches the end has exactly one state per step
            # plus the initial one. Fewer means the model stopped following the
            # recording; the exit code alone cannot say so.
            if green and distinct != report["steps"] + 1:
                die(
                    f"{config}: {distinct} distinct states for {report['steps']} "
                    "steps — the replay did not reach the end of the recording"
                )
        print(
            f"security-trace: GREEN commands={report['commands']} steps={report['steps']} "
            f"distinct_actions={len(report['reached'])} ambiguous={report['ambiguous']}"
        )
        limit = ratchet(AMBIGUOUS_RATCHET)
        if report["ambiguous"] > limit:
            die(f"AMBIGUOUS ratchet missed: {report['ambiguous']} > {limit}")
        print("security-trace: reached: " + " ".join(report["reached"]))
        print("security-trace: model actions not reached: " + " ".join(report["unreached"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("traces", nargs="+", type=Path)
    parser.add_argument("--keep-data", type=Path)
    parser.add_argument("--check-data", type=Path)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    if args.keep_data is not None and args.check_data is not None:
        die("--keep-data and --check-data are mutually exclusive")
    validate(args.traces, args.keep_data, args.check_data, args.mutations)


if __name__ == "__main__":
    main()
