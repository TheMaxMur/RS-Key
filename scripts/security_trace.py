#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Map raw emulator security snapshots to RSKeySecurityState trace actions."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
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
                if event.get("schema") != 1:
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


def infer(event: dict) -> list[tuple[str, str]]:
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
    elif (
        command == 0x02
        and before["token_permissions_raw"] == 3
        and after["token_permissions_raw"] == 0
    ):
        actions = presence_path("assert")
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
    for event in events:
        inferred = infer(event)
        actions.extend(inferred)
        pc = len(actions)
        boundaries.append((pc, event["post"], event["abstract_post"]))
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
    reached = {name for name, _ in actions if name != "Stutter"}
    if len(events) < 10 or len(actions) < 20 or len(reached) < 12:
        die(
            "coverage floor missed: require traces>=1, commands>=10, "
            f"steps>=20, distinct-actions>=12; got 1/{len(events)}/{len(actions)}/{len(reached)}"
        )

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
        "",
        "TraceStutter == UNCHANGED vars",
        "",
        case_operator("BoundaryRaw", raw_values),
        "",
        case_operator("BoundaryAbstract", abstract_values),
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
    }


def run_tlc(work: Path, config: str) -> int:
    jar = os.environ.get("TLA2TOOLS_JAR")
    if not jar:
        die("TLA2TOOLS_JAR unset -- run inside `nix develop`")
    java = os.environ.get("JAVA") or shutil.which("java")
    if not java:
        die("java not found")
    result = subprocess.run(
        [java, "-XX:+UseParallelGC", "-Xmx2g", "-cp", jar, "tlc2.TLC",
         "-deadlock", "-nowarning", "-workers", "2", "-config", config,
         "TraceSecurity"],
        cwd=work,
        check=False,
    )
    return result.returncode


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
            rc = run_tlc(work, config)
            expected = 0 if config in {"TraceSecurity.cfg", "TraceSecurityBadAlphaNoR4b.cfg"} else 12
            if rc != expected:
                die(f"{config}: TLC exit {rc}, expected {expected}")
        print(
            f"security-trace: GREEN commands={report['commands']} steps={report['steps']} "
            f"distinct_actions={len(report['reached'])}"
        )
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
