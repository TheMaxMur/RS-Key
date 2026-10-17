#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Capture USB applet exchanges and compare saved oracle runs."""
import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import runpy
import sys
import platform
from pathlib import Path

from oracle_lib.compare import compare
from oracle_lib.coverage import coverage
from oracle_lib.probes import READ_SUITES
from oracle_lib import cards, fido, fido_manage, otp, negative, oath_states, fido_states, card_states, transport_cases, vendor_cases, management_cases, otp_states
from oracle_lib.catalog import catalog
from oracle_lib.runner import Options, Session, RESTRICTED_EFFECTS
from oracle_lib.trace import CaptureError, Trace, atomic_json, recover
from oracle_lib.transport import EmuCard, Hid, Pcsc, TcpReports, inventory, select_hid
from oracle_lib.otp_hid import OtpFeature

EXERCISE_SUITES = {"fido": fido.fido, "u2f": fido.u2f, "oath": otp.oath, "otp": otp.otp,
                   "piv": cards.piv, "openpgp": cards.openpgp,
                   "credential-management": fido_manage.credentials, "large-blobs": fido_manage.large_blobs,
                   "negative": negative.run, "oath-states": oath_states.run,
                   "fido-states": fido_states.run, "card-states": card_states.run,
                   "transport": transport_cases.run, "vendor": vendor_cases.run,
                   "management-states": management_cases.run, "otp-states": otp_states.run}
SUITES = tuple(dict.fromkeys((*READ_SUITES, *EXERCISE_SUITES)))


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list exact HID selectors and PC/SC reader names")
    plan = commands.add_parser("plan", help="expand cases and show matrix gaps offline; opens no device")
    plan.add_argument("--profile", choices=("rsk", "yubikey", "trezor", "generic"), default="rsk")
    plan.add_argument("--suite", action="append", choices=("all", *SUITES))
    plan.add_argument("--out", type=Path, help="optional JSON catalog destination")
    capture = commands.add_parser("capture", help="capture selected applet scenarios")
    capture.add_argument("--out", required=True, type=Path, help="new private capture directory")
    capture.add_argument("--hid", help="exact HID id, path hex, or unique serial from list")
    capture.add_argument("--otp-hid", help="exact OTP HID id from list; explicitly selects the feature-report path")
    capture.add_argument("--reader", help="exact PC/SC reader name from list")
    capture.add_argument("--emu-hid", help="explicit emulator report host:port; no USB fallback")
    capture.add_argument("--emu-card", help="explicit emulator card host:port; no USB fallback")
    capture.add_argument("--profile", choices=("rsk", "yubikey", "trezor", "generic"))
    capture.add_argument("--suite", action="append", choices=("all", *SUITES), help="repeat to select suites; default all")
    capture.add_argument("--script", type=Path, help="trusted Python file exporting run(session)")
    capture.add_argument("--exercise", action="store_true", help="also execute fixture-write scenarios")
    capture.add_argument("--allow-effect", action="append", choices=RESTRICTED_EFFECTS, default=[],
                         help="explicitly permit this effect in addition to --exercise; repeat as needed")
    capture.add_argument("--touch", action="store_true", help="operator is available for device confirmation")
    capture.add_argument("--timeout", type=float, default=15)
    capture.add_argument("--samples", type=int, default=1)
    capture.add_argument("--seed", default="rs-key-oracle-v1")
    capture.add_argument("--otp-slot", type=int, choices=(1, 2), default=2, help="fixture replaces and clears this test slot (default 2)")
    for name in ("pin", "piv-pin", "openpgp-pin", "openpgp-admin", "management-key", "oath-password"):
        capture.add_argument("--" + name + "-env", help="environment variable containing the fixture secret")
    inspect = commands.add_parser("inspect", help="recover and summarize a capture without devices")
    inspect.add_argument("capture", type=Path)
    diff = commands.add_parser("compare", help="compare two captures offline")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    diff.add_argument("--rules", type=Path, help="JSON path/mode/reason comparison rules")
    diff.add_argument("--out", type=Path)
    diff.add_argument("--max-slowdown", type=float, help="fail if a matched median right/left ratio exceeds this value")
    return root


def _secret(args, name):
    variable = getattr(args, name + "_env")
    if variable is None:
        return None
    if variable not in os.environ:
        raise ValueError(f"secret environment variable is not set: {variable}")
    return os.environ[variable]


def capture(args):
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not 1 <= args.samples <= 10000:
        raise ValueError("timeout must be finite and positive; samples must be 1..10000")
    if not any((args.hid, args.reader, args.otp_hid, args.emu_hid, args.emu_card)):
        raise ValueError("select --hid and/or --reader, or explicit emulator endpoints")
    if (args.hid or args.reader or args.otp_hid) and (args.emu_hid or args.emu_card):
        raise ValueError("hardware and emulator transports cannot share one capture")
    if args.script and not args.script.is_file():
        raise ValueError("scenario script does not exist")
    devices = inventory() if args.hid or args.reader or args.otp_hid else {"hid": [], "otp_hid": [], "readers": []}
    descriptor = select_hid(devices["hid"], args.hid) if args.hid else None
    otp_descriptor = select_hid(devices.get("otp_hid", []), args.otp_hid) if args.otp_hid else None
    if args.reader and devices["readers"].count(args.reader) != 1:
        raise ValueError("reader name must match exactly one listed reader")
    identity = descriptor or otp_descriptor
    reader_name = (args.reader or "").lower()
    detected = identity["profile"] if identity else "trezor" if "trezor" in reader_name else "rsk" if args.emu_hid or args.emu_card or "rs-key" in reader_name or " rsk" in reader_name else "yubikey" if "yubikey" in reader_name else "generic"
    if detected == "trezor" and args.profile not in (None, "trezor"):
        raise ValueError("Trezor wallet protection cannot be overridden by another profile")
    profile = args.profile or detected
    if profile == "trezor" and (args.reader or args.emu_card or args.otp_hid):
        raise ValueError("Trezor profile exposes the FIDO interface only")
    if identity and args.reader:
        reader_rsk = "RS-Key" in args.reader or " RSK" in args.reader
        if (detected == "rsk" and not reader_rsk) or (detected == "yubikey" and reader_rsk):
            raise ValueError("HID descriptor and card reader identify different device families")
    if descriptor and otp_descriptor:
        if descriptor["profile"] != otp_descriptor["profile"]:
            raise ValueError("FIDO and OTP selectors identify different device families")
        if descriptor.get("serial_number") and otp_descriptor.get("serial_number") and descriptor["serial_number"] != otp_descriptor["serial_number"]:
            raise ValueError("FIDO and OTP interfaces have different serials")
    key = _secret(args, "management_key")
    options = Options(exercise=args.exercise, touch=args.touch, timeout=args.timeout, seed=args.seed,
                      pin=_secret(args, "pin"), piv_pin=_secret(args, "piv_pin"),
                      openpgp_pin=_secret(args, "openpgp_pin"), openpgp_admin=_secret(args, "openpgp_admin"),
                      management_key=bytes.fromhex(key) if key is not None else None,
                      oath_password=_secret(args, "oath_password"), otp_slot=args.otp_slot,
                      allow_effects=tuple(args.allow_effect))
    versions = {}
    for package in ("hidapi", "pyscard", "cryptography", "fido2", "yubikey-manager"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    suites = list(SUITES) if not args.suite or "all" in args.suite else list(dict.fromkeys(args.suite))
    metadata = {"profile": profile, "backend": "emulator_tcp" if args.emu_hid or args.emu_card else "physical_usb",
                "device": descriptor, "otp_device": otp_descriptor, "reader": args.reader, "emulator": {"hid": args.emu_hid, "card": args.emu_card},
                "binding_evidence": "explicit selectors; HID/card physical correlation is not cryptographically established",
                "versions": versions, "seed": args.seed, "samples": args.samples, "suites": suites,
                "python": platform.python_version(),
                "runner_sha256": hashlib.sha256(b"".join(path.read_bytes() for path in [Path(__file__), *sorted((Path(__file__).parent / "oracle_lib").glob("*.py"))])).hexdigest(),
                "exercise": args.exercise, "operator_present": args.touch,
                "allowed_effects": args.allow_effect,
                "fixture_effects": {"otp_slot_replaced_and_cleared": args.otp_slot,
                                    "piv_slot_replaced": "82", "openpgp_slots_replaced": ["SIG", "DEC", "AUT"]} if args.exercise else {},
                "sample_kind": "uncontrolled; no physical cold-boot claim",
                "script_sha256": hashlib.sha256(args.script.read_bytes()).hexdigest() if args.script else None}
    trace = Trace(args.out, metadata)
    session = Session(trace, profile=profile, options=options)
    outcome = "completed"
    try:
        if descriptor or args.emu_hid:
            session.hid = Hid(descriptor or {"profile": "rsk", "emulator": args.emu_hid}, trace.now,
                              TcpReports(args.emu_hid) if args.emu_hid else None)
            session.hid.initialize(trace, args.timeout)
        if args.reader:
            session.card = Pcsc(args.reader, trace.now, trace.origin)
            trace.emit("session_opened", session_id="card", atr=session.card.atr, backend="pcsc_worker")
        if otp_descriptor:
            session.otp_hid = OtpFeature(otp_descriptor, trace.now, trace.origin)
            trace.emit("session_opened", session_id="otp", backend="hid_feature_worker")
        if args.emu_card:
            session.card = EmuCard(args.emu_card, trace.now)
            session.card.initialize(trace, args.timeout)
            trace.emit("session_opened", session_id="card", atr=session.card.atr, backend="emulator_tcp")
        for sample in range(args.samples):
            trace.sample = sample
            execute(session, suites)
            if args.script:
                module = runpy.run_path(str(args.script))
                if not callable(module.get("run")):
                    raise ValueError("scenario script must export run(session)")
                module["run"](session)
        return_code = 1 if any(case["verdict"] == "fail" for case in trace.cases) else 0
    except (KeyboardInterrupt, SystemExit):
        outcome = "cancelled"
        return_code = 130
    except Exception as error:
        outcome = "runner_error"
        trace.emit("runner_error", error=f"{type(error).__name__}: {error}")
        print(f"oracle: {type(error).__name__}: {error}", file=sys.stderr)
        return_code = 2
    finally:
        session.close()
        trace.finish(outcome, coverage=coverage(trace.cases))
    counts = {name: sum(case["verdict"] == name for case in trace.cases) for name in ("pass", "fail", "inconclusive")}
    print(json.dumps({"capture": str(args.out), "outcome": outcome, "cases": counts,
                      "exchanges": len(trace.exchanges)}, indent=2))
    return return_code


def execute(session, suites):
    for suite in suites:
        if session.profile == "trezor" and suite not in ("fido", "u2f", "credential-management", "large-blobs", "fido-states", "negative"):
            with session.case(f"{suite}.profile-exclusion"):
                session.require(False, "wallet profile exposes FIDO/U2F only", "excluded_by_profile")
            continue
        if suite in READ_SUITES:
            READ_SUITES[suite](session)
        if suite in EXERCISE_SUITES:
            if suite == "negative" and session.profile == "trezor":
                negative.fido(session)
            else:
                EXERCISE_SUITES[suite](session)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "list":
            print(json.dumps(inventory(), indent=2))
            return 0
        if args.command == "plan":
            suites = list(SUITES) if not args.suite or "all" in args.suite else list(dict.fromkeys(args.suite))
            result = catalog(args.profile, suites, execute)
            if args.out:
                atomic_json(args.out, result)
            print(json.dumps({"catalog": str(args.out), "cases": len(result["cases"]),
                              "unimplemented_families": [row["family"] for row in result["coverage"]["families"]
                                                         if row["coverage"] == "not_implemented"]} if args.out else result, indent=2))
            return 0
        if args.command == "capture":
            return capture(args)
        if args.command == "inspect":
            result = recover(args.capture)
            print(json.dumps(result, indent=2))
            return 0 if result["execution_outcome"] == "completed" and not result["unfinished_exchanges"] else 1
        rules = json.loads(args.rules.read_text()) if args.rules else []
        result = compare(args.left, args.right, rules, args.max_slowdown)
        if args.out:
            atomic_json(args.out, result)
        print(json.dumps(result, indent=2))
        return 1 if result["unexpected"] or result["not_comparable"] else 0
    except (ValueError, OSError, CaptureError) as error:
        print(f"oracle: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
