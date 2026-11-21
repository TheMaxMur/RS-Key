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
from oracle_lib.trace import CaptureError, Reply, Trace, atomic_json, json_value, recover
from oracle_lib.transport import EmuCard, Hid, Pcsc, TcpReports, inventory, select_hid
from oracle_lib.otp_hid import OtpFeature
from oracle_lib import oath_records, piv_lifecycle, openpgp_lifecycle, card_keys, lifecycle
from oracle_lib import vendor_lifecycle, rescue_cases
from oracle_lib import fido_extensions, fido_lifecycle, hid_sequences, keyboard
from oracle_lib import ccid_cases, cross_cases, fido_lists, preview_sign
from oracle_lib import fido_policy
from oracle_lib import otp_admin
from oracle_lib import fido_pin_cycles, vendor_properties
from oracle_lib import card_chaining
from oracle_lib import openpgp_objects
from oracle_lib import u2f_cases
from oracle_lib import binding
from oracle_lib import piv_moves
from oracle_lib import fido_lifetimes
from oracle_lib import fido_sequences
from oracle_lib import pcsc_sessions
from oracle_lib import pcsc_grants
from oracle_lib import apdu_dispatch
from oracle_lib import management_state
from oracle_lib import otp_disabled
from oracle_lib import otp_admin_matrix
from oracle_lib import config_factory
from oracle_lib import phy_records
from oracle_lib import rescue_presence
from oracle_lib import rescue_reboot
from oracle_lib import rescue_recovery
from oracle_lib import vendor_measurements
from oracle_lib import vendor_counter
from oracle_lib import config_grammar
from oracle_lib import config_vendor
from oracle_lib import audit_access
from oracle_lib import vendor_records
from oracle_lib import mse_lifetimes
from oracle_lib import vendor_local_pin
from oracle_lib import identity_chain
from oracle_lib import button_gestures
from oracle_lib import usb_identity
from oracle_lib import enterprise
from oracle_lib import rescue_matrix
from oracle_lib import fido_properties
from oracle_lib import apdu_matrix
from oracle_lib import oath_matrix
from oracle_lib import field_matrix
from oracle_lib import pin_matrix
from oracle_lib import credential_matrix
from oracle_lib import piv_matrix
from oracle_lib import vendor_matrix
from oracle_lib import management_matrix
from oracle_lib import otp_transport
from oracle_lib import registration_matrix
from oracle_lib import oath_semantics
from oracle_lib import card_pin_matrix
from oracle_lib import openpgp_matrix
from oracle_lib import u2f_semantics
from oracle_lib import blob_matrix
from oracle_lib import cross_reset
from oracle_lib import openpgp_catalog
from oracle_lib import token_matrix
from oracle_lib import piv_objects
from oracle_lib import oath_access
from oracle_lib import cbor_matrix
from oracle_lib import oath_gates
from oracle_lib import config_matrix
from oracle_lib import reset_tokens
from oracle_lib import ccid_matrix
from oracle_lib import pinpad_matrix
from oracle_lib import hid_operations
from oracle_lib import uv_matrix
from oracle_lib import info_matrix
from oracle_lib import reset_matrix
from oracle_lib import bio_matrix
from oracle_lib import piv_escrow
from oracle_lib import piv_policies
from oracle_lib import cursor_matrix
from oracle_lib import uv_block
from oracle_lib import selection_matrix
from oracle_lib import store_state
from oracle_lib import oath_pin_matrix
from oracle_lib import oath_commands
from oracle_lib import oath_rename
from oracle_lib import oath_presence
from oracle_lib import oath_challenges
from oracle_lib import oath_pages
from oracle_lib import assertion_matrix
from oracle_lib import extension_matrix
from oracle_lib import piv_references
from oracle_lib import openpgp_mse
from oracle_lib import openpgp_references
from oracle_lib import openpgp_recovery
from oracle_lib import openpgp_operations
from oracle_lib import openpgp_decipher
from oracle_lib import openpgp_kdf
from oracle_lib import openpgp_uif
from oracle_lib import openpgp_certificates
from oracle_lib import openpgp_aes
from oracle_lib import openpgp_attestation
from oracle_lib import openpgp_reset_profile
from oracle_lib import openpgp_operation_state
from oracle_lib import otp_commands
from oracle_lib import otp_swap
from oracle_lib import otp_challenges
from oracle_lib import otp_lifetime
from oracle_lib import otp_waits
from oracle_lib import keyboard_matrix
from oracle_lib import keyboard_counters
from oracle_lib import usb_ccid
from oracle_lib import usb_ccid_cases
from oracle_lib import seed_matrix
from oracle_lib import seed_lifetimes
from oracle_lib import identity_reset
from oracle_lib import cross_walks
from oracle_lib import cross_processing
from oracle_lib import uncertain_writes
from oracle_lib import numeric_matrix
from oracle_lib import vendor_uncertain
from oracle_lib import cross_quota
from oracle_lib import cross_authorization
from oracle_lib import cross_rejections
from oracle_lib import extended_lifetimes
from oracle_lib import unknown_slots
from oracle_lib import cross_presence
from oracle_lib import unknown_secrets
from oracle_lib import unknown_fido
from oracle_lib import config_lifetimes
from oracle_lib import unknown_admin
from oracle_lib import foreign_references
from oracle_lib import minimize, oath_sequences
from oracle_lib import cm_matrix
from oracle_lib import pin_commands
from oracle_lib import unknown_resets
from oracle_lib import unknown_boot

EXERCISE_SUITES = {"fido": fido.fido, "u2f": fido.u2f, "oath": otp.oath, "otp": otp.otp,
                   "piv": cards.piv, "openpgp": cards.openpgp,
                   "credential-management": fido_manage.credentials, "large-blobs": fido_manage.large_blobs,
                   "negative": negative.run, "oath-states": oath_states.run,
                   "fido-states": fido_states.run, "card-states": card_states.run,
                   "transport": transport_cases.run, "vendor": vendor_cases.run,
                   "management-states": management_cases.run, "otp-states": otp_states.run,
                   "oath-records": oath_records.run, "piv-lifecycle": piv_lifecycle.run,
                   "openpgp-lifecycle": openpgp_lifecycle.run, "card-keys": card_keys.run,
                   "connections": lifecycle.run, "vendor-lifecycle": vendor_lifecycle.run,
                   "rescue": rescue_cases.run, "fido-extensions": fido_extensions.run,
                   "fido-lifecycle": fido_lifecycle.run, "hid-sequences": hid_sequences.run,
                   "keyboard": keyboard.run, "ccid": ccid_cases.run,
                   "cross": cross_cases.run, "fido-lists": fido_lists.run,
                   "preview-sign": preview_sign.run, "fido-policy": fido_policy.run,
                   "management-enforcement": management_cases.extended, "otp-admin": otp_admin.run,
                   "fido-pin-cycles": fido_pin_cycles.run, "vendor-properties": vendor_properties.run,
                   "card-chaining": card_chaining.run, "openpgp-objects": openpgp_objects.run,
                   "fido-reset-bio": fido_lifecycle.mutations, "u2f-matrix": u2f_cases.run,
                   "piv-moves": piv_moves.run, "fido-lifetimes": fido_lifetimes.run,
                   "fido-sequences": fido_sequences.run, "pcsc-sessions": pcsc_sessions.run,
                   "enterprise-attestation": enterprise.run, "fido-reconnect": fido_lifecycle.reconnect,
                   "transport-boundaries": transport_cases.boundaries, "rescue-matrix": rescue_matrix.run,
                   "fido-properties": fido_properties.run, "fido-property-reconnect": fido_properties.reconnect,
                   "apdu-matrix": apdu_matrix.run, "oath-matrix": oath_matrix.run, "oath-reconnect": oath_matrix.reconnect,
                   "field-matrix": field_matrix.run, "pin-matrix": pin_matrix.changes,
                   "pin-setup-matrix": pin_matrix.setup, "credential-matrix": credential_matrix.run,
                   "pcsc-sharing": pcsc_sessions.sharing, "piv-matrix": piv_matrix.run,
                   "vendor-matrix": vendor_matrix.run, "management-matrix": management_matrix.run,
                   "otp-transport": otp_transport.run, "registration-matrix": registration_matrix.run,
                   "oath-semantics": oath_semantics.run, "card-pin-matrix": card_pin_matrix.run,
                   "openpgp-matrix": openpgp_matrix.run, "openpgp-terminated": openpgp_matrix.terminated,
                   "u2f-semantics": u2f_semantics.run, "blob-matrix": blob_matrix.run,
                   "cross-reset": cross_reset.run, "openpgp-catalog": openpgp_catalog.run,
                   "openpgp-catalog-reset": openpgp_catalog.reset_defaults, "token-matrix": token_matrix.run,
                   "piv-objects": piv_objects.run, "piv-pool-capacity": piv_objects.capacity,
                   "oath-access": oath_access.run, "cbor-matrix": cbor_matrix.run,
                   "oath-gates": oath_gates.run, "config-matrix": config_matrix.run,
                   "reset-tokens": reset_tokens.run, "ccid-matrix": ccid_matrix.run,
                   "pinpad-matrix": pinpad_matrix.run, "pinpad-properties": pinpad_matrix.properties,
                   "pinpad-headless": pinpad_matrix.headless, "hid-operations": hid_operations.run,
                   "uv-matrix": uv_matrix.run, "info-matrix": info_matrix.run,
                   "reset-matrix": reset_matrix.run, "bio-matrix": bio_matrix.run,
                   "piv-escrow": piv_escrow.run, "piv-policies": piv_policies.run,
                   "cursor-matrix": cursor_matrix.run, "uv-block": uv_block.run,
                   "selection-matrix": selection_matrix.run, "store-state": store_state.run,
                   "oath-pin-matrix": oath_pin_matrix.run, "oath-commands": oath_commands.run,
                   "oath-rename": oath_rename.run, "oath-presence": oath_presence.run,
                   "oath-challenges": oath_challenges.run,
                   "oath-pages": oath_pages.run,
                   "assertion-matrix": assertion_matrix.run,
                   "extension-matrix": extension_matrix.run,
                   "piv-references": piv_references.run,
                   "openpgp-mse": openpgp_mse.run,
                   "openpgp-references": openpgp_references.run,
                   "openpgp-recovery": openpgp_recovery.run,
                   "openpgp-operations": openpgp_operations.run,
                   "openpgp-decipher": openpgp_decipher.run,
                   "openpgp-kdf": openpgp_kdf.run,
                   "openpgp-uif": openpgp_uif.run,
                   "openpgp-uif-fixed": openpgp_uif.permanent,
                   "openpgp-certificates": openpgp_certificates.run,
                   "openpgp-aes": openpgp_aes.run,
                   "openpgp-attestation": openpgp_attestation.run,
                   "openpgp-reset-profile": openpgp_reset_profile.run,
                   "openpgp-operation-state": openpgp_operation_state.run,
                   "otp-commands": otp_commands.run,
                   "otp-swap": otp_swap.run,
                   "otp-challenges": otp_challenges.run,
                   "otp-lifetime": otp_lifetime.run,
                   "otp-waits": otp_waits.run,
                   "keyboard-matrix": keyboard_matrix.run,
                   "keyboard-counters": keyboard_counters.run,
                   "usb-ccid": usb_ccid_cases.run, "pcsc-grants": pcsc_grants.run, "apdu-dispatch": apdu_dispatch.run,
                   "management-state": management_state.run, "otp-disabled": otp_disabled.run,
                   "otp-admin-matrix": otp_admin_matrix.run, "config-factory": config_factory.run,
                   "phy-records": phy_records.run, "rescue-presence": rescue_presence.run, "rescue-reboot": rescue_reboot.run,
                   "rescue-recovery": rescue_recovery.run, "phy-persistence": phy_records.persistence,
                   "vendor-measurements": vendor_measurements.run, "vendor-counter": vendor_counter.run,
                   "config-grammar": config_grammar.run, "config-vendor": config_vendor.run,
                   "audit-access": audit_access.run, "vendor-records": vendor_records.run,
                   "mse-lifetimes": mse_lifetimes.run, "vendor-local-pin": vendor_local_pin.run,
                   "identity-chain": identity_chain.run, "button-gestures": button_gestures.run,
                   "usb-identity": usb_identity.run, "seed-matrix": seed_matrix.run,
                   "seed-lifetimes": seed_lifetimes.run, "identity-reset": identity_reset.run,
                   "cross-walks": cross_walks.run, "cross-processing": cross_processing.run,
                   "uncertain-writes": uncertain_writes.run, "numeric-matrix": numeric_matrix.run,
                   "vendor-uncertain": vendor_uncertain.run, "cross-quota": cross_quota.run,
                   "cross-authorization": cross_authorization.run, "cross-rejections": cross_rejections.run,
                   "extended-lifetimes": extended_lifetimes.run, "unknown-slots": unknown_slots.run,
                   "cross-presence": cross_presence.run, "unknown-secrets": unknown_secrets.run,
                   "unknown-fido": unknown_fido.run, "config-lifetimes": config_lifetimes.run,
                   "unknown-admin": unknown_admin.run, "foreign-references": foreign_references.run,
                   "cm-matrix": cm_matrix.run, "pin-command-matrix": pin_commands.run,
                   "unknown-resets": unknown_resets.run, "unknown-boot": unknown_boot.run,
                   "oath-sequences": oath_sequences.run}
FINAL_RESET_SUITES = ("seed-lifetimes", "identity-reset", "vendor-lifecycle", "piv-lifecycle", "openpgp-lifecycle", "openpgp-terminated", "openpgp-catalog-reset", "openpgp-uif-fixed", "openpgp-reset-profile", "enterprise-attestation", "fido-policy", "pin-setup-matrix", "fido-pin-cycles", "fido-reset-bio", "config-factory")
SUITES = ("rescue-recovery",) + tuple(name for name in dict.fromkeys((*READ_SUITES, *EXERCISE_SUITES)) if name not in (*FINAL_RESET_SUITES, "rescue-recovery")) + FINAL_RESET_SUITES
TREZOR_SUITES = ("fido", "u2f", "credential-management", "large-blobs", "fido-states", "negative",
                 "fido-extensions", "fido-lists", "fido-lifecycle", "preview-sign", "u2f-matrix", "fido-lifetimes", "fido-sequences")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list exact HID selectors and PC/SC reader names")
    listing.add_argument("--ccid-usb", action="store_true", help="also enumerate native CCID USB interfaces without claiming them")
    plan = commands.add_parser("plan", help="expand cases and show matrix gaps offline; opens no device")
    plan.add_argument("--profile", choices=("rsk", "yubikey", "trezor", "generic"), default="rsk")
    plan.add_argument("--suite", action="append", choices=("all", *SUITES))
    plan.add_argument("--out", type=Path, help="optional JSON catalog destination")
    plan.add_argument("--seed", default="rs-key-oracle-v1")
    plan.add_argument("--foreign-references", type=Path, help="offline signed public references to include in the potential case catalog")
    capture = commands.add_parser("capture", help="capture selected applet scenarios")
    capture.add_argument("--out", required=True, type=Path, help="new private capture directory")
    capture.add_argument("--hid", help="exact HID id, path hex, or unique serial from list")
    capture.add_argument("--otp-hid", help="exact OTP HID id from list; explicitly selects the feature-report path")
    capture.add_argument("--keyboard-hid", help="exact OTP keyboard HID id for unsolicited input reports")
    capture.add_argument("--reader", help="exact PC/SC reader name from list")
    capture.add_argument("--ccid-usb", help="exact native CCID USB selector from list --ccid-usb; OS driver must have released that interface")
    capture.add_argument("--emu-hid", help="explicit emulator report host:port; no USB fallback")
    capture.add_argument("--emu-card", help="explicit emulator card host:port; no USB fallback")
    capture.add_argument("--profile", choices=("rsk", "yubikey", "trezor", "generic"))
    capture.add_argument("--suite", action="append", choices=("all", *SUITES), help="repeat to select suites; default all")
    capture.add_argument("--script", type=Path, help="trusted Python file exporting run(session) and optional configure(session)")
    capture.add_argument("--exercise", action="store_true", help="also execute fixture-write scenarios")
    capture.add_argument("--allow-effect", action="append", choices=RESTRICTED_EFFECTS, default=[],
                         help="explicitly permit this effect in addition to --exercise; repeat as needed")
    capture.add_argument("--touch", action="store_true", help="operator is available for device confirmation")
    capture.add_argument("--operator", action="store_true", help="allow interactive prompts for physical connection actions")
    capture.add_argument("--recovery-layout", choices=rescue_recovery.LAYOUTS, help="operator-declared prepared recovery fixture; never inferred from a family name")
    capture.add_argument("--phy-defaults", type=Path, help="JSON of known per-device boot-default numeric PHY values, needed only when a tested field was absent")
    capture.add_argument("--device-pin-state", choices=("set", "unset"), help="known separate RS-Key display PIN state; getInfo clientPin/uv cannot establish its absence")
    capture.add_argument("--foreign-references", type=Path, help="offline signed public references from other test keys; never opens their devices")
    capture.add_argument("--feature", action="append", default=[], choices=("display", "headless", "strict-config", "fips-profile", "bench", "keygen-bench", "core1-stats", "preview-sign", "largeblob-ext", "pin-complexity"),
                         help="known RS-Key build feature; recorded as an operator assertion")
    capture.add_argument("--timeout", type=float, default=15)
    capture.add_argument("--samples", type=int, default=1)
    capture.add_argument("--warmups", type=int, default=0, help="additional full fixture cycles, retained in separate timing populations")
    capture.add_argument("--seed", default="rs-key-oracle-v1")
    capture.add_argument("--otp-slot", type=int, choices=(1, 2), default=2, help="fixture replaces and clears this test slot (default 2)")
    for name in ("pin", "piv-pin", "piv-puk", "openpgp-pin", "openpgp-admin", "openpgp-reset-code", "management-key", "oath-password", "oath-pin"):
        capture.add_argument("--" + name + "-env", help="environment variable containing the fixture secret")
    inspect = commands.add_parser("inspect", help="recover and summarize a capture without devices")
    inspect.add_argument("capture", type=Path)
    reduction = commands.add_parser("minimize", help="reduce a recorded semantic recipe through a trusted offline factory; no physical discovery")
    reduction.add_argument("capture", type=Path)
    reduction.add_argument("--scenario", required=True)
    reduction.add_argument("--sample", type=int, help="failed invocation to reduce when the capture contains repeated samples")
    reduction.add_argument("--factory", required=True, type=Path, help="trusted Python make_session(trace, seed) for fresh synthetic/emulator-only sessions")
    reduction.add_argument("--out", required=True, type=Path)
    reduction.add_argument("--max-trials", type=int, default=128)
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


def host_step(trace, label, operation, request=None, describe=lambda value: value):
    session = Session(trace)
    result = []
    with session.case("transport." + label, ("T01",), parameters=request or {}):
        def invoke(deadline, observe):
            value = operation()
            result.append(value)
            return Reply(b"")
        trace.exchange("host", "host_api", label, json.dumps(request or {}, sort_keys=True).encode(), 10, invoke)
        session.observe("host_api_result", describe(result[0]))
    if trace.cases[-1]["verdict"] != "pass":
        raise ValueError(trace.cases[-1]["reason"])
    return result[0]


def _capture(args, trace):
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not 1 <= args.samples <= 10000 or not 0 <= args.warmups <= 10000 - args.samples:
        raise ValueError("timeout must be finite and positive; samples plus nonnegative warmups must be 1..10000")
    if {"display", "headless"}.issubset(args.feature):
        raise ValueError("display and headless build declarations are mutually exclusive")
    phy_defaults = phy_records.defaults(json.loads(args.phy_defaults.read_text())) if args.phy_defaults else None
    foreign = foreign_references.load(args.foreign_references) if args.foreign_references else ()
    if not any((args.hid, args.reader, args.ccid_usb, args.otp_hid, args.keyboard_hid, args.emu_hid, args.emu_card)):
        raise ValueError("select --hid and/or --reader, or explicit emulator endpoints")
    if sum(bool(value) for value in (args.reader, args.ccid_usb, args.emu_card)) > 1:
        raise ValueError("select exactly one card backend: PC/SC, native CCID USB or emulator")
    if args.profile == "trezor" and args.ccid_usb:
        raise ValueError("Trezor profile excludes raw CCID USB before discovery")
    if args.profile == "trezor" and args.script:
        raise ValueError("Trezor wallet profile excludes trusted extension scripts before discovery")
    if (args.hid or args.reader or args.ccid_usb or args.otp_hid or args.keyboard_hid) and (args.emu_hid or args.emu_card):
        raise ValueError("hardware and emulator transports cannot share one capture")
    if args.script and not args.script.is_file():
        raise ValueError("scenario script does not exist")
    devices = host_step(trace, "discovery.inventory", inventory) if args.hid or args.reader or args.otp_hid or args.keyboard_hid else {"hid": [], "otp_hid": [], "readers": []}
    def choose(kind, selector, label=None):
        return host_step(trace, "discovery.selector." + (label or kind), lambda: select_hid(devices.get(kind, []), selector), {"selector": selector}) if selector else None
    descriptor = choose("hid", args.hid)
    otp_descriptor = choose("otp_hid", args.otp_hid)
    keyboard_descriptor = choose("otp_hid", args.keyboard_hid, "keyboard") if args.keyboard_hid != args.otp_hid else otp_descriptor
    ccid_descriptor = None
    if args.ccid_usb:
        native = host_step(trace, "discovery.ccid-usb.inventory", usb_ccid.inventory)
        ccid_descriptor = host_step(trace, "discovery.ccid-usb.selector", lambda: usb_ccid.select(native["interfaces"], args.ccid_usb), {"selector": args.ccid_usb})
    if args.reader:
        def selected_reader():
            if devices["readers"].count(args.reader) != 1:
                raise ValueError("reader name must match exactly one listed reader")
            return args.reader
        host_step(trace, "discovery.selector.reader", selected_reader, {"reader": args.reader})
    identity = descriptor or otp_descriptor or keyboard_descriptor or ccid_descriptor
    reader_name = (args.reader or "").lower()
    detected = identity["profile"] if identity else "trezor" if "trezor" in reader_name else "rsk" if args.emu_hid or args.emu_card or "rs-key" in reader_name or " rsk" in reader_name else "yubikey" if "yubikey" in reader_name else "generic"
    if detected == "trezor" and args.profile not in (None, "trezor"):
        raise ValueError("Trezor wallet protection cannot be overridden by another profile")
    profile = args.profile or detected
    if profile == "trezor" and args.script:
        raise ValueError("Trezor wallet profile excludes trusted extension scripts")
    if profile == "trezor" and (args.reader or args.ccid_usb or args.emu_card or args.otp_hid or args.keyboard_hid):
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
    if ccid_descriptor and identity:
        if ccid_descriptor["profile"] != identity["profile"] or ccid_descriptor.get("serial_number") and identity.get("serial_number") and ccid_descriptor["serial_number"] != identity["serial_number"]:
            raise ValueError("native CCID and other selectors identify different test devices")
    if keyboard_descriptor and identity and (keyboard_descriptor["profile"] != identity["profile"] or
            keyboard_descriptor.get("serial_number") and identity.get("serial_number") and keyboard_descriptor["serial_number"] != identity["serial_number"]):
        raise ValueError("keyboard selector identifies a different device")
    key = _secret(args, "management_key")
    options = Options(exercise=args.exercise, touch=args.touch, timeout=args.timeout, seed=args.seed,
                      pin=_secret(args, "pin"), piv_pin=_secret(args, "piv_pin"),
                      openpgp_pin=_secret(args, "openpgp_pin"), openpgp_admin=_secret(args, "openpgp_admin"),
                      management_key=bytes.fromhex(key) if key is not None else None,
                      oath_password=_secret(args, "oath_password"), otp_slot=args.otp_slot,
                      piv_puk=_secret(args, "piv_puk"), oath_pin=_secret(args, "oath_pin"),
                      openpgp_reset_code=_secret(args, "openpgp_reset_code"),
                      operator=args.operator,
                      recovery_layout=args.recovery_layout,
                      phy_defaults=phy_defaults,
                      device_pin_state=args.device_pin_state,
                      foreign_references=foreign,
                      features=tuple(args.feature),
                      allow_effects=tuple(args.allow_effect))
    versions = {}
    for package in ("hidapi", "pyscard", "pyusb", "cryptography", "fido2", "yubikey-manager"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    suites = list(SUITES) if not args.suite or "all" in args.suite else list(dict.fromkeys(args.suite))
    expanded = catalog(profile, suites, execute, args.seed, foreign_references=foreign)
    foreign_hash = hashlib.sha256(json.dumps(json_value(foreign), sort_keys=True, separators=(",", ":")).encode()).hexdigest() if foreign else None
    corpus = {"profile": profile, "seed": args.seed, "cases": expanded["cases"], "foreign_reference_inputs_sha256": foreign_hash}
    metadata = {"profile": profile, "backend": "emulator_tcp" if args.emu_hid or args.emu_card else "physical_usb",
                "device": descriptor, "otp_device": otp_descriptor, "keyboard_device": keyboard_descriptor,
                "reader": args.reader, "ccid_usb": ccid_descriptor, "emulator": {"hid": args.emu_hid, "card": args.emu_card},
                "binding_evidence": "explicit selectors; HID/card physical correlation is not cryptographically established",
                "versions": versions, "seed": args.seed, "samples": args.samples, "warmups": args.warmups, "suites": suites,
                "repetition_policy": "fresh scenario setup/cleanup each cycle; stateful counters and irreversible/persistent changes are not rewound",
                "input_corpus_sha256": hashlib.sha256(json.dumps(corpus, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "input_corpus_basis": "offline potential case IDs, revisions, parameters and seed; actual requests are recorded separately",
                "python": platform.python_version(),
                "runner_sha256": hashlib.sha256(b"".join(path.read_bytes() for path in [Path(__file__), *sorted((Path(__file__).parent / "oracle_lib").glob("*.py"))])).hexdigest(),
                "exercise": args.exercise, "operator_present": args.touch, "interactive_actions": args.operator,
                "allowed_effects": args.allow_effect,
                "declared_build_features": args.feature, "build_feature_evidence": "operator assertion; scenario outcomes are independent evidence",
                "declared_recovery_layout": args.recovery_layout,
                "declared_phy_defaults": phy_defaults,
                "declared_device_pin_state": args.device_pin_state,
                "foreign_reference_inputs_sha256": foreign_hash,
                "potential_fixture_effects": sorted({effect for row in expanded["cases"] for effect in row["effects"]}),
                "fixture_effects_basis": "case declarations, gated by exercise and allowed_effects; scenario events identify actual execution",
                "otp_fixture_slot": args.otp_slot,
                "sample_kind": "uncontrolled; no physical cold-boot claim",
                "script_sha256": hashlib.sha256(args.script.read_bytes()).hexdigest() if args.script else None}
    trace.metadata.update(metadata)
    atomic_json(trace.directory / "manifest.json", trace.metadata)
    trace.emit("metadata_updated", metadata=metadata, reason="confirmed discovery and offline scenario expansion")
    session = Session(trace, profile=profile, options=options)
    outcome = "completed"
    try:
        if descriptor or args.emu_hid:
            session.hid = host_step(trace, "open.hid", lambda: Hid(descriptor or {"profile": "rsk", "emulator": args.emu_hid}, trace.now,
                              TcpReports(args.emu_hid) if args.emu_hid else None), describe=lambda value: {"backend": value.layer})
            session.hid.initialize(trace, args.timeout)
        if args.reader:
            session.card = host_step(trace, "open.pcsc", lambda: Pcsc(args.reader, trace.now, trace.origin), {"reader": args.reader}, lambda value: {"atr": value.atr})
            trace.emit("session_opened", session_id="card", atr=session.card.atr, backend="pcsc_worker")
        if ccid_descriptor:
            session.card = host_step(trace, "open.ccid-usb", lambda: usb_ccid.UsbCard(ccid_descriptor, trace.now, operator=args.operator), describe=lambda value: {"backend": value.layer})
            session.card.initialize(trace, args.timeout)
            trace.emit("session_opened", session_id="card", atr=session.card.atr, backend="native_usb_ccid", device=ccid_descriptor)
        if otp_descriptor:
            session.otp_hid = host_step(trace, "open.otp-feature", lambda: OtpFeature(otp_descriptor, trace.now, trace.origin), describe=lambda value: {"backend": value.layer})
            trace.emit("session_opened", session_id="otp", backend="hid_feature_worker")
        if keyboard_descriptor:
            session.keyboard = host_step(trace, "open.keyboard", lambda: keyboard.Keyboard(keyboard_descriptor, trace.now), describe=lambda value: {"backend": "hid_input_reports"})
            trace.emit("session_opened", session_id="keyboard", backend="hidapi_input_reports")
        if args.emu_card:
            session.card = host_step(trace, "open.emu-card", lambda: EmuCard(args.emu_card, trace.now), {"endpoint": args.emu_card}, lambda value: {"backend": value.layer})
            session.card.initialize(trace, args.timeout)
            trace.emit("session_opened", session_id="card", atr=session.card.atr, backend="emulator_tcp")
        binding.confirm(session)
        extension = load_extension(session, args.script) if args.script else None
        for sample in range(args.warmups + args.samples):
            trace.sample = sample
            trace.sample_role = "warmup" if sample < args.warmups else "measured"
            execute(session, suites)
            if extension is not None:
                extension(session)
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


def capture(args):
    trace = Trace(args.out, {"requested_profile": args.profile, "stage": "discovery",
                            "requested_selectors": {name: getattr(args, name) for name in ("hid", "reader", "ccid_usb", "otp_hid", "keyboard_hid", "emu_hid", "emu_card")}})
    try:
        return _capture(args, trace)
    except BaseException as error:
        if not trace.closed:
            trace.emit("runner_error", error=f"{type(error).__name__}: {error}")
            trace.finish("cancelled" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "runner_error", coverage=coverage(trace.cases))
        raise


def load_extension(session, path):
    if session.profile == "trezor":
        raise ValueError("Trezor wallet profile excludes trusted extension scripts")
    module = runpy.run_path(str(path))
    if not callable(module.get("run")):
        raise ValueError("scenario script must export run(session)")
    configure = module.get("configure")
    if configure is not None and not callable(configure):
        raise ValueError("optional configure(session) must be callable")
    if configure is not None:
        configure(session)
    session.trace.emit("extension_ready", script_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        configured=configure is not None, configuration_scope="before sample execution; trusted code")
    return module["run"]


def execute(session, suites):
    for suite in suites:
        if session.profile == "trezor" and suite not in TREZOR_SUITES:
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
            devices = inventory()
            if args.ccid_usb:
                devices["ccid_usb"] = usb_ccid.inventory()
            print(json.dumps(devices, indent=2))
            return 0
        if args.command == "plan":
            suites = list(SUITES) if not args.suite or "all" in args.suite else list(dict.fromkeys(args.suite))
            foreign = foreign_references.load(args.foreign_references) if args.foreign_references else ()
            result = catalog(args.profile, suites, execute, args.seed, foreign_references=foreign)
            if args.out:
                atomic_json(args.out, result)
            print(json.dumps({"catalog": str(args.out), "cases": len(result["cases"]),
                              "matrix_completion": result["coverage"]["matrix_completion"],
                              "unresolved_requirements": result["coverage"]["unresolved_requirements"],
                              "unimplemented_families": [row["family"] for row in result["coverage"]["families"]
                                                         if row["coverage"] == "not_implemented"]} if args.out else result, indent=2))
            return 0
        if args.command == "capture":
            return capture(args)
        if args.command == "inspect":
            result = recover(args.capture)
            print(json.dumps(result, indent=2))
            return 0 if result["execution_outcome"] == "completed" and not result["unfinished_exchanges"] else 1
        if args.command == "minimize":
            result = minimize.minimize(args.capture, args.scenario, args.factory, args.out, args.max_trials, args.sample)
            print(json.dumps({"reproducer": str(args.out / "reproducer.json"), "steps": len(result["minimized_recipe"]["steps"]),
                              "trials": len(result["trials"]), "single_step_deletion_minimal": result["valid_single_step_deletion_minimal"]}, indent=2))
            return 0
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
