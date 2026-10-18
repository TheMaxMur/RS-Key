# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The separate display PIN gates vendor operations even without a clientPIN."""
from itertools import product
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .audit_access import verify_checkpoint, window
from .fido import info
from .fido_fixtures import credential
from .runner import CtapRoute
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import identity_fixture
from .vendor_matrix import vacant

SUBCOMMANDS = (2, 3, 4, 7, 8, 9, 10, 12, 14)
FAILURES = {"decline-pad": 0x27, "cancel-pad": 0x2d, "timeout-pad": 0x2f, "wrong-device-PIN-once": 0x31}


def cue(session, mode):
    session.trace.emit("interaction", action="vendor-device-PIN-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: accept explicitly named operation prompts; on the DEVICE PIN pad: " + mode + "; then accept subsequent confirmation only if requested", file=sys.stderr)


def ready(session, route):
    session.require(session.profile == "rsk", "separate device PIN is RS-Key-specific", "excluded_by_profile")
    session.require(session.options.device_pin_state == "set", "this fixture needs --device-pin-state set; clientPin/uv do not reveal it")
    session.require(session.options.operator, "vendor device-PIN paths need a controlled operator action")
    session.require("display" in session.options.features or "headless" in session.options.features, "declare the build's actual PIN-entry availability")
    if route == CtapRoute.CARD:
        session.require(session.card is not None, "no selected card route", "excluded_by_mode")
        session.select("fido", required=True)
    else:
        session.require(session.hid is not None, "no selected HID route", "excluded_by_mode")
    session.require(info(session).get(4, {}).get("clientPin") is False, "separate device-PIN gate is reached only without a configured host PIN")
    session.require(not info(session).get(4, {}).get("alwaysUv"), "retained no-host-PIN credential controls require the ordinary UV policy")


def run(session):
    for route, sub, mode in product(CtapRoute, SUBCOMMANDS, ("correct-device-PIN", *FAILURES)):
        if sub == 4 and mode == "correct-device-PIN":
            continue
        with session.case(f"rsk.vendor.device-PIN.{route.value}.sub-{sub}.{mode}",
                ("V01", "V02", "V03", "V04", "V06", "V07", "V08", "V09", "G10", "G11", "G13", "G14"),
                effects=("pin_attempts", "seed_change", "replace_identity", "config_change", "create_fido_credential"), touch=True,
                parameters={"separate_device_PIN": True, "operator_action": mode, "clientPIN_retry_record_is_a_different_reference": True}):
            with session.route(route):
                ready(session, route)
                session.require(sub != 12 or "strict-config" in session.options.features, "default CONFIG_WRITE does not ask for a PIN", "excluded_by_profile")
                session.require(mode != "timeout-pad" or session.options.timeout > 130, "device PIN timeout needs the full entry window")
                state = session.ctap_value(vendor(session, 5))
                identity = session.ctap_value(vendor(session, 11))
                session.require(not state.get(3), "local-PIN seed fixture must not replace a preexisting lock")
                session.require(sub != 2 or not state[1] and "fips-profile" not in session.options.features, "sealed or FIPS export refuses before the local PIN", "excluded_by_profile")
                session.require(sub not in (9, 10) or not identity[1], "local PIN fixture must not clear or replace a preexisting organization identity")
                host_retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3]
                before = None
                with credential(session, session.current.name) as retained:
                    params = None
                    if sub in (2, 3, 9, 10):
                        vacant(session)
                        key, aad = handshake(session)
                        nonce = session.fixture("vendor.local-PIN.invalid-AEAD.nonce", 12)
                        blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, bytes(32), aad)
                        blob = blob[:-1] + bytes([blob[-1] ^ 1])
                        params = {1: blob} if sub in (3, 9) else None
                        if sub == 9:
                            params[2] = identity_fixture(session)[1]
                    elif sub == 8:
                        if "headless" not in session.options.features:
                            cue(session, "correct-device-PIN")
                            before = window(session, None)
                        params = {1: b"local-PIN"}
                    elif sub == 12:
                        block = session.ctap_value(vendor(session, 13, {1: 2}))[1]
                        session.require(len(block) == 17, "strict local PIN control needs an existing LED record")
                        params = {1: 2, 2: block}
                    elif sub == 14:
                        params = {1: int(session.ctap_value(vendor(session, 14, {1: 2}))[1])}
                    with session.attempts("fido.pin", 2):
                        try:
                            cue(session, mode)
                            result = vendor(session, sub, params)
                            expected = (0x36 if "headless" in session.options.features else FAILURES[mode] if mode in FAILURES else
                                0x3d if sub == 3 else 2 if sub == 9 else 0)
                            if sub == 8 and mode == "correct-device-PIN" and result.status == 0x30:
                                session.require(False, "checkpoint signing root is not provisioned", "unsupported_confirmed")
                            session.check("vendor device-PIN path has its own exact refusal/continuation result", result.status, expected)
                            if expected:
                                session.check("device-PIN refusal or later integrity refusal discloses no secret", result.data[1:], b"")
                            elif sub == 8:
                                verify_checkpoint(session, session.ctap_value(result), b"local-PIN", before)
                            elif sub == 2:
                                encrypted = session.ctap_value(result)[1]
                                session.check("correct device PIN authorizes the actual encrypted seed", len(ChaCha20Poly1305(key).decrypt(encrypted[:12], encrypted[12:], aad)), 32)
                            session.check("separate device-PIN failure cannot spend the host PIN retry record", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], host_retries)
                            session.check("local gate preserves persistent seed/seal/lock state", session.ctap_value(vendor(session, 5)), state)
                            session.check("local gate preserves the organization identity", session.ctap_value(vendor(session, 11)), identity)
                        finally:
                            if not session.broken and "headless" not in session.options.features:
                                cue(session, "correct-device-PIN")
                                window(session, None)
                    retained.assertion(session)
                    session.observe("retry_visibility", "the device-PIN retry record is not exposed over CTAP; no clientPIN count is presented as that private counter. Host Rust vendor-pad tests check its exact decrement/reset independently")
