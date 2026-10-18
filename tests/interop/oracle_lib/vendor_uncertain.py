# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Recover unknown vendor mutations from seed, lock, identity and config readback."""
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .binding import require_pair
from .fido import pin_token, token_mac
from .fido_fixtures import credential, provision_after_reset
from .identity_chain import commitment, identity_control
from .lifecycle import Action, change, require_action
from .runner import CtapRoute
from .seed_lifetimes import known_pin
from .uncertain_writes import require_loss, lose, classify
from .vendor_cases import vendor, handshake
from .vendor_lifecycle import AUT_ENABLE, AUT_DISABLE, config, export_seed, identity_fixture, wrap
from .vendor_matrix import exportable, vacant


def prepared(session, command, sub, params=None):
    version, token = pin_token(session, 32)
    fields = {1: sub, 3: version}
    if params is not None:
        fields[2] = params
    fields[4] = token_mac(version, token, b"\xff" * 32 + bytes([command, sub]) + (codec.encode(params) if params is not None else b""))
    return fields


def run(session):
    for operation in ("LOAD", "FINALIZE", "ATT-IMPORT", "ATT-CLEAR", "AUT-ENABLE", "AUT-DISABLE", "AUDIT-CONFIG", "LED"):
        with session.case("cross.unknown-write.vendor." + operation,
                ("V01", "V02", "V03", "V04", "V05", "V06", "V07", "V09", "X03", "X10", "X11", "X12", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "seed_change", "config_change", "replace_identity", "applet_reset", "pin_change", "reboot", "read_encrypted_seed", "create_fido_credential"), touch=True):
            require_loss(session)
            require_pair(session)
            exportable(session)
            known_pin(session)
            if operation == "FINALIZE":
                require_action(session, Action.POWER_CYCLE)
            original = export_seed(session)
            private, chain = identity_fixture(session)
            identity = session.ctap_value(vendor(session, 11))
            session.require(not identity[1], "unknown identity mutation requires an initially absent organization fixture")
            replacement = ec.derive_private_key(int.from_bytes(session.fixture("unknown.seed", 24), "big") + 1, ec.SECP256R1()).private_numbers().private_value.to_bytes(32, "big")
            lock = session.fixture("unknown.soft-lock")
            old_led = session.ctap_value(vendor(session, 13, {1: 2}))[1] if operation == "LED" else None
            if operation == "LED":
                session.require(len(old_led) == 17, "unknown LED mutation requires an existing full record for exact restoration")
            old_audit = session.ctap_value(vendor(session, 14, {1: 2}))[1] if operation == "AUDIT-CONFIG" else None
            needs_seed_restore = needs_reset = False
            with credential(session, session.current.name) as retained:
                try:
                    if operation == "ATT-CLEAR":
                        session.ctap_value(vendor(session, 9, {1: wrap(session, private.private_numbers().private_value.to_bytes(32, "big")), 2: chain}, authenticated=True))
                    if operation == "AUT-DISABLE":
                        session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, lock)}))
                        session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                    session.select("fido")
                    with session.route(CtapRoute.CARD):
                        command, sub, params = 0x41, 3, None
                        if operation == "LOAD":
                            params = {1: wrap(session, replacement)}
                            needs_seed_restore = True
                        elif operation == "FINALIZE":
                            sub, needs_reset = 4, True
                        elif operation == "ATT-IMPORT":
                            sub, params = 9, {1: wrap(session, private.private_numbers().private_value.to_bytes(32, "big")), 2: chain}
                        elif operation == "ATT-CLEAR":
                            sub = 10
                            handshake(session)
                        elif operation == "AUT-ENABLE":
                            command, sub, params = 13, 255, {1: AUT_ENABLE, 2: wrap(session, lock)}
                        elif operation == "AUT-DISABLE":
                            command, sub, params = 13, 255, {1: AUT_DISABLE}
                        elif operation == "AUDIT-CONFIG":
                            sub, params = 14, {1: int(not old_audit)}
                        else:
                            value = bytearray(old_led)
                            value[3] ^= 1
                            sub, params = 12, {1: 2, 2: bytes(value)}
                        fields = prepared(session, command, sub, params)
                        lose(session, 0x10, lambda: session.ctap(command, fields))
                        session.select("fido")
                    vacant(session)
                    state = session.ctap_value(vendor(session, 5))
                    if operation == "LOAD":
                        actual = export_seed(session)
                        needs_seed_restore = actual != original
                        classify(session, "vendor loaded seed", actual, original, replacement)
                        if actual == replacement:
                            session.check("committed unknown LOAD revokes the old private reference", session.ctap(2, retained.query(session, options={"up": False})).status, 0x2e)
                            with credential(session, session.current.name + ".new") as fresh:
                                fresh.assertion(session)
                        else:
                            retained.assertion(session)
                    elif operation == "FINALIZE":
                        needs_reset = state[1]
                        classify(session, "vendor export seal", state[1], False, True)
                        if state[1]:
                            session.check("readback-confirmed seal refuses export without replay", vendor(session, 2).status, 0x30)
                        else:
                            session.check("uncommitted FINALIZE retains exact seed export", export_seed(session), original)
                        retained.assertion(session)
                    elif operation.startswith("ATT-"):
                        expected = {1: True, 2: commitment(chain)}
                        current = session.ctap_value(vendor(session, 11))
                        classify(session, "vendor batch identity", current, {1: False} if operation == "ATT-IMPORT" else expected, expected if operation == "ATT-IMPORT" else {1: False})
                        if current[1]:
                            identity_control(session, private, chain)
                        retained.assertion(session)
                    elif operation.startswith("AUT-"):
                        shape = tuple(state[i] for i in (2, 3, 4))
                        classify(session, "vendor flash/RAM lock", shape, (True, False, False) if operation == "AUT-ENABLE" else (False, True, True),
                            (False, True, False) if operation == "AUT-ENABLE" else (True, False, False))
                        if state[3] and not state[4]:
                            session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                        session.check("unknown lock operation retains the exact original seed", export_seed(session), original)
                        retained.assertion(session)
                    elif operation == "AUDIT-CONFIG":
                        classify(session, "vendor audit policy", session.ctap_value(vendor(session, 14, {1: 2}))[1], old_audit, not old_audit)
                        retained.assertion(session)
                    else:
                        classify(session, "vendor LED bytes", session.ctap_value(vendor(session, 13, {1: 2}))[1], old_led, params[2])
                        retained.assertion(session)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        if needs_reset:
                            change(session, Action.POWER_CYCLE)
                            session.ctap_value(session.ctap(7))
                            provision_after_reset(session, session.ctap_value(session.ctap(4)))
                            needs_seed_restore = True
                            session.observe("cleanup_limit", "unknown FINALIZE recovery uses an actual FIDO reset; only the supplied host PIN and original seed are restored")
                        state = session.ctap_value(vendor(session, 5))
                        if state[3]:
                            if not state[4]:
                                session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                            session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                        if needs_seed_restore:
                            session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                            session.check("unknown seed mutation cleanup restores exact original seed", export_seed(session), original)
                            session.observe("cleanup_limit", "seed is restored; credential-store tags and removed certificates cannot be rolled back")
                        if session.ctap_value(vendor(session, 11))[1]:
                            handshake(session)
                            session.ctap_value(vendor(session, 10, authenticated=True))
                        if old_led is not None:
                            session.ctap_value(vendor(session, 12, {1: 2, 2: old_led}, authenticated=True))
                            session.check("unknown LED fixture restores full original record", session.ctap_value(vendor(session, 13, {1: 2}))[1], old_led)
                        if old_audit is not None:
                            session.ctap_value(vendor(session, 14, {1: int(old_audit)}, authenticated=True))
                            session.check("unknown audit fixture restores the original opt-in", session.ctap_value(vendor(session, 14, {1: 2}))[1], old_audit)
                        retained.assertion(session)
