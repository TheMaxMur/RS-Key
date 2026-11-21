# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A seal persists, a RAM unlock does not, and batch identity survives FIDO reset."""
from itertools import product

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import codec
from .fido import info, u2f_apdu
from .fido_fixtures import credential, provision_after_reset
from .identity_chain import identity_control
from .lifecycle import Action, change, require_action
from .rescue_presence import cue, require as require_consent
from .seed_matrix import AUTH, auth_status
from .seed_matrix import ORDER
from .vendor_boot import Boundary, preflight, cross, loses_ram
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import AUT_ENABLE, AUT_DISABLE, config, export_seed, identity_fixture, wrap
from .vendor_matrix import authenticated, exportable


def known_pin(session):
    session.require(info(session).get(4, {}).get("clientPin") and session.options.pin,
        "lifetime fixture needs a known configured host PIN")


def imported_seed(session):
    for boundary, hybrid in product(Boundary, (False, True)):
        with session.case(f"rsk.seed.LOAD.persistence.{boundary.value}.hybrid-{hybrid}", ("V01", "V02", "V03", "X02", "X11", "G09", "G14"),
                effects=("seed_change", "read_encrypted_seed", "reboot", "session_recovery", "create_fido_credential"), touch=True):
            exportable(session)
            known_pin(session)
            preflight(session, boundary)
            original = export_seed(session)
            replacement = (int.from_bytes(session.fixture("seed.persist.scalar"), "big") % (ORDER - 1) + 1).to_bytes(32, "big")
            changed = False
            with credential(session, session.current.name) as old:
                try:
                    session.ctap_value(vendor(session, 3, {1: wrap(session, replacement, hybrid)}, authenticated=True))
                    changed = True
                    with credential(session, session.current.name + ".new") as fresh:
                        fresh.assertion(session)
                        cross(session, boundary)
                        session.check("loaded seed persists exactly across the selected boundary", export_seed(session), replacement)
                        session.check("reconnect or reboot cannot revive the old seed's reference", session.ctap(2, old.query(session, options={"up": False})).status, 0x2e)
                        fresh.assertion(session)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                        session.check("persisted seed fixture restores the exact prior seed", export_seed(session), original)
                        old.assertion(session)
                        session.observe("cleanup_limit", "original seed restored; LOAD-created credential-store tags and dropped device certificates cannot be rolled back")


def channels(session):
    for boundary, hybrid in product(Boundary, (False, True)):
        with session.case(f"rsk.MSE.persistence.{boundary.value}.hybrid-{hybrid}", ("V01", "V02", "X02", "X03", "X11", "G10", "G11", "G14"),
                effects=("read_encrypted_seed", "reboot", "session_recovery"), touch=True):
            exportable(session)
            known_pin(session)
            preflight(session, boundary)
            session.require(session.hid is not None, "MSE CID continuity requires the selected HID interface")
            original = export_seed(session)
            key, aad = handshake(session, hybrid)
            owner = getattr(session.hid, "cid", None)
            cross(session, boundary)
            result = vendor(session, 2, authenticated=True)
            retained = not loses_ram(boundary) and owner == getattr(session.hid, "cid", None)
            if retained:
                blob = session.ctap_value(result)[1]
                session.check("unchanged owner consumes the exact pre-boundary MSE channel", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
            else:
                session.check("rebooted or newly allocated CID cannot inherit a prior channel", result.status, 0x30)
            session.check("boundary consumer always leaves the one-shot channel spent", vendor(session, 6).status, 0x30)
            session.check("fresh MSE still exports the same seed after boundary refusal", export_seed(session), original)


def availability(session, fixture, original, unlocked):
    session.ctap_value(session.ctap(4))
    session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
    session.ctap_value(session.ctap(6, {1: 2, 2: 2}))
    for sub, params in ((5, None), (11, None), (13, {1: 1}), (13, {1: 2}), (14, {1: 2}), (15, None)):
        session.ctap_value(vendor(session, sub, params))
    session.check("locked seed does not hide U2F protocol version", session.hid_call(3, u2f_apdu(3)).status, 0x9000)
    if unlocked:
        fixture.assertion(session)
        session.check("unlocked EXPORT uses exactly the RAM seed", export_seed(session), original)
    else:
        session.check("locked seed refuses a populated GA with the missing-seed cause", session.ctap(2, fixture.query(session)).status, 0x7f)
        handshake(session)
        session.check("locked EXPORT is not allowed even with valid authorization", vendor(session, 2, authenticated=True).status, 0x30)
    session.check("LOAD is refused while wrapped, even after successful RAM unlock", vendor(session, 3, {1: wrap(session, original)}, authenticated=True).status, 0x30)
    session.check("a second AUT_ENABLE cannot replace a wrapped seed", config(session, 255, {1: AUT_ENABLE, 2: wrap(session, session.fixture("lock.replacement"))}).status, 0x30)


def locks(session):
    for boundary in Boundary:
        with session.case("rsk.soft-lock.lifetime." + boundary.value, ("V01", "V02", "V03", "V05", "X02", "X03", "X11", "X12", "G09", "G10", "G11", "G14"),
                effects=("config_change", "read_encrypted_seed", "reboot", "session_recovery", "create_fido_credential"), touch=True):
            exportable(session)
            known_pin(session)
            preflight(session, boundary)
            session.require(session.hid is not None and not info(session).get(4, {}).get("alwaysUv"), "locked U2F control requires ordinary policy and FIDO HID")
            original, key = export_seed(session), session.fixture("soft-lock.boot-key")
            engaged = False
            with credential(session, session.current.name) as retained:
                try:
                    session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, key)}))
                    engaged = True
                    session.check("AUT_ENABLE removes the plain and RAM seeds", {k: session.ctap_value(vendor(session, 5))[k] for k in (2, 3, 4)}, {2: False, 3: True, 4: False})
                    availability(session, retained, original, False)
                    session.check("AUT_DISABLE needs a successful unlock", config(session, 255, {1: AUT_DISABLE}).status, 0x33)
                    wrong = key[:-1] + bytes([key[-1] ^ 1])
                    session.check("wrong lock key has exact decryption refusal", vendor(session, 6, {1: wrap(session, wrong)}).status, 2)
                    session.check("wrong key cannot publish a RAM seed", session.ctap_value(vendor(session, 5))[4], False)
                    session.ctap_value(vendor(session, 6, {1: wrap(session, key)}))
                    session.ctap_value(vendor(session, 6, {1: wrap(session, key)}))
                    availability(session, retained, original, True)
                    cross(session, boundary)
                    state = session.ctap_value(vendor(session, 5))
                    session.check("flash lock persists while RAM follows the actual boundary", (state[2], state[3], state[4]), (False, True, not loses_ram(boundary)))
                    availability(session, retained, original, not loses_ram(boundary))
                    if loses_ram(boundary):
                        session.check("locked boot still refuses AUT_DISABLE", config(session, 255, {1: AUT_DISABLE}).status, 0x33)
                        session.ctap_value(vendor(session, 6, {1: wrap(session, key)}))
                    retained.assertion(session)
                finally:
                    if engaged and not session.broken:
                        session.trace.phase = "cleanup"
                        cue(session, "accept")
                        if not session.ctap_value(vendor(session, 5))[4]:
                            session.ctap_value(vendor(session, 6, {1: wrap(session, key)}))
                        session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                        state = session.ctap_value(vendor(session, 5))
                        session.check("permanent unlock restores flash and erases the RAM copy", (state[2], state[3], state[4]), (True, False, False))
                        session.check("repeated AUT_DISABLE has its no-lock refusal", config(session, 255, {1: AUT_DISABLE}).status, 0x30)
                        session.check("lock lifecycle retained the original seed", export_seed(session), original)
                        retained.assertion(session)


def lock_gates(session):
    for identifier, defect, version in product((AUT_ENABLE, AUT_DISABLE), AUTH, (1, 2)):
        if defect == "valid":
            continue
        with session.case(f"rsk.soft-lock.CONFIG.authorization.{identifier:016x}.{defect}.protocol-{version}",
                ("V01", "V05", "F21", "G10", "G11", "G13", "G14"), effects=("config_change", "read_encrypted_seed"), touch=True):
            exportable(session)
            known_pin(session)
            original = export_seed(session)
            params = {1: identifier}
            lock, engaged = session.fixture("lock.gate.key"), False
            try:
                if identifier == AUT_DISABLE:
                    session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, lock)}))
                    engaged = True
                    session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                before = session.ctap_value(vendor(session, 5))
                key, aad = handshake(session)
                if identifier == AUT_ENABLE:
                    nonce = session.fixture("lock.gate.nonce", 12)
                    params[2] = nonce + ChaCha20Poly1305(key).encrypt(nonce, lock, aad)
                session.check("CONFIG lock authorization is checked before lock state", authenticated(session, 13, 255, params, defect, version=version).status, auth_status(defect))
                # CONFIG takes the AUT_ENABLE channel only after its outer ACFG gate passes.
                blob = session.ctap_value(vendor(session, 2, authenticated=True))[1]
                session.check("refused lock CONFIG retains the original usable channel", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
                session.check("refused lock authorization preserves seed", export_seed(session), original)
                session.check("refused lock authorization preserves exact lock state", session.ctap_value(vendor(session, 5)), before)
            finally:
                if engaged and not session.broken:
                    session.trace.phase = "cleanup"
                    session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                    session.check("authorized AUT_DISABLE control restores the seed", export_seed(session), original)


def lock_consent(session):
    for identifier, mode in product((AUT_ENABLE, AUT_DISABLE), ("decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.soft-lock.consent.{identifier:016x}.{mode}", ("V01", "V05", "G10", "G11", "G12", "G14"),
                effects=("config_change", "read_encrypted_seed", "create_fido_credential"), touch=True):
            exportable(session)
            known_pin(session)
            require_consent(session, mode)
            original, key = export_seed(session), session.fixture("lock.consent.key")
            engaged = False
            with credential(session, session.current.name) as retained:
                try:
                    if identifier == AUT_DISABLE:
                        session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, key)}))
                        engaged = True
                        session.ctap_value(vendor(session, 6, {1: wrap(session, key)}))
                    before = session.ctap_value(vendor(session, 5))
                    params = {1: identifier}
                    if identifier == AUT_ENABLE:
                        params[2] = wrap(session, key)
                    cue(session, mode)
                    result = config(session, 255, params)
                    expected = 0x2d if identifier == AUT_DISABLE and mode == "panel-cancel" else 0x27
                    session.check("lock consent refusal preserves its distinct status", result.status, expected)
                    cue(session, "accept")
                    if identifier == AUT_ENABLE:
                        session.check("declined AUT_ENABLE spends its channel", vendor(session, 6).status, 0x30)
                    session.check("declined lock transition preserves all state flags", session.ctap_value(vendor(session, 5)), before)
                    session.check("declined lock transition preserves the exact seed", export_seed(session), original)
                    retained.assertion(session)
                finally:
                    if engaged and not session.broken:
                        session.trace.phase = "cleanup"
                        cue(session, "accept")
                        session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                        session.check("lock refusal cleanup retains seed", export_seed(session), original)


def sealed(session):
    for boundary in Boundary:
        with session.case("rsk.seed.FINALIZE.lifetime." + boundary.value,
                ("V02", "V03", "V04", "V06", "F23", "X02", "X11", "G09", "G10", "G11", "G13", "G14"),
                effects=("seed_change", "replace_identity", "applet_reset", "pin_change", "reboot", "session_recovery", "read_encrypted_seed", "create_fido_credential"), touch=True):
            exportable(session)
            known_pin(session)
            preflight(session, boundary)
            require_action(session, Action.POWER_CYCLE)
            session.require(session.hid is not None and not info(session).get(4, {}).get("alwaysUv"), "batch identity signature needs U2F and HID")
            session.require(not session.ctap_value(vendor(session, 11))[1], "existing batch identity is never replaced")
            original = export_seed(session)
            private, chain = identity_fixture(session)
            imported = finalized = False
            with credential(session, session.current.name) as retained:
                try:
                    session.ctap_value(vendor(session, 9, {1: wrap(session, private.private_numbers().private_value.to_bytes(32, "big")), 2: chain}, authenticated=True))
                    imported = True
                    session.ctap_value(vendor(session, 4, authenticated=True))
                    finalized = True
                    session.ctap_value(vendor(session, 4, authenticated=True))
                    for defect in AUTH:
                        handshake(session)
                        session.check("sealed EXPORT refuses before any PIN gate", authenticated(session, 0x41, 2, None, defect).status, 0x30)
                        session.check("sealed EXPORT still spends a live channel", vendor(session, 6).status, 0x30)
                    session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                    session.check("LOAD remains allowed without reopening the sealed window", session.ctap_value(vendor(session, 5))[1], True)
                    retained.assertion(session)
                    identity_control(session, private, chain)
                    cross(session, boundary)
                    session.check("the seal survives the selected lifetime boundary", session.ctap_value(vendor(session, 5))[1], True)
                    session.check("sealed export remains denied without MSE or auth", vendor(session, 2).status, 0x30)
                    retained.assertion(session)
                    identity_control(session, private, chain)
                finally:
                    if finalized and not session.broken:
                        session.trace.phase = "cleanup"
                        change(session, Action.POWER_CYCLE)
                        session.ctap_value(session.ctap(7))
                        provision_after_reset(session, session.ctap_value(session.ctap(4)))
                        state = session.ctap_value(vendor(session, 5))
                        session.check("authenticatorReset reopens export and removes soft lock", (state[1], state[3], state[4]), (False, False, False))
                        identity_control(session, private, chain)
                        session.check("reset revokes the old private credential before seed restoration", session.ctap(2, retained.query(session, options={"up": False})).status, 0x2e)
                        session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                        session.check("cleanup restores original seed into the reopened window", export_seed(session), original)
                        retained.assertion(session)
                        session.observe("cleanup_limit", "FIDO reset is real: resident credentials, PIN policies, device PIN and other reset-owned records stay reset; original host PIN and seed are restored")
                    if imported and not session.broken:
                        handshake(session)
                        session.ctap_value(vendor(session, 10, authenticated=True))
                        session.check("owned batch identity removed after all lifetime controls", session.ctap_value(vendor(session, 11))[1], False)


def sealed_lock(session):
    with session.case("rsk.seed.FINALIZE.locked-unlocked-disabled-boot-reset", ("V01", "V02", "V03", "V04", "V05", "X11", "G10", "G11", "G13", "G14"),
            effects=("seed_change", "config_change", "read_encrypted_seed", "applet_reset", "pin_change", "reboot", "create_fido_credential"), touch=True):
        exportable(session)
        known_pin(session)
        require_action(session, Action.POWER_CYCLE)
        original, lock = export_seed(session), session.fixture("sealed.lock.key")
        finalized = engaged = False
        with credential(session, session.current.name) as retained:
            try:
                session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, lock)}))
                engaged = True
                session.ctap_value(vendor(session, 4, authenticated=True))
                finalized = True
                state = session.ctap_value(vendor(session, 5))
                session.check("FINALIZE is available while the seed is locked", (state[1], state[2], state[3], state[4]), (True, False, True, False))
                session.check("sealed locked LOAD is still refused before its PIN gate", vendor(session, 3, {1: wrap(session, original)}).status, 0x30)
                session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                session.check("RAM unlock cannot reopen export", vendor(session, 2).status, 0x30)
                retained.assertion(session)
                session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                engaged = False
                session.check("permanent unlock cannot reopen export", vendor(session, 2).status, 0x30)
                change(session, Action.POWER_CYCLE)
                session.check("sealed plain seed survives a cold boot", session.ctap_value(vendor(session, 5))[1], True)
                retained.assertion(session)
            finally:
                if finalized and not session.broken:
                    session.trace.phase = "cleanup"
                    change(session, Action.POWER_CYCLE)
                    session.ctap_value(session.ctap(7))
                    engaged = False
                    provision_after_reset(session, session.ctap_value(session.ctap(4)))
                    session.check("reset removes both independent seal/soft-lock gates", tuple(session.ctap_value(vendor(session, 5))[i] for i in (1, 3, 4)), (False, False, False))
                    session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                    session.check("sealed-lock cleanup restores the exact original seed", export_seed(session), original)
                    retained.assertion(session)
                    session.observe("cleanup_limit", "FIDO reset-owned records stay reset; original host PIN and seed are restored")
                elif engaged and not session.broken:
                    session.ctap_value(vendor(session, 6, {1: wrap(session, lock)}))
                    session.ctap_value(config(session, 255, {1: AUT_DISABLE}))


def run(session):
    lock_gates(session)
    lock_consent(session)
    imported_seed(session)
    channels(session)
    locks(session)
    sealed(session)
    sealed_lock(session)
