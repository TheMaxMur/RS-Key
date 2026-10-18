# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read-only grants, local UV, biometric command profiles and reset witnesses."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import codec
from .fido import cm, info, pin_protocol, pin_token, token_mac, u2f_registration, u2f_apdu
from .fido_fixtures import credential, provision_after_reset
from .lifecycle import Action, change


def decrypt_member(token, label, value):
    if len(value) != 32:
        raise ValueError("encrypted getInfo member must contain IV and one AES block")
    key = HKDF(hashes.SHA256(), 16, bytes(32), label).derive(token)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(value[:16])).decryptor()
    return decryptor.update(value[16:]) + decryptor.finalize()


def readonly(session):
    for version in (1, 2):
        with session.case(f"fido.persistent-read-only.protocol-{version}", ("F10", "FE14", "F14", "F17", "F18", "G10", "G14"), effects=("create_fido_credential",), touch=True):
            session.require(info(session).get(4, {}).get("perCredMgmtRO"), "persistent read-only management not advertised", "unknown")
            version, token = pin_token(session, 64, version=version)
            session.ctap_value(cm(session, version, token, 1))
            first = session.ctap_value(session.ctap(4))
            second = session.ctap_value(session.ctap(4))
            for member, label in ((25, b"encIdentifier"), (30, b"encCredStoreState")):
                session.check("encrypted getInfo member present", member in first and member in second)
                session.check("getInfo member uses fresh ciphertext", first[member] != second[member])
                session.check("decrypted getInfo member stable", decrypt_member(token, label, first[member]), decrypt_member(token, label, second[member]))
            initial_state = decrypt_member(token, b"encCredStoreState", first[30])
            initial_id = decrypt_member(token, b"encIdentifier", first[25])
            with credential(session, session.current.name, resident=True) as fixture:
                created = session.ctap_value(session.ctap(4))
                session.check("credential creation changes store state", decrypt_member(token, b"encCredStoreState", created[30]) != initial_state)
                session.check("credential creation preserves device identifier", decrypt_member(token, b"encIdentifier", created[25]), initial_id)
                for subcommand, parameters in ((6, {2: fixture.descriptor}),
                                               (7, {2: fixture.descriptor, 3: {"id": session.fixture(session.current.name + ".user", 16), "name": "readonly-write"}})):
                    result = cm(session, version, token, subcommand, parameters)
                    session.check("persistent read-only token cannot mutate existing credential", result.protocol, "applet_error")
                    fixture.assertion(session)
                    session.ctap_value(cm(session, version, token, 1))
            after = session.ctap_value(session.ctap(4))
            session.check("credential deletion changes store state", decrypt_member(token, b"encCredStoreState", after[30]) != decrypt_member(token, b"encCredStoreState", created[30]))
            _, renewed = pin_token(session, 64, version=version)
            session.check("read-only token persists across issuance", renewed, token)


def local_uv(session):
    for version in (1, 2):
        with session.case(f"fido.builtin-UV.token.protocol-{version}", ("F07", "F08", "F06", "FE08"), touch=True):
            session.require(info(session).get(4, {}).get("uv"), "configured built-in UV not advertised", "unknown")
            protocol = pin_protocol(session, version)
            before = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
            value = session.ctap_value(session.ctap(6, {1: version, 2: 6, 3: protocol.cose, 9: 2, 10: "uv.oracle.invalid"}))
            token = protocol.decrypt(value[2])
            session.check("built-in UV token width", len(token) in (16, 32))
            after = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
            session.observe("UV retries before and after", (before, after))
            for permission in (0, 128, 255):
                result = session.ctap(6, {1: version, 2: 6, 3: protocol.cose, 9: permission, 10: "uv.oracle.invalid"})
                session.check("invalid local-UV permission refused", result.protocol, "applet_error")


def preview(session):
    for command, option, subcommand in ((0x41, "credentialMgmtPreview", 1), (0x40, "userVerificationMgmtPreview", 7)):
        with session.case(f"fido.preview.{command:02x}.{option}", ("F25", "F14" if command == 0x41 else "F24")):
            session.require(session.profile == "yubikey", "preview byte meanings require confirmed Yubico catalog", "excluded_by_profile")
            session.require(option in info(session).get(4, {}), "preview command not advertised", "unknown")
            if command == 0x41:
                version, token = pin_token(session, 4)
                fields = {1: subcommand, 3: version, 4: token_mac(version, token, bytes([subcommand]))}
            else:
                fields = {1: 1, 2: subcommand}
            value = session.ctap_value(session.ctap(command, fields))
            session.observe("profiled_preview_response", value)


def bio(session):
    with session.case("fido.biometric.enroll-rename-remove", ("F24", "F07", "G09", "G14"), effects=("biometric_enrollment",), touch=True):
        session.require(session.profile != "trezor", "biometric mutation excluded on wallet device", "excluded_by_profile")
        options = info(session).get(4, {})
        session.require("bioEnroll" in options, "standard biometric enrollment not advertised", "unknown")
        version, token = pin_token(session, 8)
        def call(subcommand, parameters=None, authenticated=True):
            fields = {1: 1, 2: subcommand}
            if parameters is not None:
                fields[3] = parameters
            if authenticated:
                fields.update({4: version, 5: token_mac(version, token, bytes([1, subcommand]) + (codec.encode(parameters) if parameters is not None else b""))})
            return session.ctap(9, fields)
        sensor = session.ctap_value(call(7, authenticated=False))
        session.observe("sensor_info", sensor)
        template = None
        try:
            begin = session.ctap_value(call(1, {3: int(session.options.timeout * 1000)}))
            template = begin[4]
            remaining = begin[6]
            session.check("biometric capture bound", isinstance(remaining, int) and 0 <= remaining <= 64)
            for _ in range(64):
                if not remaining:
                    break
                value = session.ctap_value(call(2, {1: template, 3: int(session.options.timeout * 1000)}))
                remaining = value[6]
                session.observe("capture_feedback", value.get(5))
            session.check("enrollment completed within bound", remaining, 0)
            session.ctap_value(call(5, {1: template, 2: "Oracle fixture"}))
            enrolled = session.ctap_value(call(4))
            session.check("renamed template enumerated", any(row.get(1) == template and row.get(2) == "Oracle fixture" for row in enrolled[7]))
        finally:
            if template is not None and not session.broken:
                session.trace.phase = "cleanup"
                session.ctap_value(call(6, {1: template}))
                result = call(6, {1: template})
                session.check("deleted biometric template cannot be removed twice", result.protocol, "applet_error")


def reset(session):
    with session.case("fido.reset.window-and-credential-revocation", ("F23", "F09", "U06", "FE14", "X06", "X11"), effects=("applet_reset", "pin_change", "reboot", "create_fido_credential", "create_u2f_credential"), touch=True):
        session.require(session.profile != "trezor", "reset lifecycle excluded on wallet device", "excluded_by_profile")
        session.require(session.card is not None and hasattr(session.card, "control"), "reset-window scenario needs an explicit power-cycle backend")
        from .reset_witness import snapshot, preserved
        neighbors = snapshot(session, "fido")
        readonly = pin_token(session, 64) if info(session).get(4, {}).get("perCredMgmtRO") and session.options.pin else None
        old_u2f = None
        if not info(session).get(4, {}).get("alwaysUv"):
            version = session.hid_call(3, u2f_apdu(3), "u2f.before-FIDO-reset.version")
            if version.status == 0x9000:
                old_u2f = u2f_registration(session, session.current.name)
                data = old_u2f["challenge"] + old_u2f["application"] + bytes([len(old_u2f["handle"])]) + old_u2f["handle"]
                session.check("pre-reset U2F fixture is recognized", session.hid_call(3, u2f_apdu(2, 7, data)).status, 0x6985)
        with credential(session, session.current.name) as fixture:
            fixture.assertion(session)
            change(session, Action.POWER_CYCLE)
            if readonly is not None:
                session.ctap_value(cm(session, *readonly, 1))
            session.ctap_value(session.ctap(7))
            session.options.pin = None
            session.values.pop("fido.info", None)
            current = session.ctap_value(session.ctap(4))
            session.bind("fido.info", current)
            session.check("reset clears configured host PIN", current.get(4, {}).get("clientPin"), False)
            result = session.ctap(2, fixture.query(session, options={"up": False}, authenticate=False))
            session.check("credential from before reset is unusable", result.status, 0x2E)
            if old_u2f is not None:
                old = old_u2f
                payload = old["challenge"] + old["application"] + bytes([len(old["handle"])]) + old["handle"]
                session.check("U2F handle from before reset is unusable", session.hid_call(3, u2f_apdu(2, 7, payload)).status, 0x6A80)
            if readonly is not None:
                session.check("reset invalidates the persistent RO grant", cm(session, *readonly, 1).status, 0x33)
            provision_after_reset(session, current)
            if readonly is not None:
                session.check("reprovisioning the original PIN cannot resurrect the old RO grant", cm(session, *readonly, 1).status, 0x33)
            preserved(session, "fido", neighbors)
            session.observe("cleanup_limit", "factory FIDO store retained; supplied fixture PIN reprovisioned when available")


def run(session):
    readonly(session)
    local_uv(session)
    preview(session)


def reconnect(session):
    for action in (Action.USB_RECONNECT, Action.POWER_CYCLE):
        with session.case("fido.persistent-read-only." + action.value, ("F10", "FE14", "X11", "G14"),
                          effects=("reboot",) if action == Action.POWER_CYCLE else ()):
            session.require(session.profile == "rsk", "multi-interface reconnect witness requires RS-Key identity binding", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "control"), "explicit USB rebind backend required", "excluded_by_mode")
            session.require(info(session).get(4, {}).get("perCredMgmtRO"), "persistent read-only management not advertised", "unknown")
            version, token = pin_token(session, 64)
            before = session.ctap_value(cm(session, version, token, 1))
            initial = session.ctap_value(session.ctap(4))
            change(session, action)
            after = session.ctap_value(session.ctap(4))
            session.bind("fido.info", after)
            session.check("persistent read-only grant survives connection action", session.ctap_value(cm(session, version, token, 1)), before)
            if 25 in initial and 25 in after:
                session.check("persistent identifier survives connection action", decrypt_member(token, b"encIdentifier", initial[25]), decrypt_member(token, b"encIdentifier", after[25]))
            _, renewed = pin_token(session, 64, version=version)
            session.check("persistent read-only token unchanged after connection action", renewed, token)


def mutations(session):
    bio(session)
    reset(session)
