# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset reaches routed secrets and permanent policies, including blocked PW3."""
from itertools import product

from . import codec, pgp_keys
from .cards import fixture_key
from .lifecycle import Action, change
from .openpgp_kdf import OFF, raw_verify
from .openpgp_lifecycle import fixture_session, kdf_body
from .openpgp_mse import cue
from .openpgp_operations import sign
from .runner import AIDS

COMMANDS = ((0xca, 0, 0x5e, b""), (0xcc, 0x7f, 0x21, b""), (0x20, 0, 0x81, b"123456"),
    (0x24, 0, 0x81, b"123456654321"), (0x2c, 2, 0x81, b"654321"), (0xda, 0, 0x5e, b"marker"),
    (0xdb, 0x3f, 0xff, b""), (0x47, 0x81, 0, b"\xb6\x00"), (0x2a, 0x9e, 0x9a, bytes(32)),
    (0x2a, 0x80, 0x86, b"\x02" + bytes(16)), (0x2a, 0x86, 0x80, bytes(16)),
    (0x88, 0, 0, bytes(32)), (0x22, 0x41, 0xa4, b"\x83\x01\x03"), (0x84, 0, 0, b""),
    (0xf1, 0, 0, b""), (0xf2, 0, 0, b"\x03\x03\x03"), (0xfb, 1, 0, b""),
    (0xa5, 0, 4, bytes.fromhex("60045c027f21")), (0xe6, 0, 0, b""), (0xff, 255, 255, b"invalid"))


def activate(session):
    session.card_value(session.apdu(codec.apdu(0x44)))
    session.options.openpgp_pin, session.options.openpgp_admin, session.options.openpgp_reset_code = "123456", "12345678", ""
    for domain in (0x81, 0x83, "reset_code"):
        session.failed_auth.discard(("openpgp", domain))
    session.trace.emit("authorization_recovered", domain="OpenPGP", mechanism="observed successful ACTIVATE factory reseed")


def run(session):
    from yubikit.openpgp import KEY_REF
    for blocked, action in product((False, True), Action):
        with session.case(f"openpgp.reset.routed-profile.blocked-PW3-{blocked}.{action.value}", ("O01", "O02", "O03", "O04", "O05", "O06", "O07", "O11", "O15", "O16", "O18", "O19", "O20", "O21", "O22", "X06", "X11", "G10", "G13", "G14"),
                effects=("applet_reset", "pin_change", "pin_attempts", "config_change", "replace_openpgp_keys", "replace_openpgp_aes_key", "reboot"), touch=True):
            session.require(session.profile == "rsk", "routed reset profile requires RS-Key", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "control"), "routed reset persistence requires an explicit connection backend", "excluded_by_mode")
            from .reset_witness import snapshot, preserved
            neighbors = snapshot(session, "openpgp")
            sdk = fixture_session(session)
            session.card_value(session.apdu(codec.apdu(0xe6)))
            activate(session)
            sdk = fixture_session(session)
            body, user, kdf_admin = kdf_body(session, False)
            admin = session.options.openpgp_admin.encode()
            terminated = False
            try:
                sdk.put_data(0xf9, body)
                admin = kdf_admin
                raw_verify(session, 0x83, admin)
                private = fixture_key(session, "SECP256R1")
                pgp_keys.put_key(session, sdk, KEY_REF.SIG, private)
                sdk.put_data(0xd3, b"oracle-reset-code")
                sdk.put_data(0xd5, session.fixture("OpenPGP.reset.AES"))
                sdk.put_data(0xc4, b"\x00")
                sdk.put_data(0x5e, b"oracle-reset-public")
                raw_verify(session, 0x82, user)
                sdk.put_data(0x103, b"oracle-reset-private")
                for tag in range(0xd6, 0xda):
                    sdk.put_data(tag, b"\x02\x20")
                    for candidate, expected in ((b"", 0x6985), (b"\x00\x20", 0x6985), (b"\x01\x20", 0x6985),
                            (b"\x03\x20", 0x6985), (b"\x02", 0x6a80), (b"\x02\x20x", 0x6a80), (b"\x02\xff", 0x9000)):
                        session.check("permanent UIF cannot be cleared or lowered, even by PW3", session.apdu(codec.apdu(0xda, 0, tag, candidate)).status, expected)
                    session.check("permanent UIF retains its opaque feature byte", sdk.get_data(tag), b"\x02\xff")
                for occurrence in range(3):
                    session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
                    sdk.put_data(0x7f21, b"oracle-reset-cert-" + bytes([occurrence]))
                session.card_value(session.apdu(codec.apdu(0xf2, data=b"\x02\x02\x02")))
                raw_verify(session, 0x81, user)
                cue(session, "accept")
                sign(session, KEY_REF.SIG, private.public_key(), session.fixture("OpenPGP.reset.before-power"))
                change(session, action)
                session.select("openpgp")
                session.check("KDF, permanent UIF, reset-code budget and counter survive connection action", (sdk.get_data(0xf9), [sdk.get_data(t) for t in range(0xd6, 0xda)], sdk.get_data(0xc4), sdk.get_signature_counter()), (body, [b"\x02\xff"] * 4, bytes([0, 127, 127, 127, 2, 2, 2]), 1))
                raw_verify(session, 0x81, user)
                sign(session, KEY_REF.SIG, private.public_key(), session.fixture("OpenPGP.reset.after-power"))
                for p1, p2 in ((1, 0), (0, 1), (255, 255)):
                    session.check("TERMINATE parameters outrank PW3 and body", session.apdu(codec.apdu(0xe6, p1, p2, b"x")).status, 0x6a86)
                session.check("TERMINATE without PW3 refuses before nonempty body", session.apdu(codec.apdu(0xe6, data=b"x")).status, 0x6982)
                raw_verify(session, 0x83, admin)
                session.check("authorized TERMINATE still refuses a nonempty body", session.apdu(codec.apdu(0xe6, data=b"x")).status, 0x6700)
                if blocked:
                    with session.attempts(("openpgp", 0x83), 3):
                        for status in (0x6982, 0x6983):
                            session.check("PW3 blocking uses two explicitly budgeted comparisons", session.apdu(codec.apdu(0x20, p2=0x83, data=bytes([admin[0] ^ 1]) + admin[1:])).status, status)
                        session.check("blocked PW3 refuses its exact correct KDF output", session.apdu(codec.apdu(0x20, p2=0x83, data=admin)).status, 0x6983)
                    session.check("blocked admin persists beside the exact public subject key", sdk.get_data(0xc4)[6], 0)
                    change(session, action)
                    session.select("openpgp")
                    session.check("blocked PW3 budget survives every connection action", sdk.get_data(0xc4)[6], 0)
                    raw_verify(session, 0x81, user)
                    sign(session, KEY_REF.SIG, private.public_key(), session.fixture("OpenPGP.reset.blocked-admin-retained-key"))
                session.card_value(session.apdu(codec.apdu(0xe6)))
                terminated = True
                for ins, p1, p2, data in COMMANDS:
                    session.check("terminated marker precedes command, body and authorization", session.apdu(codec.apdu(ins, p1, p2, data, cla=0x80 if ins == 0xfb else 0)).status, 0x6285)
                change(session, action)
                session.check("terminated selection persists across connection action", session.apdu(codec.apdu(0xa4, 4, data=AIDS["openpgp"])).status, 0x6285)
                session.check("terminated ordinary read remains refused after reconnect", session.apdu(codec.apdu(0xca, 0, 0x5e)).status, 0x6285)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    if not terminated:
                        if sdk.get_data(0xc4)[6]:
                            raw_verify(session, 0x83, admin)
                        session.card_value(session.apdu(codec.apdu(0xe6)))
                    activate(session)
            if session.broken:
                session.trace.emit("fixture_cleanup_pending", applet="openpgp", reason="reset outcome unknown; no reset or activation replayed")
                continue
            sdk = fixture_session(session)
            session.check("activation restores raw PIN mode, lengths and all reference defaults", sdk.get_data(0xc4), bytes([1, 127, 127, 127, 3, 0, 3]))
            session.check("activation restores KDF off", sdk.get_data(0xf9), OFF)
            for tag in range(0xd6, 0xda):
                session.check("activation clears permanent UIF", sdk.get_data(tag), b"\x00\x20")
            for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
                session.check("activation removes each asymmetric key reference", session.apdu(codec.apdu(0x47, 0x81, data=slot.crt)).status, 0x6a88)
            for occurrence in range(3):
                session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
                session.check("activation removes every certificate occurrence", sdk.get_data(0x7f21), b"")
            sdk.verify_pin("123456", extended=True)
            session.check("activation removes private DO", sdk.get_data(0x103), b"")
            for p1, p2, data in ((0x86, 0x80, bytes(16)), (0x80, 0x86, b"\x02" + bytes(16)), (0x86, 0x80, b"")):
                session.check("factory AES is missing and load precedes block validation", session.apdu(codec.apdu(0x2a, p1, p2, data)).status, 0x6a88)
            session.check("factory reset code remains explicitly unset", session.apdu(codec.apdu(0x2c, p2=0x81, data=b"oracle-reset-code" + b"new-PW1")).status, 0x6a88)
            session.check("activation resets the signature counter", sdk.get_signature_counter(), 0)
            sdk.put_data(0x5e, b"oracle-ACTIVATE-no-op")
            for p1, p2, data in ((0, 0, b""), (255, 255, b"ignored")):
                session.card_value(session.apdu(codec.apdu(0x44, p1, p2, data)))
                session.check("ACTIVATE on active card is a no-op even with ignored parameters", sdk.get_data(0x5e), b"oracle-ACTIVATE-no-op")
            sdk.put_data(0x5e, b"")
            preserved(session, "openpgp", neighbors)
