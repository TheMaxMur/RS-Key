# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV reference recovery, management-key rotation and factory-state witnesses."""
from . import codec
from .cards import connection, sdk_supported


def wire_pin(value):
    raw = value.encode()
    if not 1 <= len(raw) <= 8:
        raise ValueError("PIV fixture references must encode to 1..8 bytes")
    return raw.ljust(8, b"\xff")


def status(session, ins, p1=0, p2=0, data=b"", expected=0x9000):
    reply = session.apdu(codec.apdu(ins, p1, p2, data), f"piv.{ins:02x}.{p1:02x}.{p2:02x}")
    session.check("PIV response cause", (reply.protocol, reply.status),
                  ("success" if expected == 0x9000 else "applet_error", expected))
    return reply.data[:-2]


def fixture_session(session):
    from yubikit.piv import PivSession
    session.require(session.options.management_key is not None and session.options.piv_pin is not None,
                    "supply known PIV management key and PIN")
    piv = PivSession(connection(session))
    piv.authenticate(session.options.management_key)
    piv.verify_pin(session.options.piv_pin)
    return piv


def unblock(session):
    with session.case("piv.puk.block-unblock", ("P03", "P04", "P05", "P17", "G10", "G14"),
                      effects=("pin_change", "pin_attempts")):
        piv = fixture_session(session)
        session.require(session.options.piv_puk is not None, "PUK recovery requires --piv-puk-env")
        pin, puk = session.options.piv_pin, session.options.piv_puk
        metadata = sdk_supported(session, piv.get_pin_metadata)
        session.require(1 <= metadata.attempts_remaining <= 16, "PIN retries outside bounded recovery budget")
        changed = False
        try:
            status(session, 0x20, 0xFF, 0x80)
            wrong = "00000000" if pin != "00000000" else "11111111"
            with session.attempts(("piv", 0x80), metadata.attempts_remaining + 1):
                for left in range(metadata.attempts_remaining - 1, -1, -1):
                    status(session, 0x20, p2=0x80, data=wire_pin(wrong), expected=0x63C0 | left)
                status(session, 0x20, p2=0x80, data=wire_pin(pin), expected=0x6983)
            status(session, 0x2C, p2=0x80, data=wire_pin(puk) + wire_pin("654321"))
            changed = True
            with session.attempts(("piv", 0x80), 1) if ("piv", 0x80) not in session.failed_auth else recovered(session, ("piv", 0x80)):
                piv.verify_pin("654321")
            session.check("unblock restores full PIN retries", piv.get_pin_metadata().attempts_remaining, metadata.total_attempts)
            piv.change_puk(puk, "87654321")
            piv.change_puk("87654321", puk)
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                piv.change_pin("654321", pin)
                piv.verify_pin(pin)


def recovered(session, domain, mechanism="PUK unblock"):
    from contextlib import nullcontext
    # Only a witnessed recovery clears the stop; SELECT cannot verify a secret.
    session.failed_auth.discard(domain)
    session.trace.emit("authorization_recovered", domain=str(domain), evidence=session.evidence(), mechanism=mechanism)
    return nullcontext()


def management_keys(session):
    from yubikit.piv import MANAGEMENT_KEY_TYPE
    for algorithm in MANAGEMENT_KEY_TYPE:
        for touch in (False, True):
            with session.case(f"piv.management-key.{algorithm.name}.touch-{int(touch)}", ("P06", "P07", "G03", "G14"),
                              effects=("config_change",), touch=touch):
                piv = fixture_session(session)
                original_type = piv.management_key_type
                key = session.fixture("piv.management." + algorithm.name, algorithm.key_len)
                replaced = False
                try:
                    sdk_supported(session, lambda: piv.set_management_key(algorithm, key, touch))
                    replaced = True
                    piv.authenticate(key)
                    session.observe("new_key_authentication", "mutual challenge-response verified by SDK")
                    from .card_states import sdk_refused
                    wrong_key = bytes([key[0] ^ 0x80]) + key[1:]
                    sdk_refused(session, lambda: piv.authenticate(wrong_key), "wrong management key", 0x6982)
                    status(session, 0xFF, 0xFF, 0xFF, bytes([algorithm]) + codec.tlv(0x9B, key), 0x6982)
                    piv.authenticate(key)
                    for length in sorted({0, 1, algorithm.key_len - 1, algorithm.key_len + 1}):
                        status(session, 0xFF, 0xFF, 0xFF, bytes([algorithm]) + codec.tlv(0x9B, bytes(length)), 0x6A80)
                        piv.authenticate(key)
                    session.select("piv")
                    status(session, 0xFF, 0xFF, 0xFF, bytes([algorithm]) + codec.tlv(0x9B, key), 0x6982)
                    piv.authenticate(key)
                    session.check("management-key metadata agrees", piv.get_management_key_metadata().key_type, algorithm)
                finally:
                    if replaced and not session.broken:
                        session.trace.phase = "cleanup"
                        piv.authenticate(key)
                        piv.set_management_key(original_type, session.options.management_key)
                        piv.authenticate(session.options.management_key)


def retries(session):
    for count in (1, 2, 3, 15, 255):
        with session.case(f"piv.retry-policy.{count}", ("P08", "P04", "G04", "G14"), effects=("pin_change",)):
            piv = fixture_session(session)
            session.require(session.options.piv_puk is not None, "restoring retry policy requires known PUK")
            pin_meta = sdk_supported(session, piv.get_pin_metadata)
            puk_meta = sdk_supported(session, piv.get_puk_metadata)
            changed = False
            try:
                sdk_supported(session, lambda: piv.set_pin_attempts(count, count))
                changed = True
                session.check("PIN retry total", piv.get_pin_metadata().total_attempts, count)
                session.check("PUK retry total", piv.get_puk_metadata().total_attempts, count)
                piv.verify_pin("123456")
                piv.change_pin("123456", session.options.piv_pin)
                piv.change_puk("12345678", session.options.piv_puk)
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    piv.authenticate(session.options.management_key)
                    piv.verify_pin(session.options.piv_pin)
                    piv.set_pin_attempts(pin_meta.total_attempts, puk_meta.total_attempts)
                    piv.change_pin("123456", session.options.piv_pin)
                    piv.change_puk("12345678", session.options.piv_puk)
                    piv.verify_pin(session.options.piv_pin)


def reset(session):
    with session.case("piv.reset.preconditions-and-factory-state", ("P16", "X06", "G14"),
                      effects=("applet_reset", "pin_attempts", "pin_change")):
        from .reset_witness import snapshot, preserved
        neighbors = snapshot(session, "piv")
        piv = fixture_session(session)
        session.require(session.options.piv_puk is not None, "reset preconditions need a known PUK")
        marker = 0x5F0077
        piv.put_object(marker, b"oracle-reset-marker")
        before = piv.get_object(marker)
        refusal = session.apdu(codec.apdu(0xFB), "piv.premature-reset")
        session.check("premature RESET refused", refusal.protocol, "applet_error")
        session.check("premature RESET preserves marker", piv.get_object(marker), before)
        for reference, secret, metadata in ((0x80, session.options.piv_pin, piv.get_pin_metadata()),
                                            (0x81, session.options.piv_puk, piv.get_puk_metadata())):
            session.require(1 <= metadata.attempts_remaining <= 16, "reset attempt budget capped at 16 per reference")
            wrong = "00000000" if secret != "00000000" else "11111111"
            with session.attempts(("piv", reference), metadata.attempts_remaining):
                for _ in range(metadata.attempts_remaining):
                    request = codec.apdu(0x20, p2=0x80, data=wire_pin(wrong)) if reference == 0x80 else codec.apdu(0x2C, p2=0x80, data=wire_pin(wrong) + wire_pin("123456"))
                    result = session.apdu(request, "piv.reset.consume-reference")
                    session.check("blocking attempt refused", result.protocol, "applet_error")
        status(session, 0xFB)
        recovered(session, ("piv", 0x80), "factory reset")
        recovered(session, ("piv", 0x81), "factory reset")
        session.options.piv_pin, session.options.piv_puk = "123456", "12345678"
        from yubikit.piv import DEFAULT_MANAGEMENT_KEY, PivSession
        session.options.management_key = DEFAULT_MANAGEMENT_KEY
        fresh = PivSession(connection(session))
        fresh.verify_pin(session.options.piv_pin)
        fresh.authenticate(session.options.management_key)
        session.check("reset PIN retry total", fresh.get_pin_metadata().total_attempts, 3)
        status(session, 0xCB, 0x3F, 0xFF, codec.tlv(0x5C, marker.to_bytes(3, "big")), 0x6A82)
        preserved(session, "piv", neighbors)


def run(session):
    unblock(session)
    management_keys(session)
    retries(session)
    reset(session)
