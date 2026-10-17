# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OpenPGP recovery references, certificate cursors, AES, KDF and lifecycle."""
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import codec
from .cards import connection, sdk_supported


def request(session, ins, p1=0, p2=0, data=b"", expected=0x9000):
    reply = session.apdu(codec.apdu(ins, p1, p2, data), f"openpgp.{ins:02x}.{p1:02x}.{p2:02x}")
    session.check("OpenPGP response cause", (reply.protocol, reply.status),
                  ("success" if expected == 0x9000 else "applet_error", expected))
    return reply.data[:-2]


def fixture_session(session):
    from yubikit.openpgp import OpenPgpSession
    session.require(session.options.openpgp_admin is not None and session.options.openpgp_pin is not None,
                    "supply known OpenPGP user and admin PINs")
    pgp = OpenPgpSession(connection(session))
    pgp.verify_admin(session.options.openpgp_admin)
    return pgp


def references(session):
    with session.case("openpgp.reset-code.replace-unblock-clear", ("O04", "O05", "O02", "G10", "G14"), effects=("pin_change",)):
        pgp = fixture_session(session)
        session.require(session.options.openpgp_reset_code is not None,
                        "supply --openpgp-reset-code-env (empty means known unset) to restore reset code")
        old_pin, old_code = session.options.openpgp_pin, session.options.openpgp_reset_code
        changed = False
        try:
            for code in ("oracle-reset-code-1", "oracle-reset-code-2"):
                pgp.set_reset_code(code)
                changed = True
                pgp.reset_pin("oracle-new-user-pin", reset_code=code)
                pgp.verify_pin("oracle-new-user-pin")
                pgp.change_pin("oracle-new-user-pin", old_pin)
                pgp.verify_pin(old_pin)
                pgp.verify_admin(session.options.openpgp_admin)
            request(session, 0x20, 0xFF, 0x83)
            request(session, 0x2C, 2, 0x81, b"oracle-new-user-pin", 0x6982)
            pgp.verify_pin(old_pin)
            pgp.verify_admin(session.options.openpgp_admin)
            pgp.reset_pin("oracle-new-user-pin")
            pgp.verify_pin("oracle-new-user-pin")
            pgp.change_pin("oracle-new-user-pin", old_pin)
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                pgp.verify_admin(session.options.openpgp_admin)
                pgp.put_data(0xD3, old_code.encode())
                pgp.verify_pin(old_pin)
                session.check("reset-code presence restored", pgp.get_data(0xC4)[5] > 0, bool(old_code))


def retry_policy(session):
    for count in (1, 2, 3, 15, 255):
        with session.case(f"openpgp.retry-policy.{count}", ("O06", "O02", "G04", "G14"), effects=("pin_change",)):
            pgp = fixture_session(session)
            original = pgp.get_data(0xC4)
            session.require(len(original) == 7, "unexpected password-status format")
            session.require(original[4] == original[6] == 3 and original[5] == 0,
                            "retry-policy test requires known factory totals and no reset code")
            changed = False
            try:
                sdk_supported(session, lambda: pgp.set_pin_attempts(count, count, count))
                changed = True
                current = pgp.get_data(0xC4)
                session.check("user/admin retry policy readback", (current[4], current[6]), (count, count))
                pgp.verify_pin(session.options.openpgp_pin)
                pgp.verify_admin(session.options.openpgp_admin)
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    pgp.verify_admin(session.options.openpgp_admin)
                    pgp.set_pin_attempts(3, 3, 3)
                    pgp.verify_pin(session.options.openpgp_pin)
                    session.check("user/admin retry defaults restored", pgp.get_data(0xC4)[4::2], bytes([3, 3]))


def certificates(session):
    with session.case("openpgp.certificates.occurrence-walk", ("O16", "T13", "G09", "G14"), effects=("write_and_restore_openpgp_certificates",)):
        pgp = fixture_session(session)
        selector = bytes.fromhex("60045c027f21")
        originals = {}
        try:
            for occurrence in range(3):
                request(session, 0xA5, occurrence, 4, selector)
                originals[occurrence] = pgp.get_data(0x7F21)
                pgp.put_data(0x7F21, b"oracle-certificate-" + bytes([occurrence]))
            for occurrence in range(3):
                request(session, 0xA5, occurrence, 4, selector)
                session.check("certificate occurrence isolation", pgp.get_data(0x7F21), b"oracle-certificate-" + bytes([occurrence]))
            request(session, 0xA5, 0, 4, selector)
            for occurrence in (1, 2):
                session.check("GET NEXT advances certificate cursor", request(session, 0xCC, 0x7F, 0x21), b"oracle-certificate-" + bytes([occurrence]))
            for _ in range(2):
                request(session, 0xCC, 0x7F, 0x21, expected=0x6A80)
                session.check("past-end rejection preserves final occurrence", pgp.get_data(0x7F21), b"oracle-certificate-\x02")
            for intervening in (0x5E, 0xFFFF):
                request(session, 0xA5, 0, 4, selector)
                request(session, 0xCA, intervening >> 8, intervening & 255, expected=0x6B00 if intervening == 0xFFFF else 0x9000)
                request(session, 0xCC, 0x7F, 0x21, expected=0x6A80)
            session.select("piv")
            session.select("openpgp", required=True)
            request(session, 0xCC, 0x7F, 0x21, expected=0x6A80)
            pgp.verify_admin(session.options.openpgp_admin)
            request(session, 0xA5, 3, 4, selector, 0x6B00)
            request(session, 0xA5, 0, 4, bytes.fromhex("60045c020065"), 0x6A80)
            request(session, 0xA5, 0, 4, selector)
            session.check("cursor recovery after malformed selection", pgp.get_data(0x7F21), b"oracle-certificate-\x00")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                pgp.verify_admin(session.options.openpgp_admin)
                for occurrence, original in originals.items():
                    request(session, 0xA5, occurrence, 4, selector)
                    pgp.put_data(0x7F21, original)
                    session.check("original certificate restored", pgp.get_data(0x7F21), original)


def aes(session):
    for key_size in (16, 32):
        with session.case(f"openpgp.aes-pso.key-{key_size}", ("O15", "G03", "G10", "G14"), effects=("replace_openpgp_aes_key",), touch=True):
            pgp = fixture_session(session)
            key = session.fixture("openpgp.aes", key_size)
            pgp.put_data(0xD5, key)
            pgp.verify_pin(session.options.openpgp_pin, extended=True)
            for size in (16, 32, 256):
                plain = session.fixture("openpgp.aes.plain", size)
                encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
                expected = b"\x02" + encryptor.update(plain) + encryptor.finalize()
                encrypted = request(session, 0x2A, 0x86, 0x80, plain)
                session.check("AES-CBC known-answer encryption", encrypted, expected)
                session.check("AES-CBC known-answer decryption", request(session, 0x2A, 0x80, 0x86, encrypted), plain)
                for bad_size in (1, 15, 17, 31):
                    request(session, 0x2A, 0x86, 0x80, bytes(bad_size), 0x6700)
                    session.check("AES key survives invalid length", request(session, 0x2A, 0x86, 0x80, plain), expected)
            request(session, 0x20, 0xFF, 0x82)
            request(session, 0x2A, 0x86, 0x80, bytes(16), 0x6982)
            pgp.verify_pin(session.options.openpgp_pin, extended=True)
            session.check("AES valid control after logout refusal", len(request(session, 0x2A, 0x86, 0x80, bytes(16))), 17)
            session.observe("cleanup", "fixture AES key remains; write-only key has no export/delete protocol")


def kdf_body(session, single):
    count = 0x10000
    salts = [session.fixture("openpgp.kdf." + str(index), 8) for index in range(3)]
    def derive(pin, salt):
        data = salt + pin
        return hashlib.sha256((data * (count // len(data) + 1))[:count]).digest()
    user = derive(b"123456", salts[0])
    admin = derive(b"12345678", salts[0] if single else salts[2])
    body = codec.tlv(0x81, b"\x03") + codec.tlv(0x82, b"\x08") + codec.tlv(0x83, count.to_bytes(4, "big")) + codec.tlv(0x84, salts[0])
    if not single:
        body += codec.tlv(0x85, salts[1]) + codec.tlv(0x86, salts[2])
    return body + codec.tlv(0x87, user) + codec.tlv(0x88, admin), user, admin


def kdf(session):
    for single in (True, False):
        with session.case("openpgp.kdf." + ("single-salt" if single else "three-salt"), ("O18", "O03", "G05", "G14"), effects=("pin_change",)):
            pgp = fixture_session(session)
            keys = pgp.get_data(0xDE)
            session.require(not any(keys[i + 1] for i in range(0, len(keys) - 1, 2) if keys[i] in (1, 2, 3)),
                            "KDF replacement requires empty owner key slots")
            original = pgp.get_data(0xF9)
            session.require(original == b"\x81\x01\x00", "KDF test requires known disabled KDF")
            body, user, admin = kdf_body(session, single)
            changed = False
            try:
                pgp.put_data(0xF9, body)
                changed = True
                session.check("KDF exact readback", pgp.get_data(0xF9), body)
                request(session, 0x20, p2=0x83, data=admin)
                request(session, 0x20, p2=0x81, data=user)
                for invalid in (body[:-1], body + b"\x00", b"\x81\x01\x7f"):
                    request(session, 0xDA, 0, 0xF9, invalid, 0x6A80)
                    session.check("invalid KDF preserves verifier DO", pgp.get_data(0xF9), body)
                    request(session, 0x20, p2=0x83, data=admin)
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    request(session, 0x20, p2=0x83, data=admin)
                    pgp.put_data(0xF9, original)
                    request(session, 0x24, p2=0x81, data=b"123456" + session.options.openpgp_pin.encode())
                    request(session, 0x24, p2=0x83, data=b"12345678" + session.options.openpgp_admin.encode())
                    pgp.verify_pin(session.options.openpgp_pin)
                    pgp.verify_admin(session.options.openpgp_admin)


def lifecycle(session):
    with session.case("openpgp.terminate-activate.factory-state", ("O21", "X06", "G14"), effects=("applet_reset",), touch=True):
        from .reset_witness import snapshot, preserved
        neighbors = snapshot(session, "openpgp")
        pgp = fixture_session(session)
        pgp.put_data(0x5E, b"oracle-lifecycle-marker")
        request(session, 0xE6)
        session.observe("terminate_response", "completed")
        result = session.apdu(codec.apdu(0xCA, 0, 0x5E), "openpgp.terminated.read")
        session.check("terminated applet refuses ordinary data access", result.protocol, "applet_error")
        request(session, 0x44)
        session.options.openpgp_pin, session.options.openpgp_admin = "123456", "12345678"
        fresh = fixture_session(session)
        fresh.verify_pin(session.options.openpgp_pin)
        session.check("activation deleted marker", fresh.get_data(0x5E), b"")
        session.check("factory PIN counters", fresh.get_data(0xC4)[4:], b"\x03\x00\x03")
        again = session.apdu(codec.apdu(0x44), "openpgp.activate-again")
        session.observe("repeated_activate.status", again.status)
        fresh.verify_pin(session.options.openpgp_pin)
        preserved(session, "openpgp", neighbors)


def run(session):
    references(session)
    retry_policy(session)
    certificates(session)
    aes(session)
    kdf(session)
    lifecycle(session)
