# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH records and OTP slot fixtures checked against host cryptography."""
import hashlib
import hmac

from . import codec

OATH_HASHES = ((1, "sha1", b"12345678901234567890"),
               (2, "sha256", b"12345678901234567890123456789012"),
               (3, "sha512", b"1234567890123456789012345678901234567890123456789012345678901234"))


def otp_value(secret, challenge, algorithm, digits):
    digest = hmac.digest(secret, challenge, algorithm)
    offset = digest[-1] & 15
    return (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)


def oath_request(session, ins, data=b"", p1=0, p2=0):
    reply = session.apdu(codec.apdu(ins, p1, p2, data), f"oath.{ins:02x}")
    result = reply.data[:-2]
    pages = 0
    while reply.status >> 8 == 0x61:
        pages += 1
        if pages > 256:
            raise ValueError("OATH response continuation exceeds the page limit")
        reply = session.apdu(codec.apdu(0xA5), "oath.send-remaining")
        result += reply.data[:-2]
    session.card_value(reply)
    return result


def oath_open(session):
    selected = dict(codec.parse_tlv(session.select("oath")))
    if 0x74 in selected:
        session.require(session.options.oath_password is not None, "locked OATH requires --oath-password-env")
        key = hashlib.pbkdf2_hmac("sha1", session.options.oath_password.encode(), selected[0x71], 1000, 16)
        challenge = session.fixture("oath.access.challenge", 8)
        body = oath_request(session, 0xA3, codec.tlv(0x75, hmac.digest(key, selected[0x74], "sha1")) + codec.tlv(0x74, challenge))
        session.check("OATH mutual authentication", dict(codec.parse_tlv(body))[0x75], hmac.digest(key, challenge, "sha1"))


def oath_names(session):
    return {value[1:] for tag, value in codec.parse_tlv(oath_request(session, 0xA1)) if tag == 0x72}


def oath(session):
    namespace = b"oracle-" + session.fixture("oath.namespace", 5).hex().encode()
    for algorithm, label, secret in OATH_HASHES:
        for digits in (6, 7, 8):
            name = namespace + f"-{label}-{digits}".encode()
            with session.case(f"oath.fixture.totp.{label}.{digits}", ("A02", "A03", "A04", "A06", "A07", "A08", "A09"), effects=("create_oath_record",)):
                oath_open(session)
                session.require(name not in oath_names(session), "fixture name already exists; refusing to replace it")
                created = False
                try:
                    oath_request(session, 1, codec.tlv(0x71, name) + codec.tlv(0x73, bytes([0x20 | algorithm, digits]) + secret))
                    created = True
                    session.state("oath." + name.decode(), "created")
                    session.check("created name is listed", name in oath_names(session))
                    for counter in (0, 1, 1, 2, 0xFFFFFFFF):
                        challenge = counter.to_bytes(8, "big")
                        body = oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge), p2=1)
                        entries = codec.parse_tlv(body)
                        session.check("truncated response shape", [(t, len(v)) for t, v in entries], [(0x76, 5)])
                        session.check("digits", entries[0][1][0], digits)
                        got = int.from_bytes(entries[0][1][1:], "big")
                        session.check("TOTP value", got, otp_value(secret, challenge, label, digits))
                        session.observe(f"counter.{counter}", got)
                    challenge = (1).to_bytes(8, "big")
                    full = codec.parse_tlv(oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge)))
                    session.check("full response", full, [(0x75, bytes([digits]) + hmac.digest(secret, challenge, label))])
                    all_values = codec.parse_tlv(oath_request(session, 0xA4, codec.tlv(0x74, challenge), p2=1))
                    matched = [all_values[i + 1] for i in range(len(all_values) - 1) if all_values[i] == (0x71, name)]
                    session.check("CALCULATE ALL fixture result", matched, [(0x76, bytes([digits]) + otp_value(secret, challenge, label, digits).to_bytes(4, "big"))])
                    renamed = name + b"-r"
                    session.require(renamed not in oath_names(session), "rename destination already exists")
                    oath_request(session, 5, codec.tlv(0x71, name) + codec.tlv(0x71, renamed))
                    session.state("oath." + name.decode(), "renamed_to:" + renamed.decode())
                    name = renamed
                    session.check("renamed record is listed", name in oath_names(session))
                finally:
                    if created and not session.broken:
                        session.trace.phase = "cleanup"
                        oath_request(session, 2, codec.tlv(0x71, name))
                        session.state("oath." + name.decode(), "deleted")
                        session.check("record deleted", name not in oath_names(session))
    with session.case("oath.fixture.hotp", ("A02", "A05", "A09"), effects=("create_oath_record",)):
        oath_open(session)
        name = namespace + b"-hotp"
        session.require(name not in oath_names(session), "fixture name already exists")
        created = False
        try:
            oath_request(session, 1, codec.tlv(0x71, name) + codec.tlv(0x73, b"\x11\x06" + OATH_HASHES[0][2]))
            created = True
            session.state("oath." + name.decode(), "created")
            for counter in range(3):
                body = oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, bytes(8)), p2=1)
                response = dict(codec.parse_tlv(body))[0x76]
                session.check("HOTP counter", int.from_bytes(response[1:], "big"), otp_value(OATH_HASHES[0][2], counter.to_bytes(8, "big"), "sha1", 6))
                session.state("oath." + name.decode() + ".counter", counter + 1)
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                oath_request(session, 2, codec.tlv(0x71, name))
                session.state("oath." + name.decode(), "deleted")


def crc16(data):
    value = 0xFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value


def slot_config(key, *, access=bytes(6), yubico=False, variable=True):
    result = bytearray(52)
    result[16:22] = bytes(6) if yubico else key[16:20] + bytes(2)
    result[22:38] = key[:16]
    result[38:44] = access
    result[46:48] = bytes([0x40, 0x20 if yubico else 0x22 | (4 if variable else 0)])
    result[50:52] = (~crc16(result[:50]) & 0xFFFF).to_bytes(2, "little")
    return bytes(result)


def slot_select(session):
    if session.otp_hid:
        reply = session.otp_call(-1)
        session.check("OTP HID status available", reply.protocol, "success")
        return reply.data
    return session.select("otp")


def slot_request(session, command, data=b"", expected_len=0):
    if session.otp_hid:
        reply = session.otp_call(command, data, expected_len)
        session.check("OTP HID command success", reply.protocol, "success")
        return reply.data
    return session.card_value(session.apdu(codec.apdu(1, command, data=data), f"otp.{command:02x}"))


def otp(session):
    slot = session.options.otp_slot
    write_command = {1: 1, 2: 3}[slot]
    challenge_command = {1: 0x30, 2: 0x38}[slot]
    key, access = session.fixture("otp.hmac", 20), session.fixture("otp.access", 6)
    with session.case(f"otp.fixture.slot{slot}.hmac", ("Y02", "Y04", "Y06", "Y07"), effects=(f"replace_otp_slot_{slot}",)):
        slot_select(session)
        created = False
        try:
            config = slot_config(key, access=access)
            slot_request(session, write_command, config + bytes(6))
            created = True
            session.state(f"otp.slot{slot}", "fixture_hmac_variable")
            for length in (1, 31, 63, 64):
                if length == 64:
                    slot_request(session, write_command, slot_config(key, access=access, variable=False) + access)
                    session.state(f"otp.slot{slot}", "fixture_hmac_fixed")
                challenge = session.fixture(f"otp.challenge.{length}", length)
                padding = bytes([challenge[-1] ^ 0xFF]) * (64 - length)
                got = slot_request(session, challenge_command, challenge + padding, 20)
                session.check("HMAC-SHA1 result", got, hmac.digest(key, challenge, "sha1"))
                session.observe(f"hmac.{length}", got)
            refused = session.otp_call(write_command, bytes(58)) if session.otp_hid else session.apdu(codec.apdu(1, write_command, data=bytes(58)), "otp.delete-wrong-access")
            session.observe("wrong_access.status", refused.status)
            session.check("wrong access code refused", refused.protocol != "success")
            challenge = session.fixture("otp.after-refusal", 64)
            session.check("key survives rejected write", slot_request(session, challenge_command, challenge, 20), hmac.digest(key, challenge, "sha1"))
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                slot_request(session, write_command, bytes(52) + access)
                session.state(f"otp.slot{slot}", "empty")
    with session.case(f"otp.fixture.slot{slot}.yubico", ("Y02", "Y04", "Y08"), effects=(f"replace_otp_slot_{slot}",)):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        slot_select(session)
        key = session.fixture("otp.aes", 16)
        created = False
        try:
            slot_request(session, write_command, slot_config(key, yubico=True) + bytes(6))
            created = True
            session.state(f"otp.slot{slot}", "fixture_yubico_aes")
            challenge = session.fixture("otp.aes.challenge", 6)
            command = {1: 0x20, 2: 0x28}[slot]
            result = slot_request(session, command, challenge, 16)
            decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            plain = decryptor.update(result) + decryptor.finalize()
            session.check("AES response length", len(plain), 16)
            session.check("decrypted challenge", plain[:6], challenge)
            session.observe("device_suffix", plain[6:], "presence")
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                slot_request(session, write_command, bytes(58))
                session.state(f"otp.slot{slot}", "empty")
