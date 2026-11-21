# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH key grammar, touch bulk output and uncertain counter advancement."""
import hmac

from . import codec
from .lifecycle import Action, change
from .oath_matrix import records
from .oath_states import calculate
from .otp import OATH_HASHES, oath_names, oath_open, oath_request, otp_value
from .trace import Outcome, TransferError
from .vectors import pairwise


def key_fields(kind, algorithm, digits, secret, property_byte=0):
    return codec.tlv(0x73, bytes([kind | algorithm, digits]) + secret) + b"\x78" + bytes([property_byte])


def answer(session, name, challenge, secret, algorithm, digits, full=False, counter=None):
    body = oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge), p2=0 if full else 1)
    actual = codec.parse_tlv(body)
    moving = challenge if counter is None else counter.to_bytes(8, "big")
    expected = bytes([digits]) + (hmac.digest(secret, moving, algorithm) if full else otp_value(secret, moving, algorithm, digits).to_bytes(4, "big"))
    session.check("OATH response matches independent HMAC and digits", actual, [(0x75 if full else 0x76, expected)])


def combinations(session):
    dimensions = {"kind": (0x10, 0x20), "algorithm": (1, 2, 3), "digits": (6, 7, 8), "secret_length": (14, 15, 63, 64),
                  "properties": (0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 252, 255)}
    for row in pairwise(dimensions, session.options.seed + ":OATH-record"):
        label = ".".join(f"{name}-{value}" for name, value in row.items())
        with session.case("oath.PUT.combination." + label, ("A02", "A03", "A04", "A05", "A06", "A07", "G03", "G04", "G14"),
                          effects=("create_oath_record",), touch=True, parameters=row, method="seeded pairwise over declared type/hash/digits/secret/property levels"):
            session.require(session.profile == "rsk", "OATH accepted-property semantics require RS-Key", "excluded_by_profile")
            name, secret = b"oracle-OATH-combination", session.fixture("OATH.combination.secret", row["secret_length"])
            algorithm = {1: "sha1", 2: "sha256", 3: "sha512"}[row["algorithm"]]
            with records(session, [(name, key_fields(row["kind"], row["algorithm"], row["digits"], secret, row["properties"]))]):
                answer(session, name, (1).to_bytes(8, "big"), secret, algorithm, row["digits"], counter=0 if row["kind"] == 0x10 else None)
                answer(session, name, (2).to_bytes(8, "big"), secret, algorithm, row["digits"], full=True, counter=1 if row["kind"] == 0x10 else None)
                session.check("OATH PUT name is enumerable", name in oath_names(session))


def put_failures(session):
    mutations = [("secret-length-" + str(size), "secret", bytes(size)) for size in (0, 1, 13, 65)]
    mutations += [("digits-" + str(value), "digits", value) for value in (0, 1, 5, 9, 255)]
    mutations += [("algorithm-" + str(value), "algorithm", value) for value in (0, 4, 15)]
    mutations += [("type-" + str(value), "kind", value) for value in (0, 0x30, 0xF0)]
    mutations += [("IMF-width-" + str(size), "IMF", bytes(size)) for size in (0, 1, 3, 5)]
    for label, field, value in mutations:
        with session.case("oath.PUT.single-defect." + label, ("A02", "A04", "A05", "G03", "G04", "G14"), effects=("create_oath_record",)):
            session.require(session.profile == "rsk", "OATH bounds require RS-Key", "excluded_by_profile")
            name, secret = b"oracle-OATH-retained", OATH_HASHES[0][2]
            with records(session, [(name, key_fields(0x20, 1, 6, secret))]):
                settings = {"kind": 0x10 if field == "IMF" else 0x20, "algorithm": 1, "digits": 6, "secret": secret}
                if field != "IMF":
                    settings[field] = value
                body = codec.tlv(0x71, name) + key_fields(**settings)
                if field == "IMF":
                    body += codec.tlv(0x7A, value)
                session.check("single OATH PUT defect refused", session.apdu(codec.apdu(1, data=body)).status, 0x6A80)
                answer(session, name, bytes(8), secret, "sha1", 6)
                session.check("rejected replacement preserves exact record set", name in oath_names(session))


def calculate_bounds(session):
    for command in (0xA2, 0xA4):
        for size in (0, 1, 7, 8, 63, 64, 65):
            for full in (False, True):
                with session.case(f"oath.CALCULATE.bounds.{command:02x}.length-{size}.full-{full}", ("A04", "A07", "G03", "G14"), effects=("create_oath_record",)):
                    name, secret = b"oracle-challenge-bound", OATH_HASHES[0][2]
                    with records(session, [(name, key_fields(0x20, 1, 6, secret))], empty=command == 0xA4):
                        challenge = session.fixture("OATH.boundary.challenge", size)
                        data = (codec.tlv(0x71, name) if command == 0xA2 else b"") + codec.tlv(0x74, challenge)
                        response = session.apdu(codec.apdu(command, p2=0 if full else 1, data=data))
                        if size > 64:
                            session.check("OATH oversized challenge refused before processing", response.status, 0x6A80)
                        else:
                            result = session.card_value(response)
                            expected = bytes([6]) + (hmac.digest(secret, challenge, "sha1") if full else otp_value(secret, challenge, "sha1", 6).to_bytes(4, "big"))
                            session.check("OATH exact challenge bytes used by both paths", codec.parse_tlv(result), ([(0x71, name)] if command == 0xA4 else []) + [(0x75 if full else 0x76, expected)])
                        answer(session, name, bytes(8), secret, "sha1", 6)


def bulk_touch(session):
    with session.case("oath.bulk.mixed-touch-HOTP-increasing", ("A05", "A06", "A07", "A08", "G14"), effects=("create_oath_record",), touch=True):
        secret = OATH_HASHES[0][2]
        specs = [(b"oracle-touch", key_fields(0x20, 1, 6, secret, 2)), (b"oracle-HOTP", key_fields(0x10, 1, 6, secret)),
                 (b"oracle-plain", key_fields(0x20, 1, 6, secret)), (b"oracle-increasing", key_fields(0x20, 1, 6, secret, 1))]
        with records(session, specs, empty=True):
            challenge = (1).to_bytes(8, "big")
            body = codec.parse_tlv(oath_request(session, 0xA4, codec.tlv(0x74, challenge), p2=1))
            groups = {body[index][1]: body[index + 1] for index in range(0, len(body), 2)}
            session.check("bulk touch record is marked without consuming presence", groups[b"oracle-touch"], (0x7C, b"\x06"))
            session.check("bulk HOTP is not evaluated", groups[b"oracle-HOTP"], (0x77, b"\x06"))
            expected = b"\x06" + otp_value(secret, challenge, "sha1", 6).to_bytes(4, "big")
            for name in (b"oracle-plain", b"oracle-increasing"):
                session.check("bulk TOTP known answer", groups[name], (0x76, expected))
            answer(session, b"oracle-HOTP", challenge, secret, "sha1", 6, counter=0)
            answer(session, b"oracle-touch", challenge, secret, "sha1", 6)
            repeated = session.apdu(codec.apdu(0xA2, p2=1, data=codec.tlv(0x71, b"oracle-increasing") + codec.tlv(0x74, challenge)))
            session.check("mixed bulk advances increasing mark only", repeated.status, 0x6A80)


def lost_hotp(session):
    with session.case("oath.HOTP.lost-response.reconcile-without-retry", ("A05", "G13", "G14", "X09"), effects=("create_oath_record", "session_recovery")):
        session.require(session.card is not None and hasattr(session.card, "drop_response"), "explicit response-loss injection backend required", "excluded_by_mode")
        name, secret = b"oracle-uncertain-HOTP", OATH_HASHES[0][2]
        with records(session, [(name, key_fields(0x10, 1, 6, secret))], empty=True):
            answer(session, name, bytes(8), secret, "sha1", 6, counter=0)
            request = codec.apdu(0xA2, p2=1, data=codec.tlv(0x71, name) + codec.tlv(0x74, bytes(8)))
            try:
                session._exchange("card", session.card.layer, "oath.injected-response-loss", request, session.options.timeout,
                                  lambda deadline, observe: session.card.drop_response(request, deadline, observe))
            except TransferError as error:
                session.check("lost HOTP result remains uncertain", error.outcome, Outcome.CANCELLED)
            else:
                session.check("response loss injection must not deliver an answer", False)
            change(session, Action.RECONNECT)
            oath_open(session)
            returned = calculate(session, name, bytes(8))
            candidates = [otp_value(secret, counter.to_bytes(8, "big"), "sha1", 6) for counter in (1, 2)]
            session.check("uncertain request consumed zero or one counter", returned in candidates)
            counter = 1 + candidates.index(returned)
            session.observe("reconciled_counter", {"next_observed_counter": counter, "lost_operation_committed": counter == 2})
            answer(session, name, bytes(8), secret, "sha1", 6, counter=counter + 1)


def run(session):
    combinations(session)
    put_failures(session)
    calculate_bounds(session)
    bulk_touch(session)
    lost_hotp(session)
