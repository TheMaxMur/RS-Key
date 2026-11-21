# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Functional peers exercise new state transitions and falsify their witnesses."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import arkg, codec, fido, keyboard, oath_records
from oracle_lib.runner import Options, Session, SkipCase
from oracle_lib.trace import Reply, Trace, recover


def apdu_parts(request):
    if len(request) <= 5:
        return request[1], request[2], request[3], b""
    if request[4]:
        return request[1], request[2], request[3], request[5:5 + request[4]]
    length = int.from_bytes(request[5:7], "big")
    return request[1], request[2], request[3], request[7:7 + length]


class PasswordPeer:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.defect, self.records, self.counter = defect, {}, 0
        self.pin, self.retries, self.verified = None, 3, False

    def transfer(self, request, deadline, observe):
        observe("tx", request)
        ins, p1, p2, data = apdu_parts(request)
        status, body = 0x9000, b""
        fields = dict(codec.parse_tlv(data)) if data and ins != 0xA4 else {}
        if ins == 0xA4:
            self.verified = False
            body = codec.tlv(0x79, b"\x05\x08\x00") + codec.tlv(0x71, b"oracleid")
        elif ins == 0xB4:
            if self.pin is not None:
                status = 0x6985
            else:
                self.pin, self.retries = fields[0x80], 3
        elif ins in (0xB2, 0xB3):
            self.verified = False
            if self.pin is None:
                status = 0x6985
            elif self.retries == 0 and self.defect != "blocked-correct-PIN-bypass":
                status = 0x6982
            elif fields[0x80] != self.pin:
                self.retries -= 1
                status = 0x6982
            else:
                self.retries, self.verified = 3, True
                if ins == 0xB3:
                    self.pin = fields[0x81]
        elif ins == 1:
            name = fields[0x71]
            if not 14 <= len(fields[0x73][2:]) <= 64 or any(len(value) > 255 for tag, value in fields.items() if tag in (0x83, 0x84, 0x85)):
                status = 0x6A80
                if self.defect == "invalid-write-damages-record":
                    self.records.pop(name, None)
            else:
                self.records[name] = fields
                self.counter = 0
        elif ins == 0xA1:
            body = b"".join(codec.tlv(0x72, value[0x73][:1] + name) for name, value in self.records.items())
        elif ins == 0xB5:
            if self.pin is not None and not self.verified and self.defect != "password-ACL-bypass":
                status = 0x6982
            elif fields[0x71] not in self.records:
                status = 0x6984
            else:
                body = b"".join(codec.tlv(tag, value) for tag, value in self.records[fields[0x71]].items() if tag != 0x73)
        elif ins == 2:
            self.records.pop(fields[0x71])
        elif ins == 0xB1:
            primary = next(iter(self.records.values()))
            key = primary[0x73]
            digest = hmac.digest(key[2:], self.counter.to_bytes(8, "big"), "sha1")
            offset = digest[-1] & 15
            expected = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000
            status = 0x9000 if int.from_bytes(fields.get(0x75, bytes(4)), "big") == expected else 0x6A80
            if status == 0x9000 and self.defect == "VERIFY-CODE-advances-HOTP":
                self.counter += 1
        elif ins == 0xA2:
            key = self.records[fields[0x71]][0x73]
            from oracle_lib.otp import otp_value
            number = otp_value(key[2:], self.counter.to_bytes(8, "big"), "sha1", key[1])
            body = codec.tlv(0x76, key[1:2] + number.to_bytes(4, "big"))
            self.counter += 1
        elif ins == 4:
            assert (p1, p2) == (0xDE, 0xAD)
            self.records, self.pin, self.verified = {}, None, False
        else:
            raise AssertionError(f"unimplemented peer INS {ins:02x}")
        response = body + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("invalid-write-damages-record", "APDU success"),
    ("password-ACL-bypass", "OATH refusal cause"), ("blocked-correct-PIN-bypass", "cannot bypass block"),
    ("VERIFY-CODE-advances-HOTP", "APDU success")])
def test_password_record_and_PIN_lifecycle_dispatch(tmp_path, defect, expected):
    peer = PasswordPeer(defect)
    trace = Trace(tmp_path / "passwords", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, oath_pin="fixture-PIN",
                      allow_effects=("pin_change", "pin_attempts", "applet_reset")))
    oracle.execute(session, ["oath-records"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failed, failed
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(expected in row["reason"] for row in failed), failed
    assert peer.pin is None and not peer.records
    assert not recover(trace.directory)["unfinished_exchanges"]


def test_PIN_attempt_budget_is_explicit_bounded_and_recovers(tmp_path):
    class Peer:
        layer = "pcsc_apdu"
        count = 0
        def transfer(self, request, deadline, observe):
            self.count += 1
            status = 0x9000 if request[5:] == b"correct" else 0x63C2
            observe("tx", request)
            return Reply(status.to_bytes(2, "big"), "success" if status == 0x9000 else "applet_error", status)
    trace = Trace(tmp_path / "attempts", {})
    peer = Peer()
    session = Session(trace, card=peer, options=Options(exercise=True, allow_effects=("pin_attempts",)))
    session.applet = "openpgp"
    with session.case("bounded", effects=("pin_attempts",)):
        with session.attempts(("openpgp", 0x81), 2):
            assert session.apdu(codec.apdu(0x20, p2=0x81, data=b"wrong")).status == 0x63C2
            assert session.apdu(codec.apdu(0x20, p2=0x82, data=b"correct")).status == 0x9000
            with pytest.raises(SkipCase, match="budget exhausted"):
                session.apdu(codec.apdu(0x20, p2=0x81, data=b"correct"))
        assert ("openpgp", 0x81) not in session.failed_auth
        session.observe("explicit budget consumed", peer.count)
    assert peer.count == 2
    trace.finish()


@pytest.mark.parametrize("profile,allowed", [("rsk", ()), ("trezor", ("pin_attempts",))])
def test_budget_permission_and_wallet_guard_run_before_IO(tmp_path, profile, allowed):
    trace = Trace(tmp_path / profile, {})
    session = Session(trace, profile=profile, options=Options(exercise=True, allow_effects=allowed))
    with session.case("guarded", effects=("pin_attempts",)):
        with session.attempts("fido.pin", 2):
            raise AssertionError("guard failed")
    assert trace.cases[0]["verdict"] == "inconclusive"
    assert not trace.exchanges
    trace.finish()


def test_ARKG_public_derivation_matches_draft_A1():
    bl = bytes.fromhex("046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7")
    kem = bytes.fromhex("04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35")
    public, handle = arkg.derive(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bl),
                                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), kem),
                                bytes(range(0x40, 0x60)), b"ARKG-P256.test vectors")
    assert handle.hex() == "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361"
    assert arkg.encoded(public).hex() == "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd"


@pytest.mark.parametrize("algorithm,curve", [(-9, ec.SECP256R1), (-51, ec.SECP384R1), (-52, ec.SECP521R1), (-47, ec.SECP256K1)])
def test_alternative_COSE_identifiers_verify_real_signatures(algorithm, curve):
    private = ec.generate_private_key(curve())
    message = b"oracle independent signature"
    signature = private.sign(message, ec.ECDSA(fido.HASH_ALGORITHMS[algorithm]()))
    fido.verify(private.public_key(), algorithm, signature, message)


def test_keyboard_decoder_uses_press_edges_and_modifiers():
    assert keyboard.decode([bytes([2, 0, 4, 0, 0, 0, 0, 0]), bytes(8), bytes([0, 0, 4, 0, 0, 0, 0, 0]), bytes(8)])[0] == "Aa"
    with pytest.raises(ValueError, match="held"):
        keyboard.decode([bytes([0, 0, 4, 0, 0, 0, 0, 0])])
    with pytest.raises(ValueError, match="rollover"):
        keyboard.decode([bytes([0, 0, 1, 0, 0, 0, 0, 0])])


def test_cleanup_skip_cannot_hide_a_failed_property(tmp_path):
    trace = Trace(tmp_path / "cleanup-verdict", {})
    session = Session(trace)
    with session.case("failure-with-blocked-cleanup"):
        try:
            session.check("protected object must survive", False)
        finally:
            session.require(False, "cleanup cannot proceed")
    trace.finish()
    assert trace.cases[0]["verdict"] == "fail"
    assert "protected object must survive" in trace.cases[0]["reason"]


@pytest.mark.parametrize("earlier_failure", [False, True])
def test_expected_SDK_skip_during_cleanup_preserves_an_earlier_failure(tmp_path, earlier_failure):
    from oracle_lib.cards import sdk_supported
    from yubikit.core import NotSupportedError
    def unsupported():
        raise NotSupportedError("synthetic missing cleanup operation")
    trace = Trace(tmp_path / "SDK-cleanup", {})
    session = Session(trace)
    with session.case("SDK-cleanup"):
        try:
            session.check("protected record must survive", not earlier_failure)
        finally:
            sdk_supported(session, unsupported)
    trace.finish()
    row = trace.cases[0]
    if earlier_failure:
        assert row["verdict"] == "fail" and "protected record must survive" in row["reason"], row
    else:
        assert row["verdict"] == "inconclusive" and "SDK capability check" in row["reason"], row


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_cleanup_capability_failure_cannot_swallow_a_stop_request(tmp_path, kind):
    from oracle_lib.cards import sdk_supported
    from yubikit.core import NotSupportedError
    def unsupported():
        raise NotSupportedError("synthetic missing cleanup operation")
    trace = Trace(tmp_path / "stop-cleanup", {})
    session = Session(trace)
    with pytest.raises(kind):
        with session.case("stopped"):
            try:
                raise kind()
            finally:
                sdk_supported(session, unsupported)
    trace.finish("cancelled")
    assert session.current is None and trace.cases[0]["verdict"] == "fail"


def test_pairwise_generator_covers_every_pair_and_records_a_reproducible_seed():
    from itertools import combinations, product
    from oracle_lib.vectors import pairwise
    dimensions = {"status": range(4), "color": range(8), "brightness": (0, 1, 8, 255), "steady": (False, True)}
    vectors = pairwise(dimensions, "fixture-seed")
    assert vectors == pairwise(dimensions, "fixture-seed")
    for left, right in combinations(dimensions, 2):
        assert {(row[left], row[right]) for row in vectors} == set(product(dimensions[left], dimensions[right]))
    assert len(vectors) < len(list(product(*dimensions.values())))


def test_pairwise_bound_is_checked_before_allocating_the_product(monkeypatch):
    from oracle_lib import vectors
    def unexpected(*args):
        raise AssertionError("oversized Cartesian product was allocated")
    monkeypatch.setattr(vectors, "product", unexpected)
    with pytest.raises(ValueError, match="generation bound"):
        vectors.pairwise({"left": range(257), "right": range(257)}, "bounded")
