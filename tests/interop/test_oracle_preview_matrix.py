# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An independent ARKG private derivation signs every valid preview control."""
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib import arkg, codec, fido
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_credential_matrix import StorePeer


def cose(private):
    point = private.public_key().public_numbers()
    return {1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}


def private_derivation(bl, kem, handle, context):
    if len(handle) != 81 or len(context) > 64:
        raise ValueError("ARKG bounds")
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), handle[16:])
    shared = kem.exchange(ec.ECDH(), point)
    prefix = b"ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM." + bytes([len(context)]) + context
    extracted = hmac.digest(bytes(32), shared, "sha256")
    mac = hmac.digest(extracted, b"ARKG-KEM-HMAC-mac." + prefix + b"\x01", "sha256")
    if not hmac.compare_digest(handle[:16], hmac.digest(mac, handle[16:], "sha256")[:16]):
        raise ValueError("bad ARKG MAC")
    secret = hmac.digest(extracted, b"ARKG-KEM-HMAC-shared." + prefix + b"\x01", "sha256")
    factor = arkg.scalar(secret, b"ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL." + bytes([len(context)]) + context)
    return ec.derive_private_key((bl.private_numbers().private_value + factor) % arkg.ORDER, ec.SECP256R1())


class Peer(StorePeer):
    def make(self, fields):
        preview = fields.get(6, {}).get("previewSign")
        if preview is not None:
            if type(preview) is not dict or type(preview.get(4, 1)) is not int or preview.get(4, 1) < 0:
                return 0x11, {}
            if preview.get(4, 1) not in (0, 1, 5):
                return 0x2c, {}
            if 3 not in preview:
                return 0x14, {}
            if type(preview[3]) is not list or any(type(alg) is not int or alg >= 0 for alg in preview[3]):
                return 0x11, {}
            if -65539 not in preview[3]:
                return 0x26, {}
        status, value = super().make(fields)
        if status or preview is None:
            return status, value
        identifier = fido.auth_data(value[2])["credential_id"]
        bl = ec.derive_private_key(1000 + self.serial, ec.SECP256R1())
        kem = ec.derive_private_key(2000 + self.serial, ec.SECP256R1())
        handle = hashlib.sha256(identifier + b"MAC").digest() + codec.encode([-65539, preview.get(4, 1), hashlib.sha256(identifier).digest()])
        self.records[identifier]["preview"] = (handle, bl, kem, preview.get(4, 1))
        seed = {1: -65537, 3: -65700, -3: -9, -1: cose(bl), -2: cose(kem)}
        data = value[2][:32] + b"\x41" + bytes(4) + bytes(16) + len(handle).to_bytes(2, "big") + handle + codec.encode(seed)
        value.setdefault(6, {})["previewSign"] = {7: codec.encode({"fmt": "none", "authData": data, "attStmt": {}})}
        return 0, value

    def assertion(self, fields):
        ext = fields.get(4, {}).get("previewSign")
        signature = None
        if ext is not None:
            if type(ext) is not dict or any(type(value) is not bytes for key, value in ext.items() if key in (2, 6, 7)):
                return 0x11, {}
            if not fields.get(3) or 2 not in ext or 6 not in ext:
                return 0x2c, {}
            record = self.records.get(fields[3][0]["id"])
            if record is None:
                return 0x2e, {}
            handle, bl, kem, policy = record["preview"]
            if ext[2] != handle:
                return 0x22, {}
            if 7 not in ext:
                if self.defect != "missing-args-permitted":
                    return 0x14, {}
                ext = {**ext, 7: record["last-args"]}
            try:
                args = codec.decode(ext[7])
            except ValueError:
                return 0x12, {}
            if type(args) is not dict:
                return 0x11, {}
            if any(type(value) is not (int if key == 3 else bytes) for key, value in args.items() if key in (3, -1, -2)):
                return 0x11, {}
            if args.get(3) != -65539:
                return 0x22, {}
            if -1 not in args or -2 not in args:
                return 0x14, {}
            if len(ext[6]) != 32:
                return 3, {}
            if policy & 1 and not fields.get(5, {}).get("up", True) and self.defect != "UP-policy-ignored":
                return 0x3b, {}
            if policy & 4 and fields.get(6) != self.mac(fields[2]):
                return 0x36, {}
            try:
                key = private_derivation(bl, kem, args[-1], args[-2])
            except ValueError:
                return 0x22, {}
            digest = bytes(32) if self.defect == "wrong-preview-digest" else ext[6]
            signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            record["last-args"] = ext[7]
        status, value = super().assertion(fields)
        if status or signature is None:
            return status, value
        parsed = fido.auth_data(value[2])
        output = {**parsed.get("extensions", {}), "previewSign": {6: signature}}
        value[2] = value[2][:32] + bytes([value[2][32] | 128]) + value[2][33:37] + codec.encode(output)
        record = self.records[value[1]["id"]]
        value[3] = record["key"].sign(value[2] + fields[2], ec.ECDSA(hashes.SHA256()))
        return 0, value

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 4:
            output = b"\x00" + codec.encode({1: ["FIDO_2_3"], 2: ["previewSign"], 4: {"clientPin": True, "pinUvAuthToken": True}, 6: [1, 2]})
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect", [None, "wrong-preview-digest", "missing-args-permitted", "UP-policy-ignored"])
def test_preview_registration_argument_grammar_policy_and_real_ARKG_signatures(tmp_path, defect):
    trace = Trace(tmp_path / "preview-matrix", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["preview-sign"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        needle = {"wrong-preview-digest": "InvalidSignature", "missing-args-permitted": "malformed parameter has its isolated refusal", "UP-policy-ignored": "UP/UV policy survives"}[defect]
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
