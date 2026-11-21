# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Import-only peers bind the loaded scalar to real U2F attestation certificates."""
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from oracle_lib import codec, seed_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_seed_matrix import Peer


class FipsPeer(Peer):
    def __init__(self, defect):
        super().__init__(defect)
        self.previous_certificate = self.certificate()

    def certificate(self):
        private = ec.derive_private_key(int.from_bytes(self.vendor.seed, "big"), ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oracle FIPS fixture")])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(private, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            assert wire[1] == 1
            body, handle = wire[7:-2], b"FIPS owned handle"
            challenge, application = body[:32], body[32:]
            private = ec.derive_private_key(int.from_bytes(self.vendor.seed, "big"), ec.SECP256R1())
            point = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            cert = self.previous_certificate if self.fault == "stale-certificate" else self.certificate()
            signature = private.sign(b"\x00" + application + challenge + handle + point, ec.ECDSA(hashes.SHA256()))
            output = b"\x05" + point + bytes([len(handle)]) + handle + cert + signature + b"\x90\x00"
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0x9000)
        if wire[0] == 0x41 and codec.decode(wire[1:])[1] == 2 and self.fault != "permits-export":
            self.vendor.channel = None
            return self.reply(wire, 0x30, {}, observe)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("permits-export", "FIPS export refuses"),
    ("stale-certificate", "certificate over the exact imported public key")])
def test_FIPS_import_only_policy_and_seed_bound_attestation(tmp_path, defect, needle):
    trace = Trace(tmp_path / "FIPS-import", {})
    session = Session(trace, hid=FipsPeer(defect), profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", features=("fips-profile",), allow_effects=("seed_change",)))
    seed_matrix.fips(session)
    trace.finish()
    if needle:
        assert trace.cases[0]["verdict"] == "fail" and needle in trace.cases[0]["reason"], trace.cases
    else:
        assert len(trace.cases) == 1 and trace.cases[0]["verdict"] == "pass", trace.cases
