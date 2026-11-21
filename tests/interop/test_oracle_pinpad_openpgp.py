# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PW1-SIG entry grants are proved with a retained signing key, not VERIFY status."""
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

import oracle
from oracle_lib import codec, pinpad_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace, Outcome, TransferError
from test_oracle_openpgp_matrix import Peer as KeyPeer, sdk_type


class Peer(KeyPeer):
    pipe = True

    def transfer(self, wire, deadline, observe):
        if isinstance(wire, dict):
            from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
            observe("tx", wire["data"])
            if wire["code"] == CM_IOCTL_GET_FEATURE_REQUEST:
                result = b"\x06\x04\x00\x00\x00\x01"
            else:
                mode = self.session.current.parameters["entry_action"]
                if mode.startswith("structure-"):
                    raise TransferError("synthetic driver structure refusal", Outcome.RUNNER_ERROR)
                if mode == "correct":
                    if self.defect != "reported-success-without-SIG-grant":
                        self.grants.add(0x81)
                    result = b"\x90\x00"
                else:
                    if self.defect == "cancel-revokes-SIG-grant":
                        self.grants.clear()
                    result = b"\x64\x00" if mode == "timeout" else b"\x64\x01"
            observe("rx", result)
            return Reply(result)
        return super().transfer(wire, deadline, observe)


@pytest.mark.parametrize("defect", [None, "reported-success-without-SIG-grant", "cancel-revokes-SIG-grant"])
def test_secure_PW1_SIG_entry_performs_actual_signing(tmp_path, monkeypatch, defect):
    from yubikit import openpgp
    from yubikit.core.smartcard import ApduError
    monkeypatch.setattr(pinpad_matrix, "REFERENCES", (("openpgp", 0x81),))
    trace = Trace(tmp_path / "pinpad-PW1", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, openpgp_pin="123456", openpgp_admin="12345678", features=("display",), timeout=131, allow_effects=("config_change",)))
    peer.session = session
    class Sdk(sdk_type(session)):
        def sign(self, message, algorithm):
            digest = hashes.Hash(algorithm)
            digest.update(message)
            result = session.apdu(codec.apdu(0x2a, 0x9e, 0x9a, digest.finalize()))
            if result.status != 0x9000:
                raise ApduError(result.data[:-2], result.status)
            raw = result.data[:-2]
            return utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    oracle.execute(session, ["pinpad-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("secure entry controls the actual PW1-SIG private operation" in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.keys


def test_failed_secure_SIG_fixture_setup_restores_the_changed_PIN_mode(tmp_path, monkeypatch):
    from yubikit import openpgp
    from oracle_lib import pgp_keys
    from test_oracle_expanded import apdu_parts
    trace = Trace(tmp_path / "pinpad-partial-setup", {})
    peer = Peer()
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    def fail_import(*args):
        raise ValueError("synthetic setup failure after PIN-mode write")
    monkeypatch.setattr(pgp_keys, "put_key", fail_import)
    with session.case("pinpad.partial-setup", effects=("config_change", "replace_openpgp_sig_key")):
        pinpad_matrix.Grant(session, "openpgp", 0x81)
    trace.finish()
    writes = [apdu_parts(bytes.fromhex(row["request"]["hex"])) for row in trace.exchanges]
    assert [body for ins, p1, p2, body in writes if (ins, p1, p2) == (0xda, 0, 0xc4)] == [b"\x01", b"\x00"]
    assert trace.cases[0]["verdict"] == "fail" and "synthetic setup failure" in trace.cases[0]["reason"]
    assert not peer.keys and not session.broken
