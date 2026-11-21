# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native boundaries keep persistent keys and retire only the proper volatile state."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_cross_authorization import Card as Applets
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_store_state import Peer


class Hid(Peer):
    descriptor = {"serial_number": "offline-native"}

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            ins, p1, p2, body = apdu_parts(wire)
            assert ins == 0xa4 and body == AIDS["vendor"] or ins == 0x1f
            if ins == 0x1f:
                self.card.boundary(True)
            observe("tx", wire)
            observe("rx", b"\x90\x00")
            return Reply(b"\x90\x00", status=0x9000)
        return super().transfer(command, wire, deadline, observe)

    def reopen(self, operator):
        return self.descriptor

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="offline-native")


class Card(Applets):
    descriptor = Hid.descriptor

    def __init__(self, hid, defect):
        super().__init__(hid, None)
        class Fido:
            def transfer(inner, wire, deadline, observe):
                assert apdu_parts(wire)[0] == 0xa4
                observe("tx", wire)
                observe("rx", b"U2F_V2\x90\x00")
                return Reply(b"U2F_V2\x90\x00", status=0x9000)
        self.fido = Fido()
        self.defect, hid.card = defect, self
        self.boundaries = []

    def boundary(self, warm):
        self.boundaries.append(warm)
        if self.defect != "PIV-grants-survive":
            self.piv.has_pin = self.piv.has_management = False
        if self.defect != "PGP-grants-survive":
            self.openpgp.grants.clear()
        if self.defect != "OATH-grants-survive":
            self.oath.pin_verified, self.oath.validated = False, self.oath.code is None
        if warm and self.defect != "warm-ordinary-survives" or not warm and self.defect == "bus-ordinary-revoked":
            self.hid.token, self.hid.permissions, self.hid.rp = bytes(32), 0, None
        if warm and self.defect != "warm-ECDH-survives" or not warm and self.defect == "bus-ECDH-rotates":
            self.hid.private = ec.generate_private_key(ec.SECP256R1())
        if self.defect == "RO-lost":
            import hashlib
            self.hid.ro = hashlib.sha256(self.hid.ro).digest()
        if self.defect == "identity-lost":
            self.hid.seed += b"changed"
        if self.defect == "private-key-lost":
            self.hid.records.clear()

    def usb_reset(self, deadline, observe):
        self.boundary(False)
        observe("backend_event", b"", event="libusb.reset_device.invoked")
        return Reply(b"")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4 and body == b"\xf0\xff\xff\xff\xff":
            observe("tx", wire)
            observe("rx", b"\x6a\x82")
            return Reply(b"\x6a\x82", "applet_error", 0x6a82)
        return super().transfer(wire, deadline, observe)

    def wait_disconnect(self, deadline, observe):
        raise TransferError("offline measured disconnect", Outcome.DISCONNECTED)

    def control(self, action, deadline, observe):
        assert action == "reconnect"
        return Reply(b"offline ATR")


@pytest.mark.parametrize("defect,needle", [(None, None), ("PIV-grants-survive", "PIN latch"),
    ("PGP-grants-survive", "reference status query"), ("OATH-grants-survive", "OATH code latch"),
    ("warm-ordinary-survives", "CPU warm reboot revokes"), ("bus-ordinary-revoked", "CTAP success"),
    ("warm-ECDH-survives", "ECDH lifetime"), ("bus-ECDH-rotates", "ECDH lifetime"),
    ("RO-lost", "CTAP success"), ("identity-lost", "decrypted identity"),
    ("private-key-lost", "CTAP success")])
def test_native_reset_products_with_retained_private_controls(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    hid = Hid()
    card = Card(hid, defect)
    trace = Trace(tmp_path / "native-lifetimes", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("applet_reset", "pin_change", "config_change", "reboot", "session_recovery")))
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["extended-lifetimes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:30]
    else:
        assert len(trace.cases) == 90 and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"][:30]
        assert {True, False} == set(card.boundaries)
        assert not card.piv.keys and not card.openpgp.keys and not card.oath.records


def test_native_serial_binding_is_checked_before_fixture_writes(tmp_path, monkeypatch):
    from oracle_lib import extended_lifetimes
    from oracle_lib.vendor_boot import Boundary
    monkeypatch.setattr(extended_lifetimes, "BOUNDARIES", (Boundary.WARM, Boundary.USB_RESET))
    hid = Hid()
    card = Card(hid, None)
    card.descriptor = {"serial_number": "different"}
    trace = Trace(tmp_path / "native-wrong-pair", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", allow_effects=("applet_reset", "pin_change", "config_change", "reboot", "session_recovery")))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["extended-lifetimes"])
    trace.finish()
    assert len(trace.cases) == 36 and all(row["applicability"] == "excluded_by_mode" for row in trace.cases)
    assert not card.boundaries and not hid.records and card.applet is None
