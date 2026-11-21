# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset isolation is falsified by deleting a neighboring private key or lock."""
import hmac

import pytest

import oracle
from oracle_lib import codec, cross_reset
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_matrix import KeyCard
from test_oracle_openpgp_matrix import Peer as PgpPeer, sdk_type
from test_oracle_token_matrix import Peer as TokenPeer
from test_oracle_oath_semantics import Peer as OathPeer
from test_oracle_states import ManagementPeer
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Piv(KeyCard):
    def factory(self):
        super().factory()
        self.keys, self.policies = {}, {}

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0x87 and p2 != 0x9B and p2 not in self.keys:
            observe("tx", wire)
            observe("rx", b"\x6a\x88")
            return Reply(b"\x6a\x88", "applet_error", 0x6A88)
        return super().transfer(wire, deadline, observe)


class Hid(TokenPeer):
    def reopen(self, operator):
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            observe("tx", wire)
            observe("rx", b"\x6d\x00")
            return Reply(b"\x6d\x00", "applet_error", 0x6D00)
        return super().transfer(command, wire, deadline, observe)


class Card:
    layer, emulated = "pcsc_apdu", True

    def __init__(self, hid, defect):
        self.hid, self.defect = hid, defect
        self.piv, self.pgp, self.oath, self.management = Piv(), PgpPeer(), OathPeer(), ManagementPeer()
        self.pgp.values.update({0x65: b"\x65\x00", 0x6E: b"\x6e\x00"})
        self.applet, self.otp_key = None, None

    def control(self, action, deadline, observe):
        self.piv.has_pin = self.piv.has_management = False
        self.pgp.grants.clear()
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xA4:
            self.applet = next(name for name, aid in AIDS.items() if aid.startswith(data) or data.startswith(aid))
        if self.applet == "fido":
            observe("tx", wire)
            return Reply(b"\x90\x00", "success", 0x9000)
        if self.applet == "otp":
            observe("tx", wire)
            if ins == 1:
                if p1 in (1, 3):
                    self.otp_key = data[22:38] + data[16:20] if any(data[:52]) else None
                    output = b""
                else:
                    output = hmac.digest(self.otp_key, data, "sha1")
            else:
                output = b"\x05\x08\x00\x00\x00\x00"
            output += b"\x90\x00"
            observe("rx", output)
            return Reply(output, "success", 0x9000)
        if self.applet == "oath" and ins == 4:
            status = 0x9000 if (p1, p2) == (0xDE, 0xAD) else 0x6A80
            if status == 0x9000:
                self.oath.records.clear()
                if self.defect == "neighbor-key-lost":
                    self.piv.keys.clear()
                if self.defect == "shared-lock-lost":
                    self.management.lock = None
            output = status.to_bytes(2, "big")
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "success" if status == 0x9000 else "applet_error", status)
        if self.applet == "oath" and ins == 0xA2:
            fields = dict(codec.parse_tlv(data))
            if fields[0x71] not in self.oath.records:
                observe("tx", wire)
                observe("rx", b"\x6a\x80")
                return Reply(b"\x6a\x80", "applet_error", 0x6A80)
        peer = self.pgp if self.applet == "openpgp" else getattr(self, self.applet)
        result = peer.transfer(wire, deadline, observe)
        if self.applet == "openpgp":
            self.pgp.values.update({0x65: b"\x65\x00", 0x6E: b"\x6e\x00"})
        return result


@pytest.mark.parametrize("defect", [None, "neighbor-key-lost", "shared-lock-lost", "reset-retains-RO"])
def test_populated_applet_reset_isolation(tmp_path, monkeypatch, defect):
    from yubikit import openpgp
    from oracle_lib import binding
    hid = Hid(defect)
    card = Card(hid, defect)
    trace = Trace(tmp_path / "cross-reset", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "applet_reset", "pin_change", "pin_attempts", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    monkeypatch.setattr(cross_reset, "require_pair", lambda s: None)
    monkeypatch.setattr(binding, "check_pair", lambda s: None)
    oracle.execute(session, ["cross-reset"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        needle = "reprovisioning the original PIN cannot resurrect" if defect == "reset-retains-RO" else "applet reset preserves observed neighboring state"
        assert any(needle in row["reason"] for row in failures), failures
        assert all("cleanup" not in row["scenario_id"] for row in failures), failures
    else:
        assert not failures, [(row["scenario_id"], row["reason"]) for row in failures]
        assert sum(row["scenario_id"].endswith("verify-private-isolation") and row["verdict"] == "pass" for row in trace.cases) == 4
        assert not card.piv.keys and not card.pgp.keys and not card.oath.records and card.otp_key is None and card.management.lock is None
