# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Part 10 returns cannot authenticate a protected key by assertion alone."""
import pytest

import oracle
from oracle_lib import pinpad_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace, TransferError, Outcome
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_piv_matrix import KeyCard


class Peer(KeyCard):
    pipe = True

    def control(self, *args):
        self.has_pin = False
        return Reply(b"synthetic ATR")

    def transfer(self, request, deadline, observe):
        if isinstance(request, dict):
            from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
            observe("tx", request["data"])
            if request["code"] == CM_IOCTL_GET_FEATURE_REQUEST:
                result = b"\x06\x04\x00\x00\x00\x01"
            else:
                mode = self.session.current.parameters["entry_action"]
                if mode.startswith("structure-"):
                    raise TransferError("synthetic driver structure refusal", Outcome.RUNNER_ERROR)
                if mode == "correct":
                    if self.defect != "success-without-grant":
                        self.has_pin = True
                    result = b"\x90\x00"
                else:
                    if self.defect == "cancel-authenticates":
                        self.has_pin = True
                    if self.defect == "cancel-logs-out":
                        self.has_pin = False
                    result = b"\x64\x00" if mode == "timeout" else b"\x64\x01"
            observe("rx", result)
            return Reply(result)
        ins, _, p2, _ = apdu_parts(request)
        if ins == 0x87 and p2 == 0x82 and not self.has_pin:
            observe("tx", request)
            observe("rx", b"\x69\x82")
            return Reply(b"\x69\x82", "applet_error", 0x6982)
        return super().transfer(request, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None),
    ("cancel-authenticates", "secure-entry failure cannot create a PIV grant"),
    ("cancel-logs-out", "secure PIN grants the protected private operation"),
    ("success-without-grant", "secure PIN grants the protected private operation")])
def test_secure_entry_result_is_checked_against_actual_private_access(tmp_path, monkeypatch, defect, needle):
    monkeypatch.setattr(pinpad_matrix, "REFERENCES", (("piv", 0x80),))
    trace = Trace(tmp_path / "pinpad", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        piv_pin="123456", management_key=DEFAULT_KEY, features=("display",), timeout=131))
    peer.session = session
    oracle.execute(session, ["pinpad-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.keys and not session.broken


class PropertiesPeer(Peer):
    def transfer(self, request, deadline, observe):
        if isinstance(request, dict):
            from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
            code = request["code"]
            if code == CM_IOCTL_GET_FEATURE_REQUEST:
                result = b"".join(bytes([tag, 4]) + (0x100 + tag).to_bytes(4, "big") for tag in (6, 10, 11, 17, 18))
            elif code == 0x10a:
                result = b"\x20\x02\x02\x00"
                if self.defect == "short-PIN-properties":
                    result = result[:-1]
            elif code == 0x111:
                result = b"synthetic display properties"
            elif code == 0x112:
                result = b"\x01\x02\x20\x02\x06\x01\x06\x07\x01\x08"
            elif code == 0x10b:
                if self.defect == "idle-abort-logs-out":
                    self.has_pin = False
                result = b""
            else:
                raise AssertionError("unexpected property control")
            observe("tx", request["data"])
            observe("rx", result)
            return Reply(result)
        return super().transfer(request, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("short-PIN-properties", "PIN_PROPERTIES has its four-byte"),
    ("idle-abort-logs-out", "secure PIN grants the protected")])
def test_Part10_property_structures_and_idle_abort_keep_the_grant(tmp_path, defect, needle):
    trace = Trace(tmp_path / "pinpad-properties", {})
    peer = PropertiesPeer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, piv_pin="123456", management_key=DEFAULT_KEY))
    oracle.execute(session, ["pinpad-properties"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and trace.cases[0]["verdict"] == "pass", trace.cases
        assert not peer.keys


@pytest.mark.parametrize("defect", [None, "headless-authenticates"])
def test_headless_raw_CCID_secure_cannot_grant_PIN_access(tmp_path, defect):
    class Headless(Peer):
        def raw(self, request, deadline, observe):
            assert request[0] == 0x69 and request[10] == 0
            if self.defect == "headless-authenticates":
                self.has_pin = True
            result = bytes([0x80, 0, 0, 0, 0, 0, request[6], 0x40, 0, 0])
            observe("tx", request)
            observe("rx", result)
            return result
    trace = Trace(tmp_path / "headless", {})
    session = Session(trace, card=Headless(defect), profile="rsk", options=Options(exercise=True, piv_pin="123456", management_key=DEFAULT_KEY, features=("headless",)))
    oracle.execute(session, ["pinpad-headless"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("secure-entry failure cannot create a PIV grant" in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
