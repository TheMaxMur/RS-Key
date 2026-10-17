# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""HID scheduling and host response loss are tested through normal suite dispatch."""
from collections import deque

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import CtapRoute, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError, recover
from oracle_lib.transport import Hid
from oracle_lib.transport_cases import reports


class PresenceReports:
    def __init__(self, defect=None):
        self.defect, self.queue, self.owner = defect, deque(), None
        self.next_cid = 10
        self.now, self.lock_until, self.lock_owner = 0, 0, None

    def write(self, report):
        frame = report[1:]
        cid, command, size = frame[:4], frame[4] & 127, int.from_bytes(frame[5:7], "big")
        value = frame[7:7 + size]
        if command != 6 and cid != self.lock_owner and self.now < self.lock_until:
            self.queue.extend(reports(cid, 0x3F, b"\x06"))
        elif command == 6:
            self.next_cid += 1
            allocated = self.next_cid.to_bytes(4, "big") if cid == bytes([255]) * 4 else cid
            self.queue.extend(reports(cid, 6, value + allocated + bytes([2, 5, 8, 0, 5])))
        elif command == 0x11:
            if self.owner is not None and (cid == self.owner or self.defect == "foreign-cancel-bypass"):
                self.queue.extend(reports(self.owner, 0x10, b"\x2d"))
                self.owner = None
        elif self.owner is not None:
            error = 1 if self.defect == "wrong-busy-code" else 6
            self.queue.extend(reports(cid, 0x3F, bytes([error])))
        elif command == 0x10 and value[:1] == b"\x0b":
            self.owner = cid
        elif command == 0x10 and value[:1] == b"\x04":
            self.queue.extend(reports(cid, command, b"\x00" + codec.encode({1: ["FIDO_2_1"]})))
        elif command == 1:
            self.queue.extend(reports(cid, command, value))
        elif command in (4, 8):
            valid = not value if command == 8 else len(value) == 1 and value[0] <= 10
            if command == 4 and valid:
                self.lock_owner, self.lock_until = cid, self.now + value[0]
            self.queue.extend(reports(cid, command if valid else 0x3F, b"" if valid else b"\x02"))
        else:
            raise AssertionError("unexpected report command")
        return len(report)

    def read(self, length, milliseconds):
        if self.queue:
            return self.queue.popleft()
        if self.owner is not None:
            return reports(self.owner, 0x3B, b"\x02")[0]
        return b""

    def close(self):
        pass


@pytest.mark.parametrize("defect,expected", [(None, None), ("foreign-cancel-bypass", "foreign CANCEL did not complete"),
                                           ("wrong-busy-code", "foreign channel busy code")])
def test_HID_presence_cancel_concurrency_and_recovery(tmp_path, monkeypatch, defect, expected):
    from oracle_lib import hid_sequences
    trace = Trace(tmp_path / "presence", {})
    peer = PresenceReports(defect)
    hid = Hid({}, trace.now, peer)
    monkeypatch.setattr(hid_sequences, "wait", lambda session, seconds: setattr(peer, "now", peer.now + seconds))
    hid.cid = bytes.fromhex("01020304")
    session = Session(trace, hid=hid)
    oracle.execute(session, ["hid-sequences"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(expected in row["reason"] for row in failures), failures
    assert hid.on_keepalive is None and hid.on_report is None
    recovered = recover(trace.directory)
    assert not recovered["unfinished_exchanges"]
    if defect is None:
        cancelled = next(row for row in trace.exchanges if row["command"] == "ctap.0b")
        assert cancelled["timing"]["keepalives"]
        assert cancelled["timing"]["response_latency_ns"] is not None
        sends = [row for row in trace.exchanges if row["protocol_outcome"] == "no_response_expected"]
        assert sends and all(row["timing"]["response_latency_ns"] is None for row in sends)


def test_FIDO_card_route_keeps_APDU_and_CTAP_status_separate(tmp_path):
    class Card:
        layer = "pcsc_apdu"
        calls = 0
        def transfer(self, request, deadline, observe):
            self.calls += 1
            observe("tx", request)
            body = b"\x31" if request[1] == 0x10 else b""
            response = body + b"\x90\x00"
            observe("rx", response)
            return Reply(response, "success", 0x9000)
    trace = Trace(tmp_path / "card-ctap", {})
    card = Card()
    session = Session(trace, card=card)
    with session.case("card-PIN"):
        with session.route(CtapRoute.CARD):
            result = session.ctap(6, {1: 2, 2: 9, 6: bytes(32)})
            session.check("nested CTAP PIN refusal", (result.protocol, result.status), ("applet_error", 0x31))
            with pytest.raises(Exception, match="already refused"):
                session.ctap(6, {1: 2, 2: 9, 6: bytes(32)})
    trace.finish()
    assert card.calls == 1
    assert trace.exchanges[0]["status"] == 0x9000
    assert trace.cases[0]["observations"]["ctap.card.06.step-1.status"]["value"] == 0x31


def test_response_loss_requires_explicit_reconnect_and_readback(tmp_path, monkeypatch):
    from yubikit import openpgp

    class Card:
        layer = "pcsc_apdu"
        value = b"original"
        authenticated = False
        def transfer(self, request, deadline, observe):
            from test_oracle_expanded import apdu_parts
            ins, p1, p2, data = apdu_parts(request)
            body = b""
            if ins == 0x20:
                self.authenticated = True
            elif ins == 0xCA:
                body = self.value
            elif ins == 0xDA:
                assert self.authenticated
                self.value = data
            elif ins == 0xA4:
                self.authenticated = False
            else:
                raise AssertionError("unexpected peer instruction")
            observe("tx", request)
            response = body + b"\x90\x00"
            observe("rx", response)
            return Reply(response, "success", 0x9000)
        def drop_response(self, request, deadline, observe):
            from test_oracle_expanded import apdu_parts
            assert self.authenticated
            self.value = apdu_parts(request)[3]
            observe("tx", request)
            raise TransferError("injected before response delivery", Outcome.CANCELLED, protocol="injected_response_loss")
        def control(self, action, deadline, observe):
            assert action == "reconnect"
            self.authenticated = False
            return Reply(b"")

    trace = Trace(tmp_path / "lost", {})
    card = Card()
    session = Session(trace, card=card, options=Options(exercise=True, openpgp_admin="fixture-admin"))
    class Sdk:
        def __init__(self, connection):
            session.select("openpgp")
        def get_data(self, tag):
            return session.card_value(session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255)))
        def verify_admin(self, secret):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=secret.encode())))
        def put_data(self, tag, data):
            session.card_value(session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, data)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    from oracle_lib.cross_cases import lost_write
    lost_write(session)
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases
    assert card.value == b"original" and not session.broken
    failed = next(row for row in trace.exchanges if row["protocol_outcome"] == "injected_response_loss")
    assert failed["side_effect_status"] == "unknown" and failed["timing"]["response_latency_ns"] is None
    assert trace.cases[0]["observations"]["write_readback"]["value"] == "committed"
    assert not recover(trace.directory)["unfinished_exchanges"]
