# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The real emulator client receives raw CCID faults through an offline socket."""
import socket

import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from oracle_lib.transport import EmuCard


def header(kind, sequence, status=0, error=0, body=b""):
    return bytes([kind]) + len(body).to_bytes(4, "little") + bytes([0, sequence, status, error, 0]) + body


class Socket:
    def __init__(self, defect=None):
        self.defect, self.pending, self.closed, self.messages = defect, b"", False, []

    def settimeout(self, timeout):
        pass

    def sendall(self, packet):
        message = packet[5:]
        assert packet[0] == 0 and len(message) == int.from_bytes(packet[1:5], "big")
        self.messages.append(message)
        sequence = message[6] if len(message) > 6 else 0
        declared = int.from_bytes(message[1:5], "little") if len(message) >= 10 else 0
        if len(message) < 10 or declared > 3062 or len(message) < 10 + declared:
            result = header(0x80, sequence, body=b"\x6f\x00" if self.defect != "malformed-accepted" else b"\x90\x00")
        elif message[0] == 0x6F and declared < 4:
            result = header(0x81, sequence, 0x40, 1)
        elif message[0] == 0x6F:
            apdu = message[10:10 + declared]
            body = b"\x05\x08\x00\x90\x00" if apdu[1] == 0xFD else b"\x90\x00"
            result = header(0x80, sequence, body=body)
        elif message[0] == 0x62:
            result = header(0x80, sequence, body=b"offline ATR")
        else:
            if self.defect == "ABORT-closes-link":
                self.closed = True
            return
        self.pending += len(result).to_bytes(4, "big") + result

    def recv(self, size):
        if self.closed:
            return b""
        if not self.pending:
            raise socket.timeout("synthetic idle observation")
        result, self.pending = self.pending[:size], self.pending[size:]
        return result

    def close(self):
        self.closed = True


def test_short_raw_CCID_header_is_transmitted_without_a_host_index_error():
    card = EmuCard.__new__(EmuCard)
    peer = Socket()
    card.socket, card.clock, card.on_extension = peer, lambda: 0, None
    result = card.raw(b"\x6f", 1000000000, lambda *args, **kwargs: None)
    assert result[10:] == b"\x6f\x00" and peer.messages == [b"\x6f"]


@pytest.mark.parametrize("defect,needle", [(None, None), ("malformed-accepted", "malformed CCID frame receives transport resynchronization"),
    ("ABORT-closes-link", "unsupported idle CCID command has a bounded silent observation")])
def test_raw_CCID_faults_run_through_the_actual_socket_client(tmp_path, monkeypatch, defect, needle):
    from oracle_lib import transport
    created = []
    def connect(*args, **kwargs):
        created.append(Socket(defect))
        return created[-1]
    monkeypatch.setattr(transport.socket, "create_connection", connect)
    trace = Trace(tmp_path / "CCID-faults", {})
    card = EmuCard("synthetic.invalid:1", trace.now)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True))
    oracle.execute(session, ["ccid-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert len(created) == 4 and not session.broken
