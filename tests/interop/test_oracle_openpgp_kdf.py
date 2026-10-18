# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An independent TLV model reseeds only empty owner slots and retains real keys."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import Peer as ReferencePeer, sdk_with_errors


def setting(data):
    if data == b"\x81\x01\x00":
        return b"123456", b"12345678"
    fields = list(codec.parse_tlv(data))
    tags = (0x81, 0x82, 0x83, 0x84, 0x87, 0x88) if len(data) == 90 else (0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88)
    widths = {0x81: 1, 0x82: 1, 0x83: 4, 0x84: 8, 0x85: 8, 0x86: 8, 0x87: 32, 0x88: 32}
    if tuple(tag for tag, _ in fields) != tags or any(len(value) != widths[tag] for tag, value in fields):
        raise ValueError("fixed KDF layout")
    if b"".join(codec.tlv(tag, value) for tag, value in fields) != data:
        raise ValueError("noncanonical length")
    values = dict(fields)
    return values[0x87], values[0x88]


class Peer(ReferencePeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw = 0x9000
        if ins == 0xda and p2 == 0xf9:
            if 0x83 not in self.grants:
                sw = 0x6982
            else:
                try:
                    user, admin = setting(body)
                except (ValueError, KeyError):
                    sw = 0x6a80
                else:
                    if self.keys:
                        sw = 0x6985
                    else:
                        self.values[0xf9] = body
                        self.pins = {0x81: user, 0x83: admin}
                        self.left = dict(self.maximum)
                        if self.defect != "old-reset-code-retained":
                            self.code = b""
        elif ins == 0xda and p2 == 0xd3:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif body and not 8 <= len(body) <= 127:
                sw = 0x6a80
            else:
                self.code = body
        elif ins == 0xca and p2 == 0xc4:
            output = bytes([self.mode, 127, 127, 127, self.left[0x81], 3 if self.code else 0, self.left[0x83]])
            observe("tx", wire)
            observe("rx", output + b"\x90\x00")
            return Reply(output + b"\x90\x00", "success", 0x9000)
        else:
            if ins == 0x20 and body == b"123456" and self.pins[0x81] != body and p2 == 0x81 and self.defect == "raw-PIN-still-valid":
                body = self.pins[0x81]
                wire = codec.apdu(ins, p1, p2, body)
            return super().transfer(wire, deadline, observe)
        output = sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)

    def control(self, action, deadline, observe):
        result = super().control(action, deadline, observe)
        if self.defect == "KDF-key-lost-on-reconnect":
            self.keys.clear()
        return result


@pytest.mark.parametrize("defect,needle", [(None, None), ("old-reset-code-retained", "deactivates incompatible reset-code"),
    ("raw-PIN-still-valid", "no longer matches"), ("KDF-key-lost-on-reconnect", "raw signature input has the exact width/policy outcome")])
def test_KDF_empty_layouts_incompatible_old_password_and_private_key_persistence(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-KDF", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", openpgp_reset_code="",
        allow_effects=("pin_change", "pin_attempts", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-kdf"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert peer.pins == {0x81: b"123456", 0x83: b"12345678"} and peer.code == b"" and not peer.keys
