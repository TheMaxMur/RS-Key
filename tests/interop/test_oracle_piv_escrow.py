# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Protected-management opt-in is independent of host PRINTED record contents."""
import pytest

import oracle
from oracle_lib import codec, piv_escrow
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_piv_objects import Peer as ObjectPeer


class Peer(ObjectPeer):
    def transfer(self, wire, deadline, observe):
        ins, _, _, data = apdu_parts(wire)
        protected = bool(piv_escrow.flags(self.objects.get(piv_escrow.ADMIN)) & 2)
        if ins == 0xff:
            result = super().transfer(wire, deadline, observe)
            if result.status == 0x9000 and protected and self.defect != "rotation-keeps-escrow":
                self.objects[piv_escrow.ADMIN] = codec.tlv(0x80, codec.tlv(0x81, b"\x00") + codec.tlv(0x83, b"oracle"))
            return result
        if ins in (0xcb, 0xdb):
            fields = dict(codec.parse_tlv(data))
            identifier = int.from_bytes(fields[0x5c], "big")
            body, sw = b"", None
            if ins == 0xcb and identifier == piv_escrow.DISCOVERY:
                body, sw = b"synthetic immutable discovery", 0x9000
            elif ins == 0xcb and identifier == piv_escrow.PRINTED and protected:
                sw = 0x9000 if self.has_pin or self.defect == "management-bypasses-escrow-PIN" else 0x6982
                if sw == 0x9000:
                    body = codec.tlv(0x53, codec.tlv(0x88, codec.tlv(0x89, self.key)))
            elif ins == 0xdb and self.has_management:
                value = fields[0x53]
                if identifier in (piv_escrow.DISCOVERY, piv_escrow.FACTORY_CERT):
                    sw = 0x6a80
                elif identifier == piv_escrow.PRINTED:
                    escrow = any(value == codec.tlv(0x88, codec.tlv(0x89, value[-length:])) for length in (16, 24, 32) if len(value) == length + 4)
                    if escrow and self.defect != "host-escrow-stored":
                        sw = 0x9000
                    elif protected and value:
                        sw = 0x6985
            if sw is not None:
                output = body + sw.to_bytes(2, "big")
                observe("tx", wire)
                observe("rx", output)
                return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)
        return super().transfer(wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("host-escrow-stored", "acknowledged host escrow bytes"),
    ("rotation-keeps-escrow", "identical explicit key rotation revokes"),
    ("management-bypasses-escrow-PIN", "management grant cannot replace PIN")])
def test_PIV_escrow_and_immutable_object_state(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "escrow", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, piv_pin="123456", management_key=DEFAULT_KEY, allow_effects=("config_change",)))
    oracle.execute(session, ["piv-escrow"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.objects and not peer.keys
