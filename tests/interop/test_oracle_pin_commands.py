# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""ClientPIN dispatch guards precede semantics and retain a real private key."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_token_matrix import Peer as Tokens


class Peer(Tokens):
    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 6:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        status = None
        keys = list(fields)
        if keys and keys[0] != 1 or len(keys) > 1 and keys[1] != 2:
            status = 0x14
        else:
            for value in (fields.get(1, 0), fields.get(2, 0)):
                if value < 0:
                    status = 0x11
                    break
                if value > 0xffffffff:
                    status = 0x12
                    break
        if status is None and fields.get(1, 0) not in (1, 2):
            status = 0x14 if self.defect == "subcommand-before-protocol" and fields.get(2, 0) == 0 else 2
        if status is None:
            sub = fields.get(2, 0)
            if sub not in (1, 2, 3, 4, 5, 9):
                status = 0x14 if sub == 0 else 0x3e
            elif sub in (3, 4, 5, 9) and 3 not in fields:
                status = 0x14
            elif self.defect == "public-read-requires-MAC" and sub in (1, 2) and 4 in fields and not fields[4]:
                status = 0x33
        if status is None:
            return super().transfer(command, wire, deadline, observe)
        if self.defect == "dispatch-deletes-key":
            self.records.clear()
        output = bytes([status])
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "applet_error", status)


@pytest.mark.parametrize("defect,needle", [(None, None), ("subcommand-before-protocol", "exact isolated outcome"),
    ("public-read-requires-MAC", "exact isolated outcome"), ("dispatch-deletes-key", "CTAP success")])
def test_protocol_subcommand_and_unused_field_products(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "PIN-commands", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["pin-command-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:25]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:25]
