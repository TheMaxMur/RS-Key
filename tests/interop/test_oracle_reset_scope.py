# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A reset witness must notice deletion of a populated neighboring public record."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_states import OathStateCard


class Card(OathStateCard):
    def __init__(self, defect):
        super().__init__()
        self.damage_neighbor, self.selected = defect, None
        self.neighbor = b"populated OpenPGP fixture"

    def transfer(self, request, deadline, observe):
        if request[1] == 0xA4:
            aid = request[5:5 + request[4]]
            self.selected = next(name for name, known in AIDS.items() if aid == known)
        if self.selected == "oath":
            result = super().transfer(request, deadline, observe)
            if request[1:4] == b"\x04\xde\xad" and self.damage_neighbor:
                self.neighbor = b""
            return result
        observe("tx", request)
        if request[1] == 0xA4:
            data = b""
        elif self.selected == "management" and request[1] == 0x1D:
            data = b"\x06" + codec.tlv(2, bytes(4))
        elif self.selected == "piv" and request[1] == 0xF7:
            data = codec.tlv(4, b"public key metadata")
        elif self.selected == "openpgp" and request[1] == 0xCA:
            data = self.neighbor
        else:
            raise AssertionError("unexpected neighboring command")
        observe("rx", data + b"\x90\x00")
        return Reply(data + b"\x90\x00", status=0x9000)


@pytest.mark.parametrize("defect", [False, True])
def test_reset_scope_is_checked_by_ordinary_dispatch(tmp_path, defect):
    trace = Trace(tmp_path / "scope", {})
    card = Card(defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, allow_effects=("config_change", "applet_reset")))
    oracle.execute(session, ["oath-states"])
    trace.finish()
    row = next(row for row in trace.cases if row["scenario_id"] == "oath.transition.reset")
    if defect:
        assert row["verdict"] == "fail" and "preserves observed neighboring state" in row["reason"], row
    else:
        assert row["verdict"] == "pass", row
    assert not card.records
