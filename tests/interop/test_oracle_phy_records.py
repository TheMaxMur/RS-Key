# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""One-byte PHY overlay behavior is checked against a separate field walk and key."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec, phy_records
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_rescue import Card as RescueCard


class Card(RescueCard):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.fields = {0: bytes.fromhex("1209f1d2"), 4: b"\x11", 5: b"\xff", 6: bytes(2), 8: b"\x1e",
            9: b"Oracle test key\x00", 10: b"\xff" * 4, 11: b"\x1f", 12: b"\x03", 13: b"\x00", 14: b"\x01", 15: b"Oracle\x00"}
        self.writes = []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0x1c and p1 == 1:
            self.writes.append(data)
            original, source, changed = dict(self.fields), memoryview(data), set()
            while len(source) >= 2:
                tag, length = source[0], source[1]
                if len(source) < 2 + length:
                    if self.defect == "atomic-rejects-valid-prefix":
                        self.fields = original
                    break
                value, source = bytes(source[2:2 + length]), source[2 + length:]
                if self.defect == "first-duplicate-wins" and tag in changed:
                    continue
                if tag in (0, 10) and length == 4 or tag == 6 and length == 2 or tag in (4, 5, 8, 11, 12, 13, 14) and length == 1:
                    self.fields[tag] = value
                    changed.add(tag)
                elif tag in (9, 15) and 1 <= length <= 33:
                    text = value.partition(b"\x00")[0]
                    if len(text) > 32:
                        continue
                    if self.defect == "rejects-opaque-UTF8":
                        try:
                            text.decode()
                        except UnicodeDecodeError:
                            continue
                    if text:
                        self.fields[tag] = text + b"\x00"
                    elif self.defect != "NUL-cannot-clear":
                        self.fields.pop(tag, None)
                    changed.add(tag)
            if self.defect == "PHY-replaces-device-key":
                self.key = ec.derive_private_key(43, ec.SECP256K1())
            output = b"\x90\x00"
        elif ins == 0x1e and p1 == 1:
            output = b"".join(bytes([tag, len(value)]) + value for tag, value in sorted(self.fields.items())) + b"\x90\x00"
        else:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0x9000)


@pytest.mark.parametrize("defect,needle", [(None, None), ("first-duplicate-wins", "first truncated TLV"),
    ("atomic-rejects-valid-prefix", "first truncated TLV"), ("rejects-opaque-UTF8", "first truncated TLV"),
    ("NUL-cannot-clear", "first truncated TLV"), ("PHY-replaces-device-key", "InvalidSignature")])
def test_every_PHY_field_uses_actual_overlay_and_retained_private_key(tmp_path, defect, needle):
    card = Card(defect)
    original = dict(card.fields)
    trace = Trace(tmp_path / "PHY-records", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    oracle.execute(session, ["phy-records"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:30]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:30]
        assert card.fields == original


def test_an_absent_numeric_PHY_field_needs_a_known_effective_restore_value(tmp_path):
    card = Card()
    card.fields.pop(4)
    trace = Trace(tmp_path / "PHY-no-guessed-default", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    with session.case("missing GPIO restore", effects=("config_change",)):
        before = phy_records.read(session)
        with phy_records.fixture(session, before, {**before, 4: b"\xff"}):
            pytest.fail("absent hardware default must block before a write")
    assert not card.writes
    session.options.phy_defaults = phy_records.defaults({"04": "11"})
    with session.case("known GPIO restore", effects=("config_change",)):
        before = phy_records.read(session)
        with phy_records.fixture(session, before, {**before, 4: b"\xff"}):
            session.card_value(session.apdu(codec.apdu(0x1c, 1, data=b"\x04\x01\xff", cla=0x80)))
    trace.finish()
    assert card.fields[4] == b"\x11"
    assert trace.cases[0]["applicability"] == "blocked_by_precondition" and trace.cases[1]["verdict"] == "pass"


@pytest.mark.parametrize("defect", [None, "connection-loses-PHY"])
def test_PHY_record_and_private_key_survive_every_connection_action(tmp_path, defect):
    class PersistentCard(Card):
        emulated = True
        def control(self, action, deadline, observe):
            if defect:
                self.fields[6] = bytes(2)
            return Reply(b"offline ATR")
    card = PersistentCard()
    original = dict(card.fields)
    trace = Trace(tmp_path / "PHY-persistence", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True, allow_effects=("config_change", "reboot")))
    oracle.execute(session, ["phy-persistence"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("each complete PHY field survives" in reason for reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert card.fields == original


@pytest.mark.parametrize("value", [None, [], {"4": "11"}, {"99": "00"}, {"04": "0011"}, {"04": 17}])
def test_PHY_defaults_reject_ambiguous_or_wrong_width_profile_values(value):
    with pytest.raises(ValueError):
        phy_records.defaults(value)
