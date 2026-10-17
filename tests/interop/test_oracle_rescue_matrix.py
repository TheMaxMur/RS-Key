# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Calendar normalization, refusal atomicity and unset state through dispatch."""
from datetime import datetime, timedelta, timezone

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_rescue import Card


class CalendarCard(Card):
    emulated = True

    def control(self, action, deadline, observe):
        if action == "power_cycle":
            self.seconds = None
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        status, value = 0x9000, b""
        if ins == 0x1E and p1 == 4 and self.seconds is not None and self.defect == "ticks-at-boundary":
            self.seconds = (self.seconds + 1) % (2 ** 32)
        if ins == 0x1E:
            if data:
                status = 0x6700
            elif p1 in (0, 5, 9, 255) or p1 == 8 and p2 != 0 or p1 == 4 and p2 not in (1, 2):
                status = 0x6A86
            elif p1 == 4 and self.seconds is None:
                status = 0x6985
            elif p1 == 1:
                value = codec.tlv(6, bytes(2))
            elif p1 == 2:
                counts = [0x80000, 0, 0x80000, 0, 0x200000]
                if self.defect == "bad-flash-totals":
                    counts[0] -= 1
                value = b"".join(item.to_bytes(4, "big") for item in counts)
            elif p1 == 6:
                if self.defect == "no-fuses":
                    status = 0x6400
                else:
                    value = b"\x00\x00\x30"
            elif p1 == 7:
                value = b"\xff\xff"
            else:
                return super().transfer(wire, deadline, observe)
        elif ins == 0x1C and p1 == 2:
            old = self.seconds
            try:
                if p2 not in (1, 2):
                    status = 0x6A86
                elif len(data) != (8 if p2 == 1 else 4):
                    status = 0x6700
                elif p2 == 2:
                    self.seconds = int.from_bytes(data, "big")
                else:
                    year, month, day, _, hour, minute, second = int.from_bytes(data[:2], "big"), *data[2:]
                    if month > 11 or not 1 <= day <= 31 or hour > 23 or minute > 59 or second > 60:
                        raise ValueError("calendar range")
                    date = datetime(year, month + 1, 1, tzinfo=timezone.utc) + timedelta(days=day - 1, hours=hour, minutes=minute, seconds=second)
                    seconds = int(date.timestamp())
                    if not 0 <= seconds <= 0xFFFFFFFF:
                        raise ValueError("epoch range")
                    if self.defect != "civil-noop":
                        self.seconds = seconds
            except (ValueError, OverflowError):
                status = 0x6A80
            if status != 0x9000:
                self.seconds = 0 if self.defect == "bad-write-clears-clock" else old
        elif ins == 0x1C:
            status = 0x6A86
        elif ins == 0x1F:
            status = 0x6700 if data else 0x6A86
        elif ins == 0x20:
            status = 0x6A86
        else:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        response = value + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("civil-noop", "preserves advancing RTC"),
                                           ("bad-write-clears-clock", "preserves advancing RTC"),
                                           ("bad-flash-totals", "flash usage accounting"), ("ticks-at-boundary", None)])
def test_complete_calendar_vectors_through_suite_dispatch(tmp_path, defect, expected):
    trace = Trace(tmp_path / "calendar", {})
    peer = CalendarCard(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, allow_effects=("reboot",)))
    oracle.execute(session, ["rescue-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases


def test_software_emulator_missing_fuses_remains_an_observation_limit(tmp_path):
    trace = Trace(tmp_path / "no-fuses", {})
    session = Session(trace, card=CalendarCard("no-fuses"), profile="rsk", options=Options(exercise=True, allow_effects=("reboot",)))
    oracle.execute(session, ["rescue-matrix"])
    trace.finish()
    assert not [row for row in trace.cases if row["verdict"] == "fail"], trace.cases
    row = next(row for row in trace.cases if row["scenario_id"] == "rescue.READ.selector-6")
    assert row["applicability"] == "excluded_by_mode" and "no rollback fuse observation" in row["reason"]
    assert next(row for row in trace.cases if row["scenario_id"] == "rescue.READ.selector-7")["verdict"] == "pass"
