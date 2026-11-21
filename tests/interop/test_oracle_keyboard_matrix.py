# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Stored raw material generates independent boot reports with explicit faults."""
import pytest

import oracle
from oracle_lib import keyboard
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Trace, TransferError
from test_oracle_otp_commands import Peer


class Keyboard:
    def __init__(self, peer, session):
        self.peer, self.session = peer, session

    def reports(self, deadline, emit):
        slot = self.session.current.parameters["slot"]
        config = self.peer.slots[slot]
        material = config[:38]
        if self.peer.defect == "static-types-access-code":
            material += config[38:44]
        if self.peer.defect == "TAB-flags-emit-prefix" and config[46] & 1:
            material = b"\x2b" + material
        if config[46] & 32:
            material += b"\x28"
        sent = False
        for index, value in enumerate(material):
            if value & 127:
                sent = True
                modifier = 0 if self.peer.defect == "static-shift-lost" else 2 if value & 128 else 0
                emit(bytes([modifier, 0, value & 127, 0, 0, 0, 0, 0]), self.session.trace.now())
                if self.peer.defect != "static-last-release-lost" or index != len(material) - 1:
                    emit(bytes(8), self.session.trace.now())
        if not sent:
            raise TransferError("synthetic observation reached its deadline without reports", Outcome.DEADLINE)


@pytest.mark.parametrize("defect,needle", [(None, None), ("static-types-access-code", "access-code leakage"),
    ("TAB-flags-emit-prefix", "invented TAB prefixes"), ("static-shift-lost", "access-code leakage"),
    ("static-last-release-lost", "key held")])
def test_static_lengths_flags_modifiers_and_all_four_slot_gestures(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-static-keyboard", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, operator=True, allow_effects=("otp_extra_slots",)))
    session.keyboard = Keyboard(peer, session)
    oracle.execute(session, ["keyboard-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.slots


def test_keyboard_decoder_partial_capture_and_shifted_punctuation(tmp_path):
    press = bytes([2, 0, 0x1e, 0, 0, 0, 0, 0])
    assert keyboard.decode([press, bytes(8)])[0] == "!"
    with pytest.raises(ValueError, match="key held"):
        keyboard.decode([press])
    assert keyboard.decode([press], allow_held=True) == ("!", [(2, 0x1e)])
    trace = Trace(tmp_path / "partial-keyboard", {})
    session = Session(trace, options=Options(operator=True))
    class Reports:
        def reports(self, deadline, emit):
            emit(press, trace.now())
            pytest.fail("capture limit must stop before requesting more reports")
    session.keyboard = Reports()
    with session.case("partial-observation", ("Y11",)):
        frames, times, start = keyboard.listen(session, "one declared press", max_reports=1)
        session.check("only actually observed reports are retained", frames, [press])
        session.check("captured timestamp follows observation start", times[0] >= start)
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases


@pytest.mark.parametrize("continuous,expected", [(False, 2), (True, 4)])
def test_native_keyboard_full_window_retains_separate_gestures_beyond_the_idle_cutoff(continuous, expected):
    class Clock:
        now = 0
        def __call__(self):
            return self.now
    clock = Clock()
    class Backend:
        def read(self, size, timeout):
            clock.now += 100000000
            return {100000000: b"\x00\x00\x04\x00\x00\x00\x00\x00", 200000000: bytes(8),
                2500000000: b"\x00\x00\x05\x00\x00\x00\x00\x00", 2600000000: bytes(8)}.get(clock.now, b"")
    native = keyboard.Keyboard({}, clock, Backend())
    frames = []
    native.reports(4000000000, lambda frame, timestamp: frames.append(frame), until_deadline=continuous)
    assert len(frames) == expected
    assert keyboard.decode(frames)[0] == ("ab" if continuous else "a")
