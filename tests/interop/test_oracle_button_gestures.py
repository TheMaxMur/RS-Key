# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A sensor/keyboard rig models input and output independently of scenario labels."""
import threading

import pytest

import oracle
from oracle_lib import button_gestures
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_otp_commands import Peer


class Clock:
    value = 0

    def __call__(self):
        return self.value

    def advance(self, value):
        self.value = max(self.value, value)


class Job:
    def __init__(self, driver, edges, start, deadline):
        self.driver, self.deadline, self.done = driver, deadline, threading.Event()
        self.edges = [(start + offset * 1000000, pressed) for offset, pressed in edges]
        self.consumed, self.cancelled = False, False

    def release(self, deadline):
        self.edges.append((self.driver.clock() + 50000000, False))

    def wait_edge(self, ordinal, deadline):
        self.driver.clock.advance(self.edges[ordinal - 1][0])

    def finish(self, deadline):
        self.driver.clock.advance(self.edges[-1][0])
        raw = {"source": self.driver.source, "initial_pressed": False, "final_pressed": False,
            "edges": [{"pressed": pressed, "lower_ns": at, "upper_ns": at} for at, pressed in self.edges],
            "sampled_edge_ms": [at // 1000000 for at, _ in self.edges]}
        self.done.set()
        return raw

    def cancel(self):
        self.cancelled = True


class Driver:
    def __init__(self, clock, source):
        self.clock, self.source = clock, source
        self.current, self.jobs = None, []
        self.ready = threading.Event()

    def describe(self):
        return {"source": self.source, "instrument_id": "offline-sensor-model", "host_clock": "trace.monotonic_origin", "schedule_tolerance_ns": 0}

    def start(self, edges, start, deadline):
        self.current = Job(self, edges, start, deadline)
        self.jobs.append(self.current)
        self.clock.advance(start)
        self.ready.set()
        return self.current

    def close(self):
        for job in self.jobs:
            job.cancel()


class Keyboard:
    continuous = True

    def __init__(self, peer, driver, fault):
        self.peer, self.driver, self.fault = peer, driver, fault
        self.suppress_next = False

    def reports(self, deadline, emit, *, until_deadline=False):
        assert until_deadline
        assert self.driver.ready.wait(1), "stimulus did not start"
        self.driver.ready.clear()
        job = self.driver.current
        assert job.done.wait(1), "stimulus did not release"
        outputs = []
        if job.consumed:
            if self.fault == "consumed-press-types":
                outputs.append((job.edges[-1][0] + 1001000000, 1))
            self.suppress_next = self.fault == "suppression-is-permanent"
        elif self.suppress_next:
            pass
        else:
            pressed, count, last = False, 0, None
            for at, down in job.edges:
                if last is not None and count and at > last + 1000000000 and (not pressed or self.fault == "fires-while-held"):
                    outputs.append((last + 1001000000, count))
                    count, last = 0, None
                if pressed and not down:
                    included = last is None or at - last < 1000000000 or self.fault == "inclusive-release-gap" and at - last == 1000000000
                    if included:
                        count = (count + 1) % 256 if self.fault == "wraps-click-count" else min(255, count + 1)
                    last = at
                pressed = down
            if count and last is not None:
                outputs.append((last + 1001000000, count))
        for at, slot in outputs:
            config = self.peer.slots.get(slot)
            if config is None:
                continue
            for index, key in enumerate(value for value in config[:38] if value):
                emit(bytes([0, 0, key, 0, 0, 0, 0, 0]), at + index * 2000000)
                emit(bytes(8), at + index * 2000000 + 1000000)
        self.driver.clock.advance(deadline - 500000000 if self.fault == "early-listener-return" else deadline)


class Hid:
    layer = "offline_gesture_hid"
    on_keepalive = on_report = None

    def __init__(self, driver):
        self.driver = driver

    def send_only(self, *args):
        raise AssertionError("gesture model never sends unobserved frames")

    def transfer(self, command, data, deadline, observe):
        if command == 0x10:
            assert data == b"\x0b"
            self.on_keepalive(2, self.driver.clock())
            self.driver.current.consumed = True
            result, status = b"\x00", 0
        else:
            assert command == 1
            self.driver.current.consumed = True
            result, status = data, None
        self.driver.clock.advance(self.driver.clock() + 50000000)
        observe("tx", data)
        observe("rx", result)
        return Reply(result, status=status)


@pytest.mark.parametrize("source,fault,needle", [("device_samples", None, None), ("electrical_sensor", None, None),
    ("device_samples", "inclusive-release-gap", "exact slot sequence"), ("device_samples", "wraps-click-count", "exact slot sequence"),
    ("device_samples", "fires-while-held", "exact slot sequence"), ("device_samples", "consumed-press-types", "cannot type an OTP"),
    ("device_samples", "suppression-is-permanent", "next independent click"), ("device_samples", "early-listener-return", "complete requested window")])
def test_gesture_boundaries_holds_overflow_repeats_and_consumed_press_recovery(tmp_path, source, fault, needle):
    clock, peer = Clock(), Peer()
    driver = Driver(clock, source)
    trace = Trace(tmp_path / "button-gestures", {"execution_environment": "offline_sensor_model"}, clock=clock)
    session = Session(trace, card=peer, hid=Hid(driver), profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=60, allow_effects=("otp_both_slots", "otp_extra_slots")))
    session.keyboard, session.button_stimulus = Keyboard(peer, driver, fault), driver
    oracle.execute(session, ["button-gestures"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and not failures, failures
        inconclusive = [row for row in trace.cases if row["verdict"] == "inconclusive"]
        assert len(inconclusive) == (3 if source == "electrical_sensor" else 0), inconclusive
        assert all("exact firmware sampling" in row["reason"] for row in inconclusive)
    assert not peer.slots
    assert all(job.cancelled for job in driver.jobs)


def test_actuator_ACK_cannot_substitute_for_input_sensor_evidence_before_any_slot_write(tmp_path):
    peer = Peer()
    trace = Trace(tmp_path / "no-invented-edges", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, operator=True,
        allow_effects=("otp_both_slots", "otp_extra_slots")))
    driver = Driver(Clock(), "actuator_ACK")
    session.keyboard, session.button_stimulus = Keyboard(peer, driver, None), driver
    oracle.execute(session, ["button-gestures"])
    trace.finish()
    assert not peer.slots and not driver.jobs and not trace.exchanges
    assert all("not observed button edges" in row["reason"] or "operator interaction" in row["reason"] for row in trace.cases)
