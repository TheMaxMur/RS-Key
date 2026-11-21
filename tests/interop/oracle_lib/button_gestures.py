# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Timed button inputs need sensor evidence, separate from unsolicited USB output."""
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum
import threading

from . import keyboard
from .hid_sequences import hooks
from .otp_commands import Route, checksum, fixture
from .trace import Outcome, TransferError

CLICK_WINDOW_MS = 1000
SETTLE_NS = 1500000000
ARM_NS = 100000000
OBSERVATION_MARGIN_NS = 250000000
TEXT = {1: "a", 2: "bb", 3: "ccc", 4: "dddd"}


class InputSource(Enum):
    SENSOR = "electrical_sensor"
    SAMPLES = "device_samples"


class Consumption(Enum):
    PRESENCE = "presence-held-through-completion"
    DISPATCH = "command-interrupts-idle-click"


@dataclass(frozen=True)
class Program:
    name: str
    edges: tuple
    slots: tuple
    boundary_gap_ms: int | None = None
    held: bool = False


def programs():
    for clicks in (1, 2, 3, 4, 5, 255, 256, 257):
        yield Program("click-count-" + str(clicks), tuple((200 * index + delta, pressed) for index in range(clicks) for delta, pressed in ((0, True), (100, False))), (clicks,))
    yield Program("long-held-single", ((0, True), (3000, False)), (1,), held=True)
    yield Program("held-across-prior-window", ((0, True), (100, False), (200, True), (1600, False)), (1,))
    yield Program("separate-repeated-gestures", ((0, True), (100, False), (2300, True), (2400, False)), (1, 1))
    for gap in (CLICK_WINDOW_MS - 1, CLICK_WINDOW_MS, CLICK_WINDOW_MS + 1):
        yield Program("release-gap-" + str(gap), ((0, True), (100, False), (200, True), (100 + gap, False)),
            (2 if gap < CLICK_WINDOW_MS else 1,), gap)


class Window:
    def __init__(self, session, duration_ns, purpose="stimulus"):
        self.session, self.frames, self.times, self.error = session, [], [], None
        self.purpose, self.ended = purpose, None
        self.started = session.trace.now()
        self.deadline = self.started + duration_ns
        self.worker = threading.Thread(target=self.collect, daemon=True)

    def collect(self):
        try:
            self.session.keyboard.reports(self.deadline, lambda frame, stamp: (self.frames.append(bytes(frame)), self.times.append(stamp)), until_deadline=True)
        except TransferError as error:
            if error.outcome != Outcome.DEADLINE or self.frames:
                self.error = error
        except BaseException as error:
            self.error = error
        finally:
            self.ended = self.session.trace.now()

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, kind, error, traceback):
        while self.worker.is_alive() and self.session.trace.now() <= self.deadline + 250000000:
            self.worker.join(0.1)
        if self.worker.is_alive():
            self.session.broken = True
            raise TransferError("keyboard observation worker exceeded its bounded window", Outcome.DEADLINE)
        for frame, stamp in zip(self.frames, self.times):
            event = self.session.trace.emit("io_event", session_id="keyboard", exchange_id=None, direction="rx", unsolicited=True,
                observation_layer="hid_report", observed_ns=stamp, hex=frame.hex(), length=len(frame))
            self.session.event_evidence = event["event_id"]
        self.session.observe("gesture_output_window." + self.purpose, {"start_ns": self.started, "deadline_ns": self.deadline,
            "observed_end_ns": self.ended, "report_times_ns": self.times, "device_emission_times_ns": None}, "presence")
        if self.error is not None:
            raise self.error
        self.session.check("keyboard backend observed the complete requested window", self.ended is not None and self.ended >= self.deadline)
        return False


def ready(session):
    session.require(session.profile == "rsk", "multi-click mapping requires RS-Key", "excluded_by_profile")
    session.require(session.options.operator and session.keyboard is not None and session.card is not None, "gesture matrix needs explicit card/keyboard selectors and operator")
    session.require(getattr(session.keyboard, "continuous", False), "gesture matrix requires complete keyboard observation windows", "excluded_by_mode")
    session.require(session.options.timeout > 2, "gesture controls need the full post-release window")
    session.require(session.button_stimulus is not None, "timed gesture matrix requires a sensor-backed button_stimulus from trusted configure(session)")
    session.require(callable(getattr(session.button_stimulus, "start", None)) and callable(getattr(session.button_stimulus, "close", None)),
        "button stimulus needs explicit start and release-on-close operations")
    description = session.button_stimulus.describe()
    session.require(description.get("source") in tuple(value.value for value in InputSource), "actuator acknowledgments/operator reports are not observed button edges")
    session.require(bool(description.get("instrument_id")) and description.get("host_clock") == "trace.monotonic_origin", "stimulus needs identified instrumentation and the trace clock contract")
    tolerance = description.get("schedule_tolerance_ns")
    session.require(type(tolerance) is int and 0 <= tolerance <= 100000000, "declare an input-schedule uncertainty no greater than 100 ms for separated click/hold controls")
    session.observe("button_instrument", description, "presence")


def start_stimulus(session, edges, start, deadline):
    session.trace.emit("interaction", action="button-stimulus", stage="requested", source="runner",
        target_start_ns=start, edges_ms=edges, deadline_ns=deadline, observed_touch_ns=None)
    return session.button_stimulus.start(edges, start, deadline)


def slots(session, stack):
    for slot in TEXT:
        config = bytearray(52)
        config[:slot] = bytes([3 + slot]) * slot
        config[44], config[47] = slot, 0x20
        stack.enter_context(fixture(session, Route.CARD, slot, checksum(config)))


def evidence(session, raw, window, expected_count):
    session.trace.emit("button_input_evidence", evidence=raw, observation_layer="external_input_instrument")
    session.require(isinstance(raw, dict) and raw.get("source") in tuple(value.value for value in InputSource), "input source is not observed sensor/device sampling evidence")
    session.require(raw.get("initial_pressed") is False and raw.get("final_pressed") is False, "button must be observed released before and after the stimulus")
    events = raw.get("edges")
    session.require(isinstance(events, list) and len(events) == expected_count, "stimulus did not observe the complete intended edge count")
    previous = window.started
    for index, edge in enumerate(events):
        low, high = edge.get("lower_ns"), edge.get("upper_ns")
        session.require(type(low) is int and type(high) is int and previous <= low <= high <= window.deadline,
            "input intervals must be ordered, bounded and expressed against the trace origin")
        session.require(edge.get("pressed") is (index % 2 == 0), "observed edges must alternate press/release")
        previous = high
    session.require(window.deadline - events[-1]["upper_ns"] >= SETTLE_NS, "output observation did not include the complete post-release gesture window")
    return events


def idle(session):
    for program in programs():
        with session.case("otp.gesture." + program.name, ("Y12", "Y14", "G11", "G12", "G14"), effects=("otp_both_slots", "otp_extra_slots", "keyboard_output"),
                parameters={"button_edges_ms": program.edges, "boundary_gap_ms": program.boundary_gap_ms, "input_evidence_required": True}):
            ready(session)
            duration = ARM_NS + program.edges[-1][0] * 1000000 + SETTLE_NS + OBSERVATION_MARGIN_NS
            session.require(duration < int(session.options.timeout * 1000000000), "increase timeout for the complete gesture/hold window")
            with ExitStack() as stack:
                slots(session, stack)
                job = None
                with Window(session, duration) as observed:
                    try:
                        job = start_stimulus(session, program.edges, observed.started + ARM_NS, observed.deadline)
                        raw = job.finish(observed.deadline)
                    finally:
                        if job is not None:
                            job.cancel()
                edges = evidence(session, raw, observed, len(program.edges))
                tolerance = session.button_stimulus.describe()["schedule_tolerance_ns"]
                session.require(all(observed.started + ARM_NS + offset * 1000000 - tolerance <= edge["lower_ns"] <= edge["upper_ns"] <= observed.started + ARM_NS + offset * 1000000 + tolerance
                    for (offset, _), edge in zip(program.edges, edges)), "observed input missed its calibrated intended schedule")
                text, presses = keyboard.decode(observed.frames)
                expected = "".join(TEXT.get(slot, "") for slot in program.slots)
                exact = True
                if program.boundary_gap_ms is not None:
                    sampled = raw.get("sampled_edge_ms")
                    exact = InputSource(raw["source"]) == InputSource.SAMPLES and isinstance(sampled, list) and len(sampled) == len(edges) and all(type(value) is int for value in sampled)
                    if exact:
                        session.require(all(left <= right for left, right in zip(sampled, sampled[1:])), "device sample clock must be monotonic")
                        session.require(sampled[-1] - sampled[1] == program.boundary_gap_ms, "actual sampled release gap missed the intended exact boundary")
                        expected = TEXT[2 if sampled[-1] - sampled[1] < CLICK_WINDOW_MS else 1]
                    else:
                        session.check("boundary output stays within the electrical timing uncertainty", text in (TEXT[1], TEXT[2]))
                if exact:
                    session.check("complete observed gesture selects the exact slot sequence without held-key repetition", text, expected)
                if program.held and observed.times:
                    session.check("no keyboard report was observed before the held button's release interval", observed.times[0] >= edges[-1]["lower_ns"])
                session.observe("gesture_result", {"text": text, "presses": presses, "electrical_to_device_sample_latency_ns": None,
                    "exact_boundary_sample_evidence": exact if program.boundary_gap_ms is not None else None}, "presence")
                session.observe("input_to_first_report_interval_ns", [observed.times[0] - edges[0]["upper_ns"], observed.times[0] - edges[0]["lower_ns"]] if observed.times else None, "presence")
                session.require(exact, "electrical edges do not expose exact firmware sampling at this boundary; raw input/output retained")


def consumed(session):
    for mode in Consumption:
        with session.case("otp.gesture.consumed." + mode.value, ("Y12", "Y14", "X05", "G11", "G12", "G14"),
                effects=("otp_both_slots", "otp_extra_slots", "keyboard_output"), touch=True,
                parameters={"dispatch_consumes_pending_clicks": True, "operator_presence": mode}):
            ready(session)
            with hooks(session):
                with ExitStack() as stack:
                    slots(session, stack)
                    job, raw, dispatch = None, None, []
                    with Window(session, int(session.options.timeout * 1000000000)) as observed:
                        try:
                            if mode == Consumption.PRESENCE:
                                def keepalive(status, timestamp):
                                    nonlocal job
                                    if status == 2 and job is None:
                                        job = start_stimulus(session, ((0, True),), session.trace.now() + ARM_NS, observed.deadline)
                                session.hid.on_keepalive = keepalive
                                result = session.ctap(11)
                                session.require(job is not None, "presence-needed stage was not observed; no consumed press is claimed")
                                session.check("held-presence control completed its command", result.status, 0)
                                dispatch = [session.trace.exchanges[-1]["timing"]["call_start_ns"], session.trace.exchanges[-1]["timing"]["call_end_ns"]]
                                job.release(observed.deadline)
                            else:
                                job = start_stimulus(session, ((0, True), (100, False)), observed.started + ARM_NS, observed.deadline)
                                job.wait_edge(2, observed.deadline)
                                result = session.hid_call(1, b"interrupt-idle-click", "gesture.interrupt.PING")
                                session.check("intervening dispatch is a successful real command", result.data, b"interrupt-idle-click")
                                dispatch = [session.trace.exchanges[-1]["timing"]["call_start_ns"], session.trace.exchanges[-1]["timing"]["call_end_ns"]]
                            raw = job.finish(observed.deadline)
                        finally:
                            if job is not None:
                                job.cancel()
                    edges = evidence(session, raw, observed, 2)
                    if mode == Consumption.PRESENCE:
                        session.require(edges[0]["upper_ns"] <= dispatch[1] <= edges[1]["lower_ns"], "sensor evidence did not bracket command completion with the held press")
                    else:
                        session.require(edges[-1]["upper_ns"] <= dispatch[0] and dispatch[1] < edges[-1]["lower_ns"] + CLICK_WINDOW_MS * 1000000,
                            "dispatch missed the unfinished idle-click window")
                    session.check("a press consumed by dispatch cannot type an OTP", keyboard.decode(observed.frames)[0], "")
                    session.observe("consumed_press_dispatch_interval_ns", dispatch, "presence")
                    with Window(session, ARM_NS + 100000000 + SETTLE_NS + OBSERVATION_MARGIN_NS, "fresh-click-control") as control:
                        fresh = start_stimulus(session, ((0, True), (100, False)), control.started + ARM_NS, control.deadline)
                        try:
                            observed_fresh = fresh.finish(control.deadline)
                        finally:
                            fresh.cancel()
                    evidence(session, observed_fresh, control, 2)
                    session.check("the next independent click remains live after the consumed release", keyboard.decode(control.frames)[0], TEXT[1])


def run(session):
    idle(session)
    consumed(session)
