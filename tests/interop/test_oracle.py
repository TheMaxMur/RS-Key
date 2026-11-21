# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Evidence integrity, framing, deadline, binding, and oracle fault controls."""
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from oracle_lib import codec, transport
from oracle_lib.compare import compare
from oracle_lib.runner import Options, Session, SCENARIO_REVISION
from oracle_lib.trace import CaptureError, Outcome, Reply, Trace, TransferError, recover, summarize


class Clock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        self.value += 1000
        return self.value


class FakeCard:
    layer = "pcsc_apdu"

    def __init__(self, reply=b"\x90\x00", error=None):
        self.reply, self.error = reply, error
        self.calls = []

    def transfer(self, request, deadline, observe):
        self.calls.append(request)
        observe("tx", request)
        if self.error:
            raise self.error
        observe("rx", self.reply)
        status = int.from_bytes(self.reply[-2:], "big")
        return Reply(self.reply, "success" if status == 0x9000 else "applet_error", status)


def recorded(path, response=b"\x90\x00", variable=False, clock=None):
    trace = Trace(path, {"backend": "synthetic"}, clock or Clock())
    session = Session(trace, card=FakeCard(response))
    with session.case("piv.read", ("P01",)):
        reply = session.apdu(b"\x00\xfd\x00\x00")
        session.observe("response", reply.data, "presence" if variable else "exact")
    trace.finish()
    return trace


def test_capture_recovery_and_private_permissions(tmp_path):
    trace = recorded(tmp_path / "run")
    result = recover(trace.directory)
    assert result["execution_outcome"] == "completed"
    assert len(result["exchanges"]) == 1
    timing = result["exchanges"][0]["timing"]
    assert timing["api_duration_ns"] > 0
    assert timing["first_rx_ns"] is None
    assert os.stat(trace.directory).st_mode & 0o777 == 0o700
    for name in ("events.jsonl", "manifest.json", "results.json"):
        assert os.stat(trace.directory / name).st_mode & 0o777 == 0o600


def test_exchange_steps_keep_sample_scope_without_rescanning_capture_history(tmp_path):
    class AppendOnly(list):
        def __iter__(self):
            raise AssertionError("exchange recorder rescanned prior history")
    trace = Trace(tmp_path / "step-scope", {}, Clock())
    trace.exchanges = AppendOnly()
    scopes = ((None, 0), ("first", 0), ("other", 0), ("first", 0), ("first", 1), ("first", 0), ("first", 1))
    for name, sample in scopes:
        trace.case, trace.sample = name, sample
        trace.exchange("hid", "hid_report", "PING", b"", 1, lambda deadline, observe: Reply(b"echo"))
    rows = trace.exchanges[:]
    assert [(row["scenario_id"], row["sample"]) for row in rows] == list(scopes)
    assert [row["step"] for row in rows] == [0, 0, 0, 1, 0, 2, 1]
    trace.exchanges = rows
    trace.finish()


@pytest.mark.parametrize("field,value", [("scenario_revision", SCENARIO_REVISION + 1), ("parameters", {"bound": 3}), ("coverage_method", "different product")])
def test_comparator_excludes_changed_contract_from_results_and_timing(tmp_path, field, value):
    left, right = recorded(tmp_path / "left"), recorded(tmp_path / "right")
    path = right.directory / "events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    next(row for row in events if row["record_type"] == "scenario_finished")["result"][field] = value
    path.write_text("".join(json.dumps(row) + "\n" for row in events))
    result = compare(left.directory, right.directory)
    assert result["not_comparable"] >= 1 and result["matched_cases"] == 0 and result["timing"] == []
    assert any("scenario contract differs" in row.get("reason", "") for row in result["differences"])


def test_interrupted_request_is_not_success(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    trace.emit("exchange_started", exchange_id="pending", request={"hex": "00", "length": 1})
    trace.flush()
    trace.stream.write('{"truncated":')
    trace.stream.close()
    result = recover(trace.directory)
    assert result["execution_outcome"] == "incomplete"
    assert result["unfinished_exchanges"] == ["pending"]
    assert result["warning"] == "truncated final record"


@pytest.mark.parametrize("defect", ["sequence", "run_id", "length", "timing", "request", "scope", "evidence", "nonfinite"])
def test_corrupt_capture_is_refused(tmp_path, defect):
    trace = recorded(tmp_path / "run")
    path = trace.directory / "events.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    finished = next(row for row in records if row["record_type"] == "exchange_finished")
    if defect == "sequence":
        finished["sequence"] += 1
    elif defect == "run_id":
        finished["run_id"] = "foreign"
    elif defect == "length":
        finished["response"]["length"] += 1
    elif defect == "timing":
        finished["timing"]["api_duration_ns"] += 1
    elif defect == "request":
        finished["request"]["hex"] = "01"
    elif defect == "scope":
        finished["sample"] = 99
    elif defect == "nonfinite":
        finished["timing"]["api_duration_ns"] = float("nan")
    else:
        next(row for row in records if row["record_type"] == "scenario_finished")["result"]["exchanges"] = []
    path.write_text("".join(json.dumps(row) + "\n" for row in records))
    with pytest.raises(CaptureError):
        recover(trace.directory)


def test_timeout_is_censored_and_does_not_retry_or_cleanup(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    card = FakeCard(error=TransferError("lost write response", Outcome.DEADLINE))
    session = Session(trace, card=card, options=Options(exercise=True))
    with session.case("write", effects=("write",)):
        try:
            session.apdu(b"\x00\xdb\x00\x00")
        finally:
            assert session.broken
    with session.case("after-unknown"):
        session.apdu(b"\x00\xfd\x00\x00")
    trace.finish()
    assert len(card.calls) == 1
    assert trace.cases[0]["verdict"] == "fail"
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"
    sample = trace.exchanges[0]
    assert sample["execution_outcome"] == "deadline"
    assert sample["timing"]["response_latency_ns"] is None
    assert summarize([sample])[0]["censored_count"] == 1
    assert summarize([sample])[0]["median_ns"] is None


def test_no_unrequested_fixture_write(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    card = FakeCard()
    session = Session(trace, card=card)
    with session.case("fixture", effects=("write",)):
        session.apdu(b"\x00\xdb\x00\x00")
    trace.finish()
    assert not card.calls
    assert trace.cases[0]["applicability"] == "excluded_by_mode"


def test_refused_pin_is_not_retried_after_reselection(tmp_path):
    trace = Trace(tmp_path / "run", {})
    card = FakeCard(b"\x63\xc2")
    session = Session(trace, card=card)
    session.applet = "piv"
    for name in ("first", "second"):
        with session.case(name):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x80, data=b"wrong\xff\xff\xff")))
    trace.finish()
    assert len(card.calls) == 1
    assert trace.cases[0]["verdict"] == "fail"
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"


def test_pin_guard_recognizes_unique_shortened_aid(tmp_path):
    trace = Trace(tmp_path / "run", {})
    card = FakeCard()
    session = Session(trace, card=card)
    with session.case("piv.short-select"):
        session.apdu(codec.apdu(0xA4, 4, data=bytes.fromhex("a00000030800001000")))
        session.check("short AID identifies PIV", session.applet, "piv")
        session.card_value(session.apdu(codec.apdu(0x20, p2=0x80, data=b"123456\xff\xff")))
    with session.case("ambiguous.select"):
        session.apdu(codec.apdu(0xA4, 4, data=bytes.fromhex("a000000527")))
        session.apdu(codec.apdu(0x20, p2=0x80, data=b"123456\xff\xff"))
    trace.finish()
    assert len(card.calls) == 3
    assert trace.cases[0]["verdict"] == "pass"
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"


def test_send_only_cancel_has_no_fabricated_response_time(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    trace.exchange("hid", "hid_report", "cancel", b"", 1,
                   lambda deadline, observe: Reply(b"", "no_response_expected"))
    trace.finish()
    result = trace.exchanges[0]
    assert result["response"] is None
    assert result["timing"]["response_latency_ns"] is None
    assert result["timing"]["api_duration_ns"] > 0


def test_malformed_response_stops_following_mutations(tmp_path):
    trace = Trace(tmp_path / "run", {})
    card = FakeCard(error=TransferError("invalid frame", protocol="malformed_response"))
    session = Session(trace, card=card, options=Options(exercise=True))
    with session.case("invalid-response"):
        session.apdu(bytes.fromhex("00fd0000"))
    with session.case("no-following-write", effects=("write",)):
        session.apdu(bytes.fromhex("00db0000"))
    trace.finish()
    assert len(card.calls) == 1
    assert session.broken
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"


def test_trezor_vendor_and_card_paths_never_reach_device(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    card = FakeCard()

    class Fido:
        layer = "hid_report"

        def transfer(self, *args):
            raise AssertionError("forbidden command reached wallet device")

    session = Session(trace, card=card, hid=Fido(), profile="trezor", options=Options(exercise=True))
    with session.case("wallet-vendor"):
        session.ctap(0x41, {1: 3})
    with session.case("wallet-card"):
        session.apdu(b"\x00\x1f\x01\x00")
    with session.case("wallet-pin-change"):
        session.ctap(6, {1: 2, 2: 4})
    trace.finish()
    assert not card.calls
    assert all(row["execution_outcome"] == "host_rejected" for row in trace.exchanges)
    assert all(row["transmission_evidence"] == "unknown" for row in trace.exchanges)


def test_compare_detects_status_defect_and_respects_narrow_rule(tmp_path):
    a = recorded(tmp_path / "a")
    b = recorded(tmp_path / "b", b"\x6a\x80")
    result = compare(a.directory, b.directory)
    assert result["unexpected"] >= 1
    assert any(row["path"].endswith(".status") for row in result["differences"])
    equal = compare(a.directory, a.directory)
    assert equal["unexpected"] == equal["not_comparable"] == 0
    c = recorded(tmp_path / "c", b"\x01\x90\x00")
    allowed = compare(a.directory, c.directory, [{"path": "*.observations.response", "mode": "presence", "reason": "device identity"}])
    assert allowed["unexpected"] == 0 and allowed["allowed"] == 1


def test_comparing_incomplete_capture_is_not_green(tmp_path):
    trace = recorded(tmp_path / "run")
    path = trace.directory / "events.jsonl"
    path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    report = compare(trace.directory, trace.directory)
    assert report["not_comparable"] == 2
    assert report["timing"] == []


def test_comparison_of_only_excluded_cases_is_not_green(tmp_path):
    trace = Trace(tmp_path / "run", {}, Clock())
    session = Session(trace, card=FakeCard())
    with session.case("not-requested", effects=("write",)):
        session.apdu(bytes.fromhex("00db0000"))
    trace.finish()
    result = compare(trace.directory, trace.directory)
    assert result["matched_cases"] == 0 and result["excluded_cases"] == 1
    assert result["not_comparable"] == 1


def test_timing_threshold_detects_slowdown_only_when_requested(tmp_path):
    class SlowClock(Clock):
        def __call__(self):
            self.value += 10000
            return self.value

    fast = recorded(tmp_path / "fast")
    slow = recorded(tmp_path / "slow", clock=SlowClock())
    descriptive = compare(fast.directory, slow.directory)
    assert descriptive["unexpected"] == 0
    assert descriptive["timing"][0]["right_over_left"] == 10
    enforced = compare(fast.directory, slow.directory, max_slowdown=2)
    assert enforced["unexpected"] == 1
    assert enforced["differences"][0]["path"].startswith("timing.")


def test_property_rule_cannot_hide_a_neighboring_capability_defect(tmp_path):
    def captured(path, maximum, resident):
        trace = Trace(path, {}, Clock())
        session = Session(trace, card=FakeCard())
        with session.case("getinfo"):
            session.apdu(bytes.fromhex("00fd0000"))
            session.observe("capabilities", {4: {"rk": resident}, 5: maximum})
        trace.finish()
        return trace.directory

    reference = captured(tmp_path / "reference", 1536, True)
    candidate = captured(tmp_path / "candidate", 7609, False)
    rule = [{"path": "*.observations.capabilities.5", "mode": "tolerance", "absolute": 6073, "reason": "profile message limit"}]
    result = compare(reference, candidate, rule)
    assert result["allowed"] == result["unexpected"] == 1
    defect = next(row for row in result["differences"] if row["classification"] == "unexpected_difference")
    assert defect["path"].endswith("capabilities.4.rk")


def test_codec_preserves_duplicates_and_rejects_truncation():
    encoded = bytes.fromhex("a2014100014101")
    assert codec.decode(encoded, lossless=True)["entries"] == [(1, b"\x00"), (1, b"\x01")]
    with pytest.raises(ValueError, match="duplicate"):
        codec.decode(encoded)
    for value in (b"\x5a\xff\xff\xff\xff", b"\xa1", b"\x61\xff", b"\x00\x00"):
        with pytest.raises(ValueError):
            codec.decode(value)
    assert codec.parse_tlv(bytes.fromhex("710161710162")) == [(0x71, b"a"), (0x71, b"b")]
    with pytest.raises(ValueError):
        codec.parse_tlv(bytes.fromhex("71820100"))


def test_apdu_encoding_boundaries():
    assert codec.apdu(0x84, le=256) == bytes.fromhex("0084000000")
    assert codec.apdu(0x84, le=257) == bytes.fromhex("00840000000101")
    assert codec.apdu(0xDA, data=b"a" * 256)[:7] == bytes.fromhex("00da0000000100")


class Frames:
    def __init__(self, frames):
        self.frames, self.writes = list(frames), []

    def write(self, frame):
        self.writes.append(frame)
        return len(frame)

    def read(self, length, timeout):
        return self.frames.pop(0) if self.frames else b""


@pytest.mark.parametrize("sequence", [0, 1])
def test_raw_hid_records_keepalive_and_validates_continuations(sequence):
    cid = bytes.fromhex("01020304")
    frames = Frames([
        (cid + bytes.fromhex("bb000102")).ljust(64, b"\x00"),
        (cid + bytes.fromhex("81003a") + b"a" * 57),
        (cid + bytes([sequence]) + b"b").ljust(64, b"\x00"),
    ])
    clock = Clock()
    hid = transport.Hid({}, clock, frames)
    hid.cid = cid
    events = []
    if sequence:
        with pytest.raises(TransferError, match="continuation sequence"):
            hid.transfer(1, b"x" * 58, 1000000000, lambda *a, **k: events.append((a, k)))
    else:
        reply = hid.transfer(1, b"x" * 58, 1000000000, lambda *a, **k: events.append((a, k)))
        assert reply.data == b"a" * 57 + b"b"
        assert reply.timing["first_rx_ns"] < reply.timing["final_rx_ns"]
        assert reply.timing["tx_complete_ns"] == events[1][0][2]
        assert reply.timing["first_rx_ns"] == events[2][0][2]
        assert reply.timing["first_final_rx_ns"] == events[3][0][2]
        assert reply.timing["final_rx_ns"] == events[4][0][2]
    assert len(frames.writes) == 2
    assert frames.writes[0][1:8] == bytes.fromhex("0102030481003a")
    assert len(events) == 5


def _hanging_pcsc(pipe, reader):
    pipe.send(("ready", b"\x3b\x00"))
    pipe.recv()
    pipe.send(("started", time.monotonic_ns()))
    time.sleep(30)


def test_pcsc_deadline_terminates_worker(monkeypatch):
    monkeypatch.setattr(transport, "_pcsc_worker", _hanging_pcsc)
    origin = time.monotonic_ns()
    clock = lambda: time.monotonic_ns() - origin
    card = transport.Pcsc("synthetic reader", clock, origin)
    try:
        with pytest.raises(TransferError, match="deadline"):
            card.transfer(b"\x00", clock() + 30000000, lambda *a, **k: None)
        assert not card.process.is_alive()
        assert card.broken
    finally:
        card.close()


def test_ambiguous_hid_selection_is_refused():
    devices = [{"id": "a", "path_hex": "01", "serial_number": "same"},
               {"id": "b", "path_hex": "02", "serial_number": "same"}]
    with pytest.raises(ValueError, match="matched 2"):
        transport.select_hid(devices, "same")
    assert transport.select_hid(devices, "a") is devices[0]
