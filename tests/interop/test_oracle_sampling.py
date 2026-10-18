# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Warmups and witnessed session boundaries cannot merge into measured populations."""
import json

import pytest

import oracle
from oracle_lib.compare import compare
from oracle_lib.runner import Session
from oracle_lib.trace import CaptureError, Reply, SessionStart, Trace, recover, summarize
from test_oracle import Clock, FakeCard


def capture(path):
    trace = Trace(path, {"backend": "synthetic", "warmups": 1}, Clock())
    session = Session(trace, card=FakeCard())
    for sample in range(4):
        trace.sample, trace.sample_role = sample, "warmup" if sample == 0 else "measured"
        if sample == 2:
            trace.mark_session("card", SessionStart.REPORTED_POWER)
        with session.case("sample", ("T14",)):
            session.card_value(session.apdu(b"\x00\xfd\x00\x00"))
            session.card_value(session.apdu(b"\x00\xfd\x00\x00"))
    trace.finish()
    return trace.directory


def test_warmups_and_first_calls_keep_separate_raw_populations(tmp_path):
    result = recover(capture(tmp_path / "samples"))
    assert len(result["exchanges"]) == 8
    assert [row["sample_role"] for row in result["cases"]] == ["warmup", "measured", "measured", "measured"]
    assert [row["session_call_population"] for row in result["exchanges"]] == [
        "first_after_session_open", "subsequent_session_call", "subsequent_session_call", "subsequent_session_call",
        "first_after_operator_reported_power_cycle", "subsequent_session_call", "subsequent_session_call", "subsequent_session_call"]
    assert sum(row["n"] for row in result["statistics"] if row["sample_role"] == "warmup") == 2
    assert not any(row["session_call_population"] == "first_after_physical_power_cycle" for row in result["statistics"])


@pytest.mark.parametrize("field,value", [("warmups", 2), ("backend", "physical_usb"), ("seed", "different"), ("foreign_reference_inputs_sha256", "changed"), ("capture_detail_mode", "unbuffered")])
def test_incompatible_sampling_context_cannot_produce_speed_ratios(tmp_path, field, value):
    left, right = capture(tmp_path / "left"), capture(tmp_path / "right")
    manifest = right / "manifest.json"
    metadata = json.loads(manifest.read_text())
    metadata[field] = value
    manifest.write_text(json.dumps(metadata))
    report = compare(left, right)
    assert report["timing"] == [] and any(row["path"] == "timing.context" for row in report["differences"])


def test_timing_population_cannot_be_changed_in_a_finished_exchange(tmp_path):
    path = capture(tmp_path / "samples")
    stream = path / "events.jsonl"
    events = [json.loads(line) for line in stream.read_text().splitlines()]
    next(row for row in events if row["record_type"] == "exchange_finished")["sample_role"] = "measured"
    stream.write_text("".join(json.dumps(row) + "\n" for row in events))
    with pytest.raises(CaptureError, match="population changed"):
        recover(path)


def test_known_populations_and_quantiles_retain_censored_samples():
    rows = []
    for index in range(1000):
        rows.append({"exchange_id": str(index), "scenario_id": "sample", "step": 0, "command": "PING", "status": 0,
            "execution_outcome": "completed", "protocol_outcome": "success", "observation_layer": "synthetic",
            "timing": {"response_latency_ns": index + 1}, "sample_role": "measured"})
    measured = summarize(rows)[0]
    assert (measured["min_ns"], measured["median_ns"], measured["mad_ns"], measured["p95_ns"], measured["p99_ns"]) == (1, 500.5, 250, 950, 990)
    rows += [{**rows[0], "exchange_id": "warmup", "sample_role": "warmup", "timing": {"response_latency_ns": 999999}},
             {**rows[0], "exchange_id": "deadline", "execution_outcome": "deadline", "timing": {"response_latency_ns": None}}]
    populations = summarize(rows)
    assert len(populations) == 3
    censored = next(row for row in populations if row["execution_outcome"] == "deadline")
    assert censored["median_ns"] is None and censored["censored_count"] == 1
    assert next(row for row in populations if row["n"] == 1000) == measured


def test_capture_cli_records_warmup_cycles_before_measured_cycles(tmp_path, monkeypatch):
    class Card(FakeCard):
        atr = b"synthetic"
        def close(self):
            pass
    def probe(session):
        with session.case("sample.cli", ("T14",)):
            session.card_value(session.apdu(b"\x00\xfd\x00\x00"))
    monkeypatch.setattr(oracle, "inventory", lambda: {"hid": [], "readers": ["RS-Key synthetic"]})
    monkeypatch.setattr(oracle, "Pcsc", lambda *args: Card())
    monkeypatch.setitem(oracle.READ_SUITES, "piv", probe)
    monkeypatch.setitem(oracle.EXERCISE_SUITES, "piv", lambda session: None)
    path = tmp_path / "capture"
    assert oracle.main(["capture", "--reader", "RS-Key synthetic", "--suite", "piv", "--out", str(path), "--warmups", "2", "--samples", "3"]) == 0
    result = recover(path)
    cases = [row for row in result["cases"] if row["scenario_id"] == "sample.cli"]
    assert [row["sample_role"] for row in cases] == ["warmup", "warmup", "measured", "measured", "measured"]
    assert result["manifest"]["samples"] == 3 and result["manifest"]["warmups"] == 2
    populations = [row for row in compare(path, path)["timing"] if row["scenario_id"] == "sample.cli"]
    assert len(populations) == 1 and populations[0]["left_n"] == populations[0]["right_n"] == 3


def test_logging_delay_stays_outside_API_latency_and_is_recorded_separately(tmp_path):
    class Clock:
        value = 0
        def __call__(self):
            return self.value
    class Instrumented(Trace):
        def __init__(self, path, scale):
            self.scale, self.manual = scale, Clock()
            super().__init__(path, {}, self.manual)
        def emit(self, *args, **kwargs):
            result = super().emit(*args, **kwargs)
            self.manual.value += self.scale * 100
            return result
        def flush(self):
            super().flush()
            self.manual.value += self.scale * 200
    rows = []
    for scale in (1, 10):
        trace = Instrumented(tmp_path / str(scale), scale)
        def transfer(deadline, observe):
            observe("tx", b"request")
            trace.manual.value += 50
            observe("rx", b"response")
            return Reply(b"response")
        trace.exchange("card", "synthetic", "request", b"request", 1, transfer)
        trace.finish()
        row = recover(trace.directory)["exchanges"][0]
        rows.append(row)
        assert row["timing"]["api_duration_ns"] == row["timing"]["response_latency_ns"] == 50
        assert row["capture_overhead"]["runner_observer_duration_ns"] == 0
    for field in ("request_duration_ns", "response_duration_ns"):
        assert rows[1]["capture_overhead"][field] == rows[0]["capture_overhead"][field] * 10 > 0


def test_corrupt_overhead_cannot_silently_change_timing_evidence(tmp_path):
    path = capture(tmp_path / "overhead")
    stream = path / "events.jsonl"
    events = [json.loads(line) for line in stream.read_text().splitlines()]
    next(row for row in events if row["record_type"] == "exchange_capture_overhead")["overhead"]["request_duration_ns"] += 1
    stream.write_text("".join(json.dumps(row) + "\n" for row in events))
    with pytest.raises(CaptureError, match="overhead interval"):
        recover(path)
