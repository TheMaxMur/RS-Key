# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Durable observations; transport timing excludes JSON serialization."""
import json
import math
import os
import platform
import statistics
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

SCHEMA_VERSION = 1
MAX_EXACT_INTEGER = 2**53 - 1
MAX_EVENT_BYTES = 16 * 1024 * 1024


class CaptureError(RuntimeError):
    """Capture integrity failed; issuing further requests is unsafe."""


class Outcome(str, Enum):
    COMPLETED = "completed"
    HOST_REJECTED = "host_rejected"
    DEADLINE = "deadline"
    DISCONNECTED = "disconnected"
    CANCELLED = "cancelled"
    RUNNER_ERROR = "runner_error"


class SessionStart(str, Enum):
    OPEN = "first_after_session_open"
    RECONNECT = "first_after_reconnect"
    RESET = "first_after_card_reset"
    REPORTED_POWER = "first_after_operator_reported_power_cycle"
    EMULATED_POWER = "first_after_emulated_power_cycle"


class TransferError(Exception):
    def __init__(self, message, outcome=Outcome.RUNNER_ERROR, protocol="no_response", code=None):
        super().__init__(message)
        self.outcome, self.protocol, self.code = outcome, protocol, code
        self.transmitted = False


@dataclass
class Reply:
    data: bytes
    protocol: str = "success"
    status: object = None
    timing: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.protocol in ("success", "applet_error") and isinstance(self.status, int) and self.status >> 8 == 0x61:
            self.protocol = "response_continuation"

    @property
    def is_rejection(self):
        return self.protocol in ("applet_error", "transport_error")


def json_value(value):
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, Enum):
        return json_value(value.value)
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_EXACT_INTEGER:
        return {"type": "integer", "decimal": str(value)}
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {key: json_value(item) for key, item in value.items()}
        return {"type": "map", "entries": [[json_value(k), json_value(v)] for k, v in value.items()]}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [json_value(item) for item in value]
        return {"type": "set", "values": sorted(items, key=lambda item: json.dumps(item, sort_keys=True))}
    if isinstance(value, float) and not math.isfinite(value):
        return {"type": "float", "value": str(value)}
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise TypeError(f"unsupported trace value: {type(value).__name__}")


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(json_value(value), stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class Trace:
    def __init__(self, directory, metadata, clock=time.monotonic_ns):
        self.directory = Path(directory)
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700)
        self.clock, self.origin = clock, clock()
        self.run_id = str(uuid.uuid4())
        self.sequence = self.exchange_count = 0
        self.case = None
        self.sample = 0
        self.sample_role = "measured"
        self.phase = "probe"
        self.exchanges, self.cases = [], []
        self._step_counts = {}
        self._session_calls = {}
        self._session_starts = {}
        self.closed = False
        self.metadata = {
            "schema_version": SCHEMA_VERSION, "run_id": self.run_id,
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "clock": "host_monotonic", "clock_resolution_ns": int(time.get_clock_info("monotonic").resolution * 1e9),
            "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
            "flush_policy": "fsync before each request and after its result",
            "capture_detail_mode": "raw events buffered during API; JSON and fsync outside the measured call",
            **metadata,
        }
        atomic_json(self.directory / "manifest.json", self.metadata)
        fd = os.open(self.directory / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.stream = os.fdopen(fd, "w", encoding="utf-8")
        self.emit("run_started", metadata=self.metadata)
        self.flush()

    def now(self):
        value = self.clock() - self.origin
        if not 0 <= value <= MAX_EXACT_INTEGER:
            raise CaptureError("monotonic clock outside the run's exact integer range")
        return value

    def mark_session(self, session_id, start):
        if not isinstance(start, SessionStart):
            raise ValueError("session start must identify a typed observed boundary")
        self._session_calls[session_id] = 0
        self._session_starts[session_id] = start
        self.emit("timing_session_boundary", session_id=session_id, population=start.value)

    def emit(self, record_type, **payload):
        if self.closed:
            raise CaptureError("capture already closed")
        self.sequence += 1
        event = {
            "schema_version": SCHEMA_VERSION, "record_type": record_type,
            "run_id": self.run_id, "event_id": f"event-{self.sequence}",
            "sequence": self.sequence, "time_ns": self.now(),
            "scenario_id": self.case, "sample": self.sample, **payload,
        }
        try:
            encoded = json.dumps(json_value(event), allow_nan=False, separators=(",", ":"))
            if len(encoded.encode()) > MAX_EVENT_BYTES:
                raise CaptureError("trace event too large")
            self.stream.write(encoded + "\n")
        except (OSError, ValueError, TypeError) as error:
            raise CaptureError(f"cannot persist trace event: {error}") from error
        return event

    def flush(self):
        try:
            self.stream.flush()
            os.fsync(self.stream.fileno())
        except OSError as error:
            raise CaptureError(f"cannot flush capture: {error}") from error

    def exchange(self, session_id, layer, command, request, timeout, transfer):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.exchange_count += 1
        exchange_id = f"exchange-{self.exchange_count}"
        operation_id = f"{self.case or 'session'}:{self.sample}"
        journal_start = self.now()
        ordinal = self._session_calls.get(session_id, 0)
        population = self._session_starts.get(session_id, SessionStart.OPEN).value if ordinal == 0 else "subsequent_session_call"
        self._session_calls[session_id] = ordinal + 1
        started = self.emit(
            "exchange_started", exchange_id=exchange_id, operation_id=operation_id,
            session_id=session_id, observation_layer=layer, phase=self.phase,
            command=command, request={"hex": request.hex(), "length": len(request)},
            timeout_ns=int(timeout * 1e9),
            sample_role=self.sample_role, session_call_population=population,
        )
        self.flush()
        io_events = []
        observer_duration = 0

        def observe(direction, data, timestamp=None, **fields):
            nonlocal observer_duration
            observer_start = self.now()
            io_events.append({"direction": direction, "_data": bytes(data),
                              "observed_ns": observer_start if timestamp is None else timestamp,
                              **fields})
            observer_duration += self.now() - observer_start

        t0 = self.now()
        deadline = t0 + int(timeout * 1e9)
        reply = error = None
        interrupted = None
        try:
            reply = transfer(deadline, observe)
            if not isinstance(reply, Reply):
                raise TypeError("transport did not return a Reply")
        except TransferError as failure:
            error = failure
        except (KeyboardInterrupt, SystemExit) as failure:
            interrupted = failure
            error = TransferError(type(failure).__name__, Outcome.CANCELLED)
        except CaptureError:
            raise
        except Exception as failure:
            error = TransferError(f"{type(failure).__name__}: {failure}")
        t1 = self.now()
        timing = {"clock": "host_monotonic", "call_start_ns": t0, "call_end_ns": t1,
                  "api_duration_ns": t1 - t0, "deadline_ns": deadline,
                  "tx_complete_ns": None, "first_rx_ns": None, "final_rx_ns": None,
                  "response_latency_ns": None}
        if reply:
            timing.update(reply.timing)
            if reply.protocol != "no_response_expected":
                timing["response_latency_ns"] = t1 - t0
        for event in io_events:
            raw = event.pop("_data")
            self.emit("io_event", exchange_id=exchange_id, session_id=session_id,
                      observation_layer=layer, hex=raw.hex(), length=len(raw), **event)
        step_key = (self.case, self.sample)
        step = self._step_counts.get(step_key, 0)
        self._step_counts[step_key] = step + 1
        result = {
            "exchange_id": exchange_id, "operation_id": operation_id,
            "scenario_id": self.case, "sample": self.sample, "phase": self.phase,
            "sample_role": self.sample_role, "session_call_population": population,
            "session_id": session_id, "observation_layer": layer,
            "step": step,
            "command": command, "request": started["request"],
            "response": {"hex": reply.data.hex(), "length": len(reply.data)} if reply and reply.protocol != "no_response_expected" else None,
            "status": reply.status if reply else getattr(error, "code", None),
            "timing": timing,
            "execution_outcome": error.outcome.value if error else Outcome.COMPLETED.value,
            "protocol_outcome": error.protocol if error else reply.protocol,
            "error": str(error) if error else None,
            "transmission_evidence": "observed_tx" if any(e["direction"] == "tx" for e in io_events) else "unknown",
            "side_effect_status": "unknown" if error else "not_assessed",
        }
        self.exchanges.append(result)
        self.emit("exchange_finished", **result)
        self.flush()
        journal_end = self.now()
        overhead = {"request_start_ns": journal_start, "request_end_ns": t0, "request_duration_ns": t0 - journal_start,
                    "response_start_ns": t1, "response_end_ns": journal_end, "response_duration_ns": journal_end - t1,
                    "runner_observer_duration_ns": observer_duration,
                    "scope": "journal encoding and fsync outside API; observer estimate inside API; this overhead record/flush excluded"}
        result["capture_overhead"] = overhead
        self.emit("exchange_capture_overhead", exchange_id=exchange_id, overhead=overhead)
        self.flush()
        if interrupted:
            raise interrupted
        if error:
            error.transmitted = result["transmission_evidence"] == "observed_tx"
            raise error
        return reply

    def finish(self, outcome="completed", **extra):
        if self.closed:
            return
        self.emit("run_finished", execution_outcome=outcome, **extra)
        self.flush()
        atomic_json(self.directory / "results.json", {
            "schema_version": SCHEMA_VERSION, "run_id": self.run_id,
            "execution_outcome": outcome, "cases": self.cases, "exchanges": self.exchanges,
            "statistics": summarize(self.exchanges), **extra,
        })
        self.stream.close()
        self.closed = True


def summarize(exchanges):
    groups = {}
    for exchange in exchanges:
        key = (exchange["scenario_id"], exchange["step"], exchange["command"],
               exchange["execution_outcome"], exchange["protocol_outcome"], str(exchange["status"]),
               exchange["observation_layer"], exchange.get("sample_role", "measured"),
               exchange.get("session_call_population", "unrecorded"))
        groups.setdefault(key, []).append(exchange)
    result = []
    for key, rows in groups.items():
        completed = [r for r in rows if r["timing"]["response_latency_ns"] is not None]
        values = sorted(r["timing"]["response_latency_ns"] for r in completed)
        median = statistics.median(values) if values else None
        result.append({
            "scenario_id": key[0], "step": key[1], "command": key[2],
            "execution_outcome": key[3], "protocol_outcome": key[4], "status": rows[0]["status"],
            "observation_layer": key[6], "n": len(rows), "response_count": len(values),
            "sample_role": key[7], "session_call_population": key[8],
            "censored_count": sum(r["execution_outcome"] == "deadline" for r in rows),
            "min_ns": min(values) if values else None, "median_ns": median,
            "mad_ns": statistics.median(abs(v - median) for v in values) if values else None,
            "p95_ns": values[math.ceil(len(values) * .95) - 1] if len(values) >= 100 else None,
            "p99_ns": values[math.ceil(len(values) * .99) - 1] if len(values) >= 1000 else None,
            "samples": [r["exchange_id"] for r in rows],
        })
    return result


def recover(directory):
    directory = Path(directory)
    def invalid_constant(value):
        raise ValueError(f"nonfinite JSON constant: {value}")

    with (directory / "manifest.json").open(encoding="utf-8") as stream:
        manifest = json.load(stream, parse_constant=invalid_constant)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION or not isinstance(manifest.get("run_id"), str):
        raise CaptureError("unsupported manifest schema")
    events, warning = [], None
    with (directory / "events.jsonl").open("rb") as stream:
        while True:
            line = stream.readline(MAX_EVENT_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_EVENT_BYTES:
                raise CaptureError("trace record exceeds the size limit")
            if not line.endswith(b"\n"):
                warning = "truncated final record"
                break
            try:
                event = json.loads(line, parse_constant=invalid_constant)
            except (ValueError, UnicodeError) as error:
                raise CaptureError("invalid complete JSONL record") from error
            index = len(events) + 1
            if (not isinstance(event, dict) or event.get("schema_version") != SCHEMA_VERSION or event.get("run_id") != manifest["run_id"]
                    or event.get("sequence") != index or event.get("event_id") != f"event-{index}"):
                raise CaptureError("trace schema, identity, or sequence mismatch")
            if (not isinstance(event.get("record_type"), str) or type(event.get("time_ns")) is not int
                    or event["time_ns"] < (events[-1]["time_ns"] if events else 0)):
                raise CaptureError("invalid record type or nonmonotonic event time")
            events.append(event)
    if any(e["record_type"] == "run_finished" for e in events[:-1]):
        raise CaptureError("events appended after run completion")
    starts = {}
    for event in events:
        if event["record_type"] == "exchange_started":
            if event["exchange_id"] in starts:
                raise CaptureError("duplicate exchange start")
            starts[event["exchange_id"]] = event
    finished = [e for e in events if e["record_type"] == "exchange_finished"]
    seen = set()
    for exchange in finished:
        exchange_id = exchange["exchange_id"]
        if exchange_id not in starts or exchange_id in seen:
            raise CaptureError("finished exchange without a unique start")
        seen.add(exchange_id)
        if starts[exchange_id]["sequence"] >= exchange["sequence"]:
            raise CaptureError("exchange finished before its start")
        for field in ("scenario_id", "sample", "session_id", "observation_layer", "command", "phase"):
            if exchange[field] != starts[exchange_id][field]:
                raise CaptureError("exchange scope changed between start and finish")
        for field in ("sample_role", "session_call_population"):
            if exchange.get(field) != starts[exchange_id].get(field):
                raise CaptureError("exchange timing population changed between start and finish")
        if exchange["request"] != starts[exchange_id]["request"]:
            raise CaptureError("exchange request changed between start and finish")
        for field_name in ("request", "response"):
            value = exchange[field_name]
            if value is not None:
                try:
                    valid = len(bytes.fromhex(value["hex"])) == value["length"]
                except (ValueError, TypeError, KeyError) as error:
                    raise CaptureError("invalid trace byte representation") from error
                if not valid:
                    raise CaptureError("trace byte length mismatch")
        timing = exchange["timing"]
        if (not all(isinstance(timing[field], int) and timing[field] >= 0 for field in ("call_start_ns", "call_end_ns", "api_duration_ns"))
                or timing["call_end_ns"] - timing["call_start_ns"] != timing["api_duration_ns"]):
            raise CaptureError("inconsistent exchange timing")
    by_id = {exchange["exchange_id"]: exchange for exchange in finished}
    overhead_ids = set()
    for event in events:
        if event["record_type"] != "exchange_capture_overhead":
            continue
        identifier, overhead = event.get("exchange_id"), event.get("overhead", {})
        if identifier not in by_id or identifier in overhead_ids or not isinstance(overhead, dict):
            raise CaptureError("capture overhead lacks unique completed exchange evidence")
        overhead_ids.add(identifier)
        for prefix in ("request", "response"):
            values = [overhead.get(prefix + "_" + field + "_ns") for field in ("start", "end", "duration")]
            if not all(type(value) is int and value >= 0 for value in values) or values[1] - values[0] != values[2]:
                raise CaptureError("inconsistent capture overhead interval")
        if (overhead.get("request_end_ns") != by_id[identifier]["timing"]["call_start_ns"]
                or overhead.get("response_start_ns") != by_id[identifier]["timing"]["call_end_ns"]
                or type(overhead.get("runner_observer_duration_ns")) is not int
                or not 0 <= overhead["runner_observer_duration_ns"] <= by_id[identifier]["timing"]["api_duration_ns"]
                or event["sequence"] <= by_id[identifier]["sequence"] or event["time_ns"] < overhead["response_end_ns"]):
            raise CaptureError("capture overhead does not bound its measured API")
        by_id[identifier]["capture_overhead"] = overhead
    cases = [e["result"] for e in events if e["record_type"] == "scenario_finished"]
    for case in cases:
        expected = [e["exchange_id"] for e in finished if (e["scenario_id"], e["sample"]) == (case["scenario_id"], case["sample"])]
        if case["exchanges"] != expected or any(item not in by_id for item in case["exchanges"]):
            raise CaptureError("scenario exchange evidence mismatch")
    completed = bool(events and events[-1]["record_type"] == "run_finished") and not warning
    return {"schema_version": SCHEMA_VERSION, "run_id": manifest["run_id"], "manifest": manifest,
            "execution_outcome": events[-1]["execution_outcome"] if completed else "incomplete",
            "warning": warning, "unfinished_exchanges": sorted(set(starts) - seen),
            "cases": cases,
            "exchanges": finished, "statistics": summarize(finished),
            "coverage": events[-1].get("coverage") if completed else None}
