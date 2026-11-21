# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reduce semantic recipes through fresh offline sessions, never replay raw writes."""
import copy
import hashlib
import json
import runpy
from pathlib import Path

from . import oath_sequences
from .runner import Session
from .trace import Trace, atomic_json, recover


def fingerprint(capture, scenario, sample=None):
    cases = [row for row in capture["cases"] if row["scenario_id"] == scenario and row["verdict"] == "fail"
             and (sample is None or row["sample"] == sample)]
    if len(cases) != 1:
        raise ValueError("minimization needs one failed invocation; select --sample when several invocations failed")
    case = cases[0]
    failures = [row for row in case["assertions"] if row["verdict"] == "fail"]
    if not failures:
        raise ValueError("minimization needs a named failed assertion, not a precondition or arbitrary exception")
    failure = failures[0]
    exchange = next((row for row in capture["exchanges"] if row["exchange_id"] == failure["evidence"]), None)
    if exchange is None:
        raise ValueError("failed assertion needs exchange evidence")
    return case, {"scenario_id": scenario, "assertion": failure["name"],
                  "triggering_action": case["observations"].get("sequence_action", {}).get("value"),
                  **{field: exchange[field] for field in ("command", "status", "protocol_outcome", "observation_layer")}}


def minimize(source, scenario, factory_path, destination, max_trials=128, sample=None):
    original = recover(source)
    if original["execution_outcome"] != "completed" or original["unfinished_exchanges"] or original["manifest"].get("profile") != "rsk":
        raise ValueError("minimization requires a complete RS-Key recipe capture; wallet/unknown profiles are excluded")
    case, target = fingerprint(original, scenario, sample)
    recipe = copy.deepcopy(case["parameters"].get("sequence_recipe"))
    oath_sequences.steps(recipe)
    if not 4 <= max_trials <= 4096:
        raise ValueError("max trials must be 4..4096, including original and final confirmation")
    factory_path, destination = Path(factory_path), Path(destination)
    factory_digest = hashlib.sha256(factory_path.read_bytes()).hexdigest()
    factory = runpy.run_path(str(factory_path)).get("make_session")
    if not callable(factory):
        raise ValueError("trusted offline factory must export make_session(trace, seed)")
    destination.mkdir(mode=0o700)
    attempts, session_objects, run_ids = [], [], {original["run_id"]}

    def trial(candidate):
        candidate = copy.deepcopy(candidate)
        try:
            oath_sequences.steps(candidate)
        except (ValueError, TypeError):
            return False
        path = destination / f"trial-{len(attempts):04d}"
        trace = Trace(path, {"profile": "rsk", "backend": "offline_reproducer", "seed": candidate["seed"],
            "recipe": candidate, "factory_sha256": factory_digest, "source_run_id": original["run_id"]})
        session = None
        try:
            session = factory(trace, candidate["seed"])
            if not isinstance(session, Session) or session.trace is not trace or any(session is item for item in session_objects):
                raise ValueError("each trial requires a newly constructed Session bound to its new trace")
            session_objects.append(session)
            if session.profile != "rsk" or session.hid or session.otp_hid or session.keyboard or session.card is None:
                raise ValueError("offline OATH reproducer requires only an RS-Key card session")
            if not (getattr(session.card, "offline", False) or getattr(session.card, "emulated", False)):
                raise ValueError("factory backend must explicitly declare offline or emulated operation")
            oath_sequences.replay(session, candidate, scenario)
        finally:
            if session is not None and isinstance(session, Session):
                session.close()
            trace.finish()
        capture = recover(path)
        if capture["run_id"] in run_ids:
            raise ValueError("reproducer reused a prior capture")
        run_ids.add(capture["run_id"])
        try:
            _, observed = fingerprint(capture, scenario)
        except ValueError:
            observed = None
        matched = observed == target
        attempts.append({"trace": str(path.resolve()), "recipe": candidate, "fingerprint": observed, "same_failure": matched})
        atomic_json(destination / "attempts.json", attempts)
        return matched

    if not trial(recipe):
        raise ValueError("fresh original recipe did not reproduce the same assertion and protocol outcome")
    best, width, minimal = recipe, 2, False
    while best["steps"] and len(attempts) < max_trials - 2:
        size = max(1, (len(best["steps"]) + width - 1) // width)
        reduced = False
        for start in range(0, len(best["steps"]), size):
            if len(attempts) >= max_trials - 2:
                break
            candidate = {**best, "steps": best["steps"][:start] + best["steps"][start + size:]}
            if trial(candidate):
                best, width, reduced = candidate, max(2, width - 1), True
                break
        if not reduced:
            if size == 1:
                minimal = len(attempts) < max_trials - 2
                break
            width = min(len(best["steps"]), width * 2)
    if not best["steps"]:
        minimal = True
    if not trial(best) or not trial(best):
        raise ValueError("shortened recipe did not reproduce the same failure in both fresh confirmation runs")
    result = {"source": str(Path(source).resolve()), "source_run_id": original["run_id"], "source_sample": case["sample"],
        "source_events_sha256": hashlib.sha256((Path(source) / "events.jsonl").read_bytes()).hexdigest(),
        "factory_sha256": factory_digest, "failure": target, "original_recipe": recipe, "minimized_recipe": best,
        "valid_single_step_deletion_minimal": minimal, "trial_budget": max_trials, "trials": attempts,
        "minimized_capture": attempts[-1]["trace"], "mode": "trusted offline factory; no transport discovery or raw replay"}
    atomic_json(destination / "reproducer.json", result)
    return result
