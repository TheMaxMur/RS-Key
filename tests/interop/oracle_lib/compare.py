# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Offline comparison never opens a transport."""
import fnmatch
import json
import math

from .trace import CaptureError, recover


def load_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("rules must be a JSON array")
    for rule in rules:
        if (not isinstance(rule, dict) or rule.get("mode") not in ("ignore", "presence", "tolerance")
                or not isinstance(rule.get("path"), str) or not rule.get("reason")):
            raise ValueError("each rule needs path, mode, and a reason")
        if rule["mode"] == "tolerance" and (not isinstance(rule.get("absolute"), (int, float))
                or isinstance(rule["absolute"], bool) or not math.isfinite(rule["absolute"]) or rule["absolute"] < 0):
            raise ValueError("tolerance requires a finite nonnegative absolute bound")
    return rules


def compare(left_directory, right_directory, rules=(), max_slowdown=None):
    if max_slowdown is not None and (not math.isfinite(max_slowdown) or max_slowdown < 1):
        raise ValueError("max slowdown must be finite and at least 1")
    left, right = recover(left_directory), recover(right_directory)
    rules = load_rules(list(rules))
    rows = []

    def difference(path, a, b, missing=False, presence=False):
        if not missing and a == b:
            return
        rule = next((rule for rule in rules if fnmatch.fnmatchcase(path, rule["path"])), None)
        if not missing and not presence and rule is None:
            if isinstance(a, dict) and isinstance(b, dict):
                if a.get("type") == b.get("type") == "map":
                    a = {json.dumps(key, sort_keys=True, separators=(",", ":")): value for key, value in a["entries"]}
                    b = {json.dumps(key, sort_keys=True, separators=(",", ":")): value for key, value in b["entries"]}
                if a.get("type") not in ("bytes", "integer", "float", "set") and b.get("type") not in ("bytes", "integer", "float", "set"):
                    for key in sorted(set(a) | set(b)):
                        difference(path + "." + key, a.get(key), b.get(key), missing=key not in a or key not in b)
                    return
            if isinstance(a, list) and isinstance(b, list):
                for index in range(max(len(a), len(b))):
                    difference(path + f".{index}", a[index] if index < len(a) else None,
                               b[index] if index < len(b) else None, missing=index >= min(len(a), len(b)))
                return
        allowed = presence and not missing
        if rule:
            if rule["mode"] == "ignore":
                allowed = True
            elif rule["mode"] == "presence":
                allowed = not missing
            elif (not missing and isinstance(a, (float, int)) and isinstance(b, (float, int))
                  and not isinstance(a, bool) and not isinstance(b, bool)):
                allowed = abs(a - b) <= rule["absolute"]
        rows.append({"path": path, "left": a, "right": b,
                     "classification": "allowed_difference" if allowed else "unexpected_difference",
                     "reason": rule["reason"] if rule else "declared variable observation" if allowed else None})

    for label, run in (("left", left), ("right", right)):
        if run["execution_outcome"] != "completed" or run["unfinished_exchanges"]:
            rows.append({"path": f"capture.{label}", "classification": "not_comparable", "reason": "incomplete capture"})
    for field in ("seed", "suites", "script_sha256", "runner_sha256", "warmups", "foreign_reference_inputs_sha256"):
        difference("manifest." + field, left["manifest"].get(field), right["manifest"].get(field))

    def cases(run):
        result = {}
        for case in run["cases"]:
            key = (case["scenario_id"], case["sample"])
            if key in result:
                raise CaptureError("duplicate scenario invocation")
            result[key] = case
        return result

    a_cases, b_cases = cases(left), cases(right)
    timing_compatible = all(left["manifest"].get(field) == right["manifest"].get(field)
        for field in ("seed", "suites", "script_sha256", "warmups", "foreign_reference_inputs_sha256", "backend", "host", "versions", "capture_detail_mode"))
    if not timing_compatible:
        rows.append({"path": "timing.context", "classification": "not_comparable",
                     "reason": "fixture, warmup, backend or host context differs"})
    matched, excluded = 0, 0
    incompatible_cases = set()
    for key in sorted(set(a_cases) | set(b_cases)):
        path = f"cases.{key[0]}.{key[1]}"
        if key not in a_cases or key not in b_cases:
            present = a_cases.get(key) or b_cases.get(key)
            if present["applicability"] in ("excluded_by_mode", "excluded_by_profile"):
                excluded += 1
                continue
            difference(path, a_cases.get(key), b_cases.get(key), missing=True)
            continue
        a, b = a_cases[key], b_cases[key]
        initial_difference = len(rows)
        incompatible = [field for field in ("scenario_revision", "parameters", "coverage_method", "sample_role") if a.get(field) != b.get(field)]
        if incompatible:
            incompatible_cases.add(key[0])
            rows.append({"path": path, "classification": "not_comparable",
                         "reason": "scenario contract differs: " + ", ".join(incompatible)})
            continue
        for field in ("verdict", "applicability"):
            difference(path + "." + field, a[field], b[field])
        neutral = a["applicability"] == b["applicability"] and a["applicability"] in ("excluded_by_mode", "excluded_by_profile", "unsupported_confirmed")
        if neutral:
            excluded += 1
            continue
        if a["verdict"] != "pass" or b["verdict"] != "pass":
            rows.append({"path": path, "classification": "not_comparable",
                         "reason": "one or both scenarios did not pass their checks"})
        elif a["exchanges"] and b["exchanges"]:
            matched += 1
        for name in sorted(set(a["observations"]) | set(b["observations"])):
            av, bv = a["observations"].get(name), b["observations"].get(name)
            difference(path + ".observations." + name,
                       av["value"] if av else None, bv["value"] if bv else None,
                       missing=av is None or bv is None,
                       presence=bool(av and bv and av["comparison"] == bv["comparison"] == "presence"))
        a_ex = [e for e in left["exchanges"] if (e["scenario_id"], e["sample"]) == key]
        b_ex = [e for e in right["exchanges"] if (e["scenario_id"], e["sample"]) == key]
        difference(path + ".exchange_count", len(a_ex), len(b_ex))
        for index, (ae, be) in enumerate(zip(a_ex, b_ex)):
            for field in ("command", "observation_layer", "execution_outcome", "protocol_outcome", "status"):
                difference(f"{path}.exchanges.{index}.{field}", ae[field], be[field])
        for index, (aa, ba) in enumerate(zip(a["assertions"], b["assertions"])):
            difference(f"{path}.assertions.{index}.name", aa["name"], ba["name"])
            difference(f"{path}.assertions.{index}.verdict", aa["verdict"], ba["verdict"])
        difference(path + ".assertion_count", len(a["assertions"]), len(b["assertions"]))
        if any(row["classification"] != "allowed_difference" for row in rows[initial_difference:]):
            incompatible_cases.add(key[0])
    timings = []
    if not matched:
        rows.append({"path": "capture.coverage", "classification": "not_comparable", "reason": "no matched executed scenarios"})

    def groups(run):
        return {(row["scenario_id"], row["step"], row["command"], row["execution_outcome"], row["protocol_outcome"],
                 str(row["status"]), row["observation_layer"], row["session_call_population"]): row for row in run["statistics"] if row["sample_role"] == "measured"}

    a_groups, b_groups = groups(left), groups(right)
    complete = all(run["execution_outcome"] == "completed" and not run["unfinished_exchanges"] for run in (left, right))
    for key in sorted(set(a_groups) & set(b_groups), key=str):
        if key[0] in incompatible_cases or not timing_compatible or not complete:
            continue
        a, b = a_groups[key], b_groups[key]
        ratio = b["median_ns"] / a["median_ns"] if a["median_ns"] and b["median_ns"] is not None else None
        row = {"scenario_id": key[0], "step": key[1], "command": key[2], "status": a["status"],
               "observation_layer": key[6], "left_n": a["response_count"], "right_n": b["response_count"],
               "session_call_population": key[7],
               "left_median_ns": a["median_ns"], "right_median_ns": b["median_ns"],
               "right_over_left": ratio, "left_censored": a["censored_count"], "right_censored": b["censored_count"]}
        timings.append(row)
        if max_slowdown is not None and ratio is not None and ratio > max_slowdown:
            rows.append({"path": f"timing.{key[0]}.{key[1]}.{key[2]}", "classification": "unexpected_difference",
                         "left": a["median_ns"], "right": b["median_ns"], "reason": f"median slowdown {ratio:.3f} exceeds {max_slowdown}"})
    return {"left": left["run_id"], "right": right["run_id"], "differences": rows,
            "timing": timings, "timing_caveat": "Host API latency includes transport, scheduling, Python overhead and operator wait; sample state is recorded in manifests.",
            "matched_cases": matched, "excluded_cases": excluded,
            "unexpected": sum(row["classification"] == "unexpected_difference" for row in rows),
            "not_comparable": sum(row["classification"] == "not_comparable" for row in rows),
            "allowed": sum(row["classification"] == "allowed_difference" for row in rows)}
