# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Expand ordinary suite entry points without opening a transport or writing a trace."""
from .coverage import coverage
from .fido import SUPPORTED_ALGORITHMS
from .runner import Options, Session


class PlanTrace:
    def __init__(self):
        self.case = None
        self.sample = 0
        self.phase = "probe"
        self.cases, self.exchanges = [], []

    def emit(self, record_type, **payload):
        return payload

    def now(self):
        return 0

    def flush(self):
        pass


def catalog(profile, suites, execute, seed="rs-key-oracle-v1", *, foreign_references=()):
    trace = PlanTrace()
    session = Session(trace, profile=profile, options=Options(seed=seed, foreign_references=foreign_references))
    session.planning = True
    session.values["fido.info"] = {10: [{"alg": value} for value in SUPPORTED_ALGORITHMS]}
    execute(session, suites)
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if failures:
        raise ValueError("catalog expansion failed: " + str(failures))
    rows = [{key: row[key] for key in ("scenario_id", "scenario_revision", "families", "effects", "parameters", "coverage_method", "applicability", "reason")}
            for row in trace.cases]
    if len({row["scenario_id"] for row in rows}) != len(rows):
        raise ValueError("duplicate scenario identity in catalog")
    return {"profile": profile, "suites": list(suites), "seed": seed, "mode": "offline_catalog",
            "expansion_basis": "potential algorithm cases; actual support requires device evidence",
            "cases": rows, "coverage": coverage(trace.cases)}
