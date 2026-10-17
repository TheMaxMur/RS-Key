# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Report observed portions of matrix families without claiming full coverage."""
import hashlib
import re
from pathlib import Path


def coverage(cases):
    matrix = Path(__file__).parents[1] / "oracle-plan.md"
    if not matrix.is_file():
        return {"matrix": None, "warning": "matrix document unavailable", "families": []}
    data = matrix.read_bytes()
    catalog = re.findall(r"^\| ([A-Z]+\d{2}) \| ([^|]+) \|", data.decode(), re.MULTILINE)
    families = []
    for family, title in catalog:
        rows = [case for case in cases if family in case["families"]]
        executed = [row for row in rows if row["exchanges"]]
        planned = rows and all(row["applicability"] == "not_run" for row in rows)
        families.append({"family": family, "title": title.strip(),
                         "coverage": "partially_exercised" if executed else "implemented_not_run" if planned else "blocked" if rows else "not_implemented",
                         "invocations": len(rows), "executed": len(executed),
                         "passed": sum(row["verdict"] == "pass" for row in rows),
                         "failed": sum(row["verdict"] == "fail" for row in rows),
                         "coverage_methods": sorted({row.get("coverage_method", "explicit") for row in rows}),
                         "scenarios": sorted({row["scenario_id"] for row in rows}),
                         "reasons": sorted({row["reason"] for row in rows if row["reason"]})})
    section = re.search(r"(?ms)^## 14\. Additional external-device profiles\n(.*?)^## 15\.", data.decode())
    external_section = section[1] if section else ""
    external = [{"profile": name.strip(), "vendor_catalog_status": "unknown",
                 "reason": "model/firmware catalog unresolved; SELECT or shared-protocol cases do not establish vendor coverage"}
                for name in re.findall(r"^\| ([^|]+) \|", external_section, re.MULTILINE)
                if name.strip() not in ("Profile", "---")]
    return {"matrix": matrix.name, "sha256": hashlib.sha256(data).hexdigest(), "external_profiles": external,
            "meaning": "Family links identify tested portions, never complete family coverage.", "families": families}
