#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Diff two device snapshots (real YubiKey vs RS-Key) into a fidelity report.

Reads the JSON captures `capture.py` writes for each key, flattens every cell's
`parsed` block into one canonical field map per device, and classifies each field
against the allow-list in `divergences.py`:

    MATCH           the two keys agree
    ALLOWED         they differ, but a rule explains it (expected divergence)
    RULE_VIOLATION  a rule matched but the value fell outside it (divergence drifted)
    UNEXPECTED      they differ with no rule — a fidelity gap

Exit status is non-zero if any UNEXPECTED or RULE_VIOLATION field survives — so
this doubles as a CI gate over a recorded pair of snapshots.

    python tests/interop/diff.py real.json rsk.json               # human report
    python tests/interop/diff.py real.json rsk.json --json        # machine-readable
    python tests/interop/diff.py real.json rsk.json --markdown     # docs/interop.md block
"""
import argparse
import json
import sys

try:
    import divergences as dv
except ImportError:  # allow `python tests/interop/diff.py …` from the repo root
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import divergences as dv

# Report order: gaps first so they lead the output.
BUCKET_ORDER = [dv.UNEXPECTED, dv.RULE_VIOLATION, dv.ALLOWED, dv.MATCH]
MARK = {dv.MATCH: "✅", dv.ALLOWED: "➖", dv.RULE_VIOLATION: "⚠️", dv.UNEXPECTED: "❌"}


def flatten(snapshot):
    """Merge every cell's `parsed` block into one {canonical_path: value} map."""
    out = {}
    for cell in snapshot.get("cells", {}).values():
        for path, value in (cell.get("parsed") or {}).items():
            out[path] = value
    return out


def restrict(snapshot, cells):
    """Keep only `cells`, refusing one either snapshot did not capture: skipped on
    both sides, a cell compares zero fields and reports clean; on one, every field
    reads as a gap the device may not have."""
    if not cells:
        sys.exit("--cells names no cell")
    kept = {}
    for name in cells:
        c = snapshot.get("cells", {}).get(name)
        if not c or c.get("status") != "ok":
            label = snapshot.get("meta", {}).get("label", "?")
            state = (c or {}).get("status", "absent")
            sys.exit(f"--cells: {name} is {state} in the {label} snapshot")
        kept[name] = c
    return {**snapshot, "cells": kept}


def compare(real_snap, rsk_snap):
    """Classify the union of canonical fields across the two snapshots."""
    real, rsk = flatten(real_snap), flatten(rsk_snap)
    results = []
    for path in sorted(set(real) | set(rsk)):
        results.append(dv.classify(path, real.get(path, dv.MISSING), rsk.get(path, dv.MISSING)))
    return results


def summarize(results):
    counts = {b: 0 for b in BUCKET_ORDER}
    for r in results:
        counts[r["bucket"]] += 1
    return counts


def _gaps(results):
    return [r for r in results if r["bucket"] in (dv.UNEXPECTED, dv.RULE_VIOLATION)]


def render_text(results, real_snap, rsk_snap):
    rm, km = real_snap.get("meta", {}), rsk_snap.get("meta", {})
    lines = [
        "RS-Key ↔ YubiKey differential",
        f"  real: serial={rm.get('ykman_serial','?')} fw={rm.get('fw','?')} "
        f"aaguid={rm.get('fido_aaguid','?')}",
        f"  rsk : serial={km.get('ykman_serial','?')} fw={km.get('fw','?')} "
        f"bcd={km.get('bcdDevice','?')} aaguid={km.get('fido_aaguid','?')}",
        "",
    ]
    for bucket in BUCKET_ORDER:
        rows = [r for r in results if r["bucket"] == bucket]
        if not rows:
            continue
        lines.append(f"{MARK[bucket]} {bucket} ({len(rows)})")
        # MATCH is voluminous and uninformative — summarize, don't enumerate.
        if bucket == dv.MATCH:
            lines.append("    " + ", ".join(r["path"] for r in rows[:12])
                         + (" …" if len(rows) > 12 else ""))
            lines.append("")
            continue
        for r in rows:
            tail = f"  [{r['reason']}]" if r.get("reason") else ""
            det = f"  ({r['detail']})" if r.get("detail") else ""
            lines.append(f"    {r['path']}: real={r['real']!r} rsk={r['rsk']!r}{det}{tail}")
        lines.append("")
    c = summarize(results)
    lines.append(f"  {c[dv.MATCH]} match, {c[dv.ALLOWED]} allowed, "
                 f"{c[dv.RULE_VIOLATION]} rule-violation, {c[dv.UNEXPECTED]} unexpected")
    return "\n".join(lines)


def render_markdown(results, real_snap, rsk_snap, date=None, host=None):
    """A dated block in the docs/interop.md living-matrix style."""
    rm, km = real_snap.get("meta", {}), rsk_snap.get("meta", {})
    date = date or km.get("date") or "????-??-??"
    host = host or km.get("host_os") or "?"
    c = summarize(results)
    out = [
        f"### Differential — {host}, {date}",
        "",
        f"Real YubiKey (serial `{rm.get('ykman_serial','?')}`, fw `{rm.get('fw','?')}`) vs "
        f"RS-Key (`VIDPID=Yubikey5`, bcd `{km.get('bcdDevice','?')}`, fw `{km.get('fw','?')}`). "
        f"**{c[dv.MATCH]} match · {c[dv.ALLOWED]} expected-divergence · "
        f"{c[dv.RULE_VIOLATION]} rule-violation · {c[dv.UNEXPECTED]} unexpected.**",
        "",
    ]
    gaps = _gaps(results)
    if gaps:
        out += ["| Field | Real | RS-Key | Verdict | Detail |", "|---|---|---|---|---|"]
        for r in gaps:
            out.append(f"| `{r['path']}` | `{r['real']}` | `{r['rsk']}` | {MARK[r['bucket']]} "
                       f"{r['bucket']} | {r.get('detail') or ''} |")
        out.append("")
    else:
        out += ["No unexpected divergences — every difference is a documented, "
                "allow-listed expectation.", ""]
    out += ["<details><summary>Expected divergences (allow-listed)</summary>", ""]
    out += ["| Field | Real | RS-Key | Reason |", "|---|---|---|---|"]
    for r in results:
        if r["bucket"] == dv.ALLOWED:
            out.append(f"| `{r['path']}` | `{r['real']}` | `{r['rsk']}` | {r.get('reason') or ''} |")
    out += ["", "</details>", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="RS-Key ↔ YubiKey snapshot diff")
    ap.add_argument("real", help="snapshot JSON captured from the real YubiKey")
    ap.add_argument("rsk", help="snapshot JSON captured from RS-Key")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--markdown", action="store_true", help="docs/interop.md-style block")
    ap.add_argument("--cells", help="compare only these cells, comma-separated; each must "
                    "have been captured on both sides")
    args = ap.parse_args()

    with open(args.real) as f:
        real_snap = json.load(f)
    with open(args.rsk) as f:
        rsk_snap = json.load(f)

    if real_snap.get("meta", {}).get("label") == rsk_snap.get("meta", {}).get("label"):
        sys.exit("both snapshots carry the same --label; did you capture the same device twice?")

    if args.cells:
        names = [c for c in args.cells.split(",") if c]
        real_snap, rsk_snap = restrict(real_snap, names), restrict(rsk_snap, names)

    results = compare(real_snap, rsk_snap)
    if args.json:
        print(json.dumps({"summary": summarize(results), "fields": results}, indent=2))
    elif args.markdown:
        print(render_markdown(results, real_snap, rsk_snap))
    else:
        print(render_text(results, real_snap, rsk_snap))

    return 1 if _gaps(results) else 0


if __name__ == "__main__":
    sys.exit(main())
