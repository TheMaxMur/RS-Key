# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk bench — on-device crypto latency, immune to XIP-cache/layout noise.

Steady-state EC latency on the RP2350 is code-layout sensitive: the hot working
set (e.g. the variable-base P-256 scalar-mul, ~34 KB) overflows the 16 KB XIP
cache, so an innocent code move shifts which lines evict and the number swings
±~30 ms. A host-timed mean over a few USB round-trips then fakes a regression —
which is exactly how a false "-33%" nearly sank the 0.14 EC migration.

This drives the firmware `bench` vendor command (INS 0x14, build `--features
bench`): the device times a primitive with its own timer (no USB jitter) and
returns a robust summary — a `median`/`MAD` over the warm samples plus a separate
`cold` first sample (the ~1.4× cold-cache op after a power-cycle). To A/B two
builds: measure + `--save a.json`, flash the other build, measure + `--save
b.json`, then `rsk bench --compare a.json b.json`.

Requires a `--features bench` image (never shipped). Reachable over CCID like the
other vendor commands; the ECDH run takes a few seconds (one blocking APDU)."""
import argparse
import json

from . import ccid

INS_BENCH = 0x14
SUMMARY_LEN = 20

# Selector name -> (P1, human label). Mirrors rsk_fido::bench::run.
PRIMITIVES = {
    "ecdh": (0, "variable-base P-256 ECDH (clientPIN key agreement)"),
    "sign": (1, "P-256 comb sign (getAssertion hot path)"),
    "ratchet": (2, "HKDF-SHA512 key-derivation ratchet"),
}


def register(sub):
    p = sub.add_parser(
        "bench",
        help="on-device crypto latency (median/MAD + cold), needs a --features bench image",
    )
    p.add_argument(
        "primitive",
        nargs="?",
        choices=sorted(PRIMITIVES),
        help="which hot path to time",
    )
    p.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="samples dropped from the warm stats (default 1: excludes the cold sample)",
    )
    p.add_argument("--save", metavar="FILE", help="write the summary as JSON")
    p.add_argument("--label", help="annotation stored with --save (e.g. a build id)")
    p.add_argument(
        "--compare",
        nargs=2,
        metavar=("BASELINE.json", "CANDIDATE.json"),
        help="print an A/B verdict between two saved summaries (no device needed)",
    )
    p.set_defaults(func=run)


# ---- pure helpers (unit-tested in test_bench.py) ----------------------------


def parse_summary(data):
    """Decode the 20-byte device Summary (five little-endian u32, microseconds)."""
    if len(data) != SUMMARY_LEN:
        raise ValueError(f"expected {SUMMARY_LEN} summary bytes, got {len(data)}")
    n, cold, mn, median, mad = (
        int.from_bytes(data[i : i + 4], "little") for i in range(0, SUMMARY_LEN, 4)
    )
    return {"n": n, "cold": cold, "min": mn, "median": median, "mad": mad}


def us_to_ms(us):
    return us / 1000.0


def cold_ratio(summary):
    """Cold-cache penalty as a multiple of the warm median (None if no warm data)."""
    median = summary["median"]
    return summary["cold"] / median if median else None


def ab_verdict(baseline, candidate, k=3.0):
    """Is the candidate's warm median a real shift from the baseline's?

    Significant when the median delta exceeds `k` pooled MADs. The +1 µs floor
    keeps two perfectly-stable runs (MAD 0) from flagging a 1 µs jitter as real."""
    delta = candidate["median"] - baseline["median"]
    threshold = k * (baseline["mad"] + candidate["mad"] + 1)
    significant = abs(delta) > threshold
    if not significant:
        direction = "no change"
    elif delta < 0:
        direction = "improvement"
    else:
        direction = "regression"
    return {
        "delta_us": delta,
        "threshold_us": threshold,
        "significant": significant,
        "direction": direction,
    }


# ---- device + rendering -----------------------------------------------------


def measure(sel, warmup, conn=None):
    if conn is None:
        conn = ccid.connect()
    ccid.select(conn, ccid.VENDOR_AID)
    data, s1, s2 = ccid.transmit(conn, [0x00, INS_BENCH, sel, warmup & 0xFF, 0x00])
    if (s1, s2) != ccid.SW_OK:
        raise SystemExit(
            f"bench command failed (SW {s1:02X}{s2:02X}). Is this a `--features bench` image?"
        )
    return parse_summary(data)


def _print_summary(name, label, summary):
    print(f"{name}  ({label})   n={summary['n']} warm")
    print(f"  cold   {us_to_ms(summary['cold']):8.1f} ms   (first op — cold XIP cache)")
    print(f"  median {us_to_ms(summary['median']):8.1f} ms")
    print(f"  min    {us_to_ms(summary['min']):8.1f} ms")
    print(f"  MAD    {us_to_ms(summary['mad']):8.1f} ms   (spread; large = cache-refill straddle)")
    ratio = cold_ratio(summary)
    if ratio is not None:
        print(f"  cold/warm {ratio:.2f}x")


def _print_compare(a, b):
    va = ab_verdict(a["summary"], b["summary"])
    for tag, rec in (("baseline", a), ("candidate", b)):
        s = rec["summary"]
        lbl = f" [{rec['label']}]" if rec.get("label") else ""
        print(f"{tag}{lbl}: median {us_to_ms(s['median']):.1f} ms   MAD {us_to_ms(s['mad']):.1f} ms")
    verb = "SIGNIFICANT" if va["significant"] else "within noise —"
    print(
        f"Δ median {us_to_ms(va['delta_us']):+.1f} ms  "
        f"(threshold ±{us_to_ms(va['threshold_us']):.1f} ms)  →  {verb} {va['direction']}"
    )


def run(args):
    if args.compare:
        with open(args.compare[0]) as f:
            a = json.load(f)
        with open(args.compare[1]) as f:
            b = json.load(f)
        _print_compare(a, b)
        return
    if not args.primitive:
        raise SystemExit("give a primitive (ecdh|sign|ratchet) or --compare A.json B.json")
    sel, label = PRIMITIVES[args.primitive]
    summary = measure(sel, args.warmup)
    _print_summary(args.primitive, label, summary)
    if args.save:
        with open(args.save, "w") as f:
            json.dump({"primitive": args.primitive, "label": args.label, "summary": summary}, f)
        print(f"saved → {args.save}")
