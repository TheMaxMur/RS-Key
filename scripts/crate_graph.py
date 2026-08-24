#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Draw `docs/images/crate-graph.svg` from the workspace manifests.

The picture it replaces was hand-drawn under a footer reading "Source:
workspace Cargo.toml manifests", and by the time anyone measured it the footer
was the only true thing left. It named 17 crates against a 28-member workspace,
so **57 of the 100 manifest edges had an endpoint it could not draw at all**; it
showed seven applets against a registered eight; it still carried
`rsk-piv -> rsk-openpgp`, an edge already deleted; it put `rsk-rsa` in the
platform tier beside `rsk-sdk`; and its note said every applet builds on
`rsk-crypto`, which `rsk-mgmt` and `rsk-vendor` do not. A diagram nothing
regenerates rots exactly like the nine copies of the crate roster did, and reads
as authoritative the whole way down.

So every name, count and note on the drawing is emitted from the manifests
here, and `--check` fails the gate when the committed SVG no longer matches
what they say.

What is *not* generated is the tier each crate sits in: `TIERS` below is the
architecture, written down. The script's job is to hold the tree to it — a
crate missing from `TIERS` (or a `TIERS` name that is not a member) is a hard
failure, so a new crate cannot be silently left out of the picture the way
eleven were; every edge must run into a later band, which is invariant R1; and
`docs/architecture.md` owes the drawing both its alt text and a table row per
member. R2 (applet -> applet is zero) is asserted here too, and the applet band
is held to `deny.toml` — the stanza that *enforces* R2 against a build — so a
ninth applet cannot land in the drawing without also landing in the ban list.

Limits, so the row is not read as more than it is. Only `[dependencies]` count,
a `[target.'cfg(…)'.dependencies]` table included, since that is a runtime edge
like any other. A dev- or build-dependency is not (`rsk-piv` KATs against
`sha2`, `rsk-ec` builds comb tables from `p256`), and folding those in would
make the picture claim edges the firmware does not have — `deny.toml` does see
them, so an applet -> applet *dev*-dependency is caught there rather than here.
Only in-workspace names are drawn; a third-party dependency is `deny.toml`'s
and `cargo vet`'s business. And the bands are a claim about *layering*, not
about what links into a given image — which crates fall outside the default
image is read off `optional = true`, not decided here.
"""

import argparse
import collections
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SVG = ROOT / "docs/images/crate-graph.svg"
#: The page the drawing belongs to. It owes the alt text — a stale one is what
#: told screen readers "seven applet crates" — and a table row per crate.
ALT_PAGE = ROOT / "docs/architecture.md"
DENY = ROOT / "deny.toml"

#: label, subtitle, colour, crates. Order is the architecture: every dependency
#: must point into a *later* band. Order inside a band is horizontal placement
#: only — nothing may depend sideways, so nothing reads it.
TIERS = [
    ("BINARIES", "the two flashable images", "#3E3A36", ["firmware", "rsk-wipe"]),
    ("DISPLAY FLOW", "which screen is shown when — display build only", "#57514A",
     ["rsk-display"]),
    ("DEVICE WIRING", "which applets exist, and how a message reaches one", "#57514A",
     ["rsk-device"]),
    (
        "APPLETS",
        "one AID each — no applet names another",
        "#C0562B",
        [
            "rsk-fido",
            "rsk-openpgp",
            "rsk-piv",
            "rsk-oath",
            "rsk-otp",
            "rsk-mgmt",
            "rsk-rescue",
            "rsk-vendor",
        ],
    ),
    (
        "SHARED RECORDS / UI",
        "a codec more than one applet reads",
        "#2F7E75",
        [
            "rsk-phy",
            "rsk-devconf",
            "rsk-store",
            "rsk-led",
            "rsk-ui",
            "rsk-bip39",
            "rsk-slip39",
            "rsk-bench",
        ],
    ),
    ("TRANSPORTS / STORAGE", "CTAPHID and CCID framing, the flash filesystem", "#2F7E75",
     ["rsk-usb", "rsk-fs"]),
    ("APDU CORE", "parsing, TLV, status words, the Applet seams", "#2F7E75", ["rsk-sdk"]),
    ("CRYPTO FACADE", "the one crate that names a primitive", "#37877E", ["rsk-crypto"]),
    ("ALGORITHMS", "reached by an allowlist, never by every applet", "#4C9086",
     ["rsk-rsa", "rsk-ec", "rsk-sha512", "rsk-mldsa"]),
]

APPLET_LABEL = "APPLETS"
#: A row of `docs/architecture.md`'s per-crate table.
CRATE_ROW = re.compile(r"^\| `(firmware|rsk-[a-z0-9]+)` \|", re.M)


def applet_tier():
    """Derived, so inserting a band above APPLETS cannot silently move R2."""
    return next(i for i, tier in enumerate(TIERS) if tier[0] == APPLET_LABEL)


def read_workspace():
    """(members, edges, firm) — in-workspace runtime `[dependencies]` as a graph.

    `firm` is what a default `cargo build` links: reachable from a flashable
    binary without crossing an `optional = true` edge. The display flow, the two
    mnemonic encoders and the benches are outside it, and the drawing has to say
    so or it claims an image it does not describe.
    """
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    manifests = [
        tomllib.loads((ROOT / rel / "Cargo.toml").read_text())
        for rel in root["workspace"]["members"]
    ]
    names = {m["package"]["name"] for m in manifests}
    edges, always = set(), collections.defaultdict(set)
    for m in manifests:
        src = m["package"]["name"]
        tables = [m.get("dependencies", {})]
        tables += [t.get("dependencies", {}) for t in m.get("target", {}).values()]
        for table in tables:
            for dst, spec in table.items():
                if dst not in names:
                    continue
                edges.add((src, dst))
                if not (isinstance(spec, dict) and spec.get("optional")):
                    always[src].add(dst)
    firm, todo = set(TIERS[0][3]), list(TIERS[0][3])
    while todo:
        for dst in always[todo.pop()] - firm:
            firm.add(dst)
            todo.append(dst)
    return names, edges, firm


def rank(members):
    """crate -> (tier index, index within tier); raises on a roster mismatch."""
    placed = {}
    for ti, (label, _sub, _colour, crates) in enumerate(TIERS):
        for ci, crate in enumerate(crates):
            if crate in placed:
                raise SystemExit(f"FAIL: {crate} is listed in two tiers ({label}).")
            placed[crate] = (ti, ci)
    missing = sorted(members - placed.keys())
    extra = sorted(placed.keys() - members)
    if missing:
        raise SystemExit(
            f"FAIL: workspace members absent from TIERS: {', '.join(missing)}.\n"
            "      A crate this file does not place is a crate the drawing omits."
        )
    if extra:
        raise SystemExit(f"FAIL: TIERS names that are not workspace members: {', '.join(extra)}.")
    return placed


def check_invariants(edges, placed):
    """R1 (strictly downward) and R2 (applet -> applet is zero).

    Band index only, so a same-tier edge fails too: `rsk-fs -> rsk-sdk` and
    `rsk-display -> rsk-device` are the two the tree has, and they are why those
    crates sit in bands of their own rather than sharing one.
    """
    tier = applet_tier()
    sideways = sorted(
        f"{a} -> {b}" for a, b in edges if placed[a][0] == tier and placed[b][0] == tier
    )
    # R2 first: an applet -> applet edge is a same-band edge, so R1 would catch
    # it and report the wrong rule. The specific message names deny.toml, which
    # is where the fix is.
    if sideways:
        raise SystemExit(
            "FAIL: applet -> applet edges (R2), which deny.toml also bans:\n      "
            + "\n      ".join(sideways)
        )
    upward = sorted(f"{a} -> {b}" for a, b in edges if placed[a][0] >= placed[b][0])
    if upward:
        raise SystemExit(
            "FAIL: these dependencies do not point strictly downward (R1):\n      "
            + "\n      ".join(upward)
        )


def check_deny_covers_the_applets():
    """Every applet the drawing shows must be one `cargo deny` also holds.

    The drawing asserting R2 is not the same as R2 being enforced: a ninth
    applet added to `TIERS` alone would be checked here for its manifest edges
    and by nothing at all for a dev-dependency or at build time.
    """
    banned = {entry["crate"] for entry in tomllib.loads(DENY.read_text())["bans"]["deny"]}
    loose = sorted(set(TIERS[applet_tier()][3]) - banned)
    if loose:
        raise SystemExit(
            f"FAIL: {DENY.name} does not ban {', '.join(loose)}.\n"
            "      An applet band member owes a `deny` entry naming its wrappers."
        )


def notes(members, edges, gated):
    """The annotations under the bands, as (plain, markup) chunks to wrap.

    Every one is a measurement, including the ones a reader would take on
    trust: the hand-written note this replaces said all seven applets build on
    `rsk-crypto`, and `rsk-mgmt` and `rsk-vendor` do not.
    """
    applets = TIERS[applet_tier()][3]
    universal = [c for c in sorted(members) if all((a, c) in edges for a in applets)]
    sideways = sum(1 for a, b in edges if a in applets and b in applets)
    # Grouped by parent set: the two hash/PQC backends share one, and a reader
    # wants the allowlist, not four near-identical lines.
    reach = collections.defaultdict(list)
    for crate in TIERS[-1][3]:
        parents = tuple(sorted(a for a, b in edges if b == crate))
        if parents:
            reach[parents].append(crate)

    head = [
        (
            f"applet → applet: {sideways} edges — shared machinery moved below the tier instead.",
            f'applet → applet: <tspan class="notek">{sideways} edges</tspan> —'
            " shared machinery moved below the tier instead.",
        ),
        (
            f"All {len(applets)} applets build on {' · '.join(universal)}.",
            f"All {len(applets)} applets build on "
            + " · ".join(f'<tspan class="notek">{c}</tspan>' for c in universal)
            + ".",
        ),
    ]
    allow = [
        (
            f"{', '.join(crates)} ← {', '.join(parents)}",
            ", ".join(f'<tspan class="notek">{c}</tspan>' for c in crates)
            + f" ← {', '.join(parents)}",
        )
        for parents, crates in sorted(reach.items(), key=lambda kv: kv[1])
    ]
    mark = "† not linked by the default image: " + " · ".join(sorted(gated))
    return sideways, head, allow, [(mark, mark)]


# 11px in the chip's mono stack advances ~6.6px; the pad keeps the widest name
# ("rsk-openpgp") off the rounded corners.
CHAR_W, CHIP_PAD, CHIP_H, CHIP_GAP = 6.6, 20.0, 28.0, 10.0
#: 11px bold with .5px letter-spacing, plus the gap before the subtitle.
TIER_CHAR_W, TIER_SUB_GAP = 8.0, 14
WIDTH, MARGIN = 780, 34


def esc(text):
    """Only the prose needs it — a Cargo package name is `[A-Za-z0-9_-]`."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def band_svg(y, label, sub, colour, crates, gated):
    """One tier: its label, its subtitle, and a centred run of chips."""
    widths = [CHIP_PAD + CHAR_W * len(c) + (9 if c in gated else 0) for c in crates]
    span = sum(widths) + CHIP_GAP * (len(crates) - 1)
    x = (WIDTH - span) / 2
    out = [
        f'  <text class="tier" x="{MARGIN}" y="{y:.0f}">{label}</text>',
        f'  <text class="sub2" x="{MARGIN + TIER_CHAR_W * len(label) + TIER_SUB_GAP:.0f}"'
        f' y="{y:.0f}">{esc(sub)}</text>',
    ]
    for crate, w in zip(crates, widths):
        out.append(
            f'  <rect x="{x:.1f}" y="{y + 8:.0f}" width="{w:.1f}" height="{CHIP_H:.0f}"'
            f' rx="7" fill="{colour}"/>'
        )
        mark = " †" if crate in gated else ""
        out.append(
            f'  <text class="node" x="{x + w / 2:.1f}" y="{y + 27:.0f}"'
            f' text-anchor="middle">{crate}{mark}</text>'
        )
        x += w + CHIP_GAP
    return out, y + 8 + CHIP_H


#: Characters of `.note` text that fit between the card's margins at 10.5px.
#: Under-measures the mono `notek` runs on purpose — a note that overflows the
#: card is the one defect a generated drawing can still ship.
NOTE_BUDGET = 108


def wrap(chunks, sep):
    """Greedily pack (plain, markup) chunks into lines that fit the card."""
    lines, plain, markup = [], "", []
    for chunk_plain, chunk_markup in chunks:
        joined = chunk_plain if not markup else plain + sep + chunk_plain
        if markup and len(joined) > NOTE_BUDGET:
            lines.append(sep.join(markup))
            plain, markup = chunk_plain, [chunk_markup]
        else:
            plain, markup = joined, markup + [chunk_markup]
    if markup:
        lines.append(sep.join(markup))
    return lines


def render(members, edges, firm):
    gated = members - firm
    sideways, head, allow, mark = notes(members, edges, gated)
    desc = (
        f"Crate dependency layers: {len(members)} crates in {len(TIERS)} tiers, from the "
        f"{len(TIERS[0][3])} flashable binaries at the top, down through the "
        f"{len(TIERS[applet_tier()][3])} applets, to the {len(TIERS[-1][3])} algorithm "
        f"crates. All {len(edges)} in-workspace dependencies point strictly downward, and "
        f"applet-to-applet edges number {sideways}."
    )
    body, y = [], 118
    for i, (label, sub, colour, crates) in enumerate(TIERS):
        rows, y = band_svg(y, label, sub, colour, crates, gated)
        body += rows
        if i + 1 < len(TIERS):
            body.append(
                f'  <path class="arw" d="M{WIDTH / 2:.0f} {y + 6:.0f} l6 0 -6 9 -6 -9 z"/>'
            )
        y += 26
    note_y = y + 4
    note_lines = wrap(head, " ") + wrap(allow, "   ·   ") + wrap(mark, " ")
    height = note_y + 18 * len(note_lines) + 40
    svg = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        "<!-- GENERATED by scripts/crate_graph.py — do not edit; run the script. -->",
        f'<svg viewBox="0 0 {WIDTH} {height:.0f}" xmlns="http://www.w3.org/2000/svg" role="img"'
        ' aria-labelledby="ttl dsc"'
        " font-family=\"'Segoe UI', system-ui, -apple-system, sans-serif\">",
        '  <title id="ttl">RS-Key crate dependency layers</title>',
        f'  <desc id="dsc">{esc(desc)}</desc>',
        "  <defs>",
        "    <style>",
        "      .h1{font-size:23px;font-weight:700;fill:#2B2723}",
        "      .sub{font-size:12.5px;fill:#948A7F}",
        "      .sub2{font-size:10.5px;fill:#ADA398;font-style:italic}",
        "      .tier{font-size:11px;font-weight:700;fill:#948A7F;letter-spacing:.5px}",
        "      .node{font-size:11px;font-weight:700;fill:#fff;"
        "font-family:'SF Mono','Roboto Mono',ui-monospace,monospace}",
        "      .note{font-size:10.5px;fill:#5A534B}",
        "      .notek{font-family:'SF Mono','Roboto Mono',ui-monospace,monospace;"
        "font-weight:700;fill:#2F7E75}",
        "      .arw{fill:#D9D2C8}",
        "      .foot{font-size:10.5px;fill:#ADA398}",
        "    </style>",
        "  </defs>",
        f'  <rect x="6" y="6" width="{WIDTH - 12}" height="{height - 12:.0f}" rx="16"'
        ' fill="#FBFAF8" stroke="#E4DED5" stroke-width="1.5"/>',
        "",
        f'  <text class="h1" x="{MARGIN}" y="46">Crate dependency layers</text>',
        f'  <text class="sub" x="{MARGIN}" y="68">{len(members)} crates · {len(edges)}'
        " in-workspace dependencies · every one points strictly downward</text>",
        f'  <text class="sub" x="{MARGIN}" y="88">each tier is host-tested (no_std) except'
        ' <tspan font-weight="700">firmware</tspan> and <tspan font-weight="700">rsk-wipe</tspan>,'
        " which are thumbv8m-only</text>",
        "",
    ]
    svg += body
    svg.append("")
    for i, line in enumerate(note_lines):
        svg.append(f'  <text class="note" x="{MARGIN}" y="{note_y + 18 * i:.0f}">{line}</text>')
    svg += [
        f'  <text class="foot" x="{MARGIN}" y="{height - 20:.0f}">Generated by'
        " scripts/crate_graph.py from the workspace Cargo.toml manifests"
        ' (<tspan font-style="italic">[dependencies]</tspan> only).</text>',
        "</svg>",
        "",
    ]
    return "\n".join(svg), desc


def page_problems(members, desc):
    """`docs/architecture.md` owes the drawing its alt text and a row per crate."""
    page = ALT_PAGE.read_text()
    out = []
    alt = f"![{desc}](images/crate-graph.svg)"
    if alt not in page:
        out.append(
            f"FAIL: {ALT_PAGE.relative_to(ROOT)} does not carry the drawing's own alt text.\n"
            f"      Expected line:\n      {alt}"
        )
    tabled = set(CRATE_ROW.findall(page))
    if members - tabled:
        out.append(
            f"FAIL: {ALT_PAGE.relative_to(ROOT)}'s crate table has no row for "
            f"{', '.join(sorted(members - tabled))}."
        )
    if tabled - members:
        out.append(
            f"FAIL: {ALT_PAGE.relative_to(ROOT)}'s crate table names "
            f"{', '.join(sorted(tabled - members))}, which is not a workspace member."
        )
    return out


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed SVG is stale")
    args = ap.parse_args(argv)

    members, edges, firm = read_workspace()
    placed = rank(members)
    check_invariants(edges, placed)
    check_deny_covers_the_applets()
    svg, desc = render(members, edges, firm)

    # Every problem is reported, and the drawing is written before the page is
    # judged: a manifest edit moves the counts in both, and stopping at the first
    # would send a contributor round the loop twice for one change.
    problems = []
    if args.check:
        if not SVG.exists() or SVG.read_text() != svg:
            problems.append(
                f"FAIL: {SVG.relative_to(ROOT)} is stale.\n"
                "      Regenerate it: python scripts/crate_graph.py"
            )
    else:
        SVG.write_text(svg)
        print(f"wrote {SVG.relative_to(ROOT)} — {len(members)} crates, {len(edges)} edges")
    problems += page_problems(members, desc)
    if problems:
        raise SystemExit("\n".join(problems))
    if args.check:
        print(f"crate-graph.svg matches {len(members)} crates / {len(edges)} edges")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
