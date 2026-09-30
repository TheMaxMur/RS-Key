# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk flash — verify a release image, then write it to a board in BOOTSEL.

The checks are the ones docs/supply-chain.md has a reader run by hand, in that
order. `cosign verify-blob` proves SHA256SUMS was signed by this repo's release
workflow in a run of this repo: the Fulcio certificate's identity, issuer and
repository, and the Rekor entry the bundle carries. The image's sha256 must be
the one SHA256SUMS lists under its name. `gh attestation verify` ties the image
to the pinned build workflow at the release's own tag, read from the SBOM's name
in SHA256SUMS; it is skipped, and says so, when `gh` is not installed. Only then
`picotool load -v` and `picotool reboot`, as the flashing guides have it.

cosign and gh are run, not imported, so nothing joins the Python dependencies. An
image you built yourself carries no release signature: it flashes only with
--local-build, which checks nothing and warns.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys

from .common import die, picotool, sanitize
from .secureboot import require_bootsel

SUMS = "SHA256SUMS"
BUNDLE = "SHA256SUMS.sigstore.json"
REPO = "TheMaxMur/RS-Key"
# The reusable builder signs and attests, not the release.yml that calls it.
SIGNER_WORKFLOW = f"{REPO}/.github/workflows/release-build.yml"
# The verify command docs/supply-chain.md and releases.md print, character for character
# (test_flash holds both). Tag refs only: releases are cut from `v*` tags.
IDENTITY_REGEXP = r"^https://github\.com/TheMaxMur/RS-Key/\.github/workflows/release-build\.yml@refs/tags/v.*$"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
# The identity names a reusable workflow any repository may call; this pins the run
# to REPO. cosign reads it from GithubWorkflowRepository, Fulcio's 1.3.6.1.4.1.57264.1.5.
REPOSITORY_PIN = "--certificate-github-workflow-repository"
# `--signer-workflow` names the file at any ref; this pins the run to the release's tag.
SOURCE_REF = "refs/tags/{tag}"
COSIGN_HELP = "https://docs.sigstore.dev/"

#: One `sha256sum` line: text mode (two spaces) or binary (` *`), and the `./`
#: the release job's `sha256sum ./*.uf2` writes in front of each name.
SUMS_LINE = re.compile(r"^([0-9a-fA-F]{64}) [ *](?:\./)?(.+)$")
#: The SBOM's name, the one asset name with nothing after the tag but a fixed
#: suffix: in `rs-key-<tag>-<flavor>.uf2` a tag like `v1.0.0-rc1` has no end.
SBOM_NAME = re.compile(r"rs-key-(.+)-sbom\.cdx\.json")


def register(sub):
    p = sub.add_parser("flash", help="verify a release .uf2, then write it over BOOTSEL")
    p.add_argument("uf2", help="a release image, with SHA256SUMS and "
                               "SHA256SUMS.sigstore.json from the same release beside it")
    p.add_argument("--dry-run", action="store_true",
                   help="verify only, and print the picotool commands without running them")
    p.add_argument("--local-build", action="store_true",
                   help="an image you built yourself: skip every release check (warns)")
    p.set_defaults(func=run)


def _run(argv):
    """A verifier's run. Its output can quote the downloaded files, so it is
    sanitized wherever it is printed."""
    return subprocess.run(argv, capture_output=True, text=True)


def _said(r):
    return sanitize((r.stderr or r.stdout or "").strip())


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def listed_digest(sums, name):
    """The digest SHA256SUMS gives `name`; dies when it gives none, or two."""
    found = set()
    with open(sums, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SUMS_LINE.match(line.rstrip("\r\n"))
            if m and m[2] == name:
                found.add(m[1].lower())
    if not found:
        die(f"{SUMS} lists no {sanitize(name)}: a release image keeps its published "
            "name; not flashing")
    if len(found) > 1:
        die(f"{SUMS} lists {sanitize(name)} twice with different digests; not flashing")
    return found.pop()


def release_tag(sums):
    """The tag SHA256SUMS names its release by; dies unless it names exactly one."""
    tags = set()
    with open(sums, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SUMS_LINE.match(line.rstrip("\r\n"))
            if m and (sbom := SBOM_NAME.fullmatch(m[2])):
                tags.add(sbom[1])
    if not tags:
        die(f"{SUMS} lists no rs-key-<tag>-sbom.cdx.json, so it names no release tag "
            "to check the provenance at; not flashing")
    if len(tags) > 1:
        die(f"{SUMS} names more than one release tag "
            f"({', '.join(sanitize(t) for t in sorted(tags))}); not flashing")
    return tags.pop()


def verify(uf2):
    here, name = os.path.split(uf2)
    shown = sanitize(name)
    sums, bundle = os.path.join(here, SUMS), os.path.join(here, BUNDLE)
    missing = [os.path.basename(p) for p in (sums, bundle) if not os.path.isfile(p)]
    if missing:
        die(f"{' and '.join(missing)} not found beside {shown}. A release image is "
            f"checked against the {SUMS} and {BUNDLE} published with it: download them from "
            "the same release. An image you built yourself has neither: pass --local-build")
    cosign = shutil.which("cosign")
    if cosign is None:
        die(f"cosign not found. It checks the release signature, and nothing is flashed "
            f"unchecked. Install it ({COSIGN_HELP}; `brew install cosign` or "
            "`nix shell nixpkgs#cosign`) and run this again")
    r = _run([cosign, "verify-blob", "--bundle", bundle,
              "--certificate-identity-regexp", IDENTITY_REGEXP,
              "--certificate-oidc-issuer", OIDC_ISSUER,
              REPOSITORY_PIN, REPO, sums])
    if r.returncode != 0:
        die(f"the signature on {SUMS} does not verify, so neither does anything it "
            f"lists; not flashing.\n{_said(r)}")
    print(f"{SUMS}: signed by {SIGNER_WORKFLOW} in a run of {REPO}, Rekor entry checked ✓")
    want, got = listed_digest(sums, name), sha256_of(uf2)
    if got != want:
        die(f"{shown}: sha256 {got} is not the {want} that {SUMS} lists; not flashing")
    print(f"{shown}: sha256 matches {SUMS} ✓")
    gh = shutil.which("gh")
    if gh is None:
        print("warning: gh not found, so the build provenance was NOT checked (gh "
              "attestation verify). The signature and the checksum above passed; install "
              "the GitHub CLI to check the provenance too.", file=sys.stderr)
        return
    ref = SOURCE_REF.format(tag=release_tag(sums))
    r = _run([gh, "attestation", "verify", uf2, "--repo", REPO,
              "--signer-workflow", SIGNER_WORKFLOW, "--source-ref", ref])
    if r.returncode != 0 and "unknown flag: --source-ref" in f"{r.stderr}{r.stdout}":
        die(f"this gh predates `gh attestation verify --source-ref`, which pins the "
            f"provenance to {sanitize(ref)}: upgrade the GitHub CLI; not flashing")
    if r.returncode != 0:
        die(f"{shown}: gh attestation verify failed; not flashing.\n{_said(r)}")
    print(f"{shown}: built by {SIGNER_WORKFLOW} at {sanitize(ref)} (attestation) ✓")


def run(args):
    uf2 = os.path.abspath(os.path.expanduser(args.uf2))
    if not os.path.isfile(uf2):
        die(f"{sanitize(args.uf2)}: no such image")
    if args.local_build:
        print("warning: --local-build: nothing checked that this image is an RS-Key "
              "release (no signature, no checksum, no provenance). Flash only an image "
              "you built yourself.", file=sys.stderr)
    else:
        verify(uf2)
    if args.dry_run:
        print("dry-run: would run")
        print(f"   picotool load -v {sanitize(uf2)}")
        print("   picotool reboot")
        return
    if shutil.which("picotool") is None:
        die("picotool not found: it writes the image over BOOTSEL (`nix develop` has it)")
    require_bootsel()
    print("loading (picotool load -v) …")
    picotool("load", "-v", uf2)
    print("written and read back ✓")
    if picotool("reboot", check=False).returncode != 0:
        die("the image is written, but `picotool reboot` failed: unplug and replug the board")
    print("rebooted into the new image ✓")
