#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Refactor reconnaissance — advisory metrics, NOT a gate. Run it when deciding
# *where* to refactor; nothing here gates a commit (that stays scripts/check.sh).
# The signals: function complexity (rust-code-analysis), firmware size by
# crate/function (cargo-bloat), and generic monomorphization (cargo-llvm-lines).
#
# The three tools are pulled ad-hoc via `nix shell --inputs-from . nixpkgs#…`
# (as in the pages workflow): their versions are pinned to the flake's nixpkgs so
# the numbers are reproducible and match the deep-checks complexity gate, yet
# they do NOT join the pinned dev shell / SBOM trust base — they never touch a
# shipping build. Run inside the dev shell (for cargo + the cross target):
#   nix develop -c ./scripts/metrics.sh [crate-src-dir ...]
# With no args it profiles the applet command handlers (the long INS/CBOR
# dispatchers); pass paths to scope the complexity pass elsewhere.
# Condition coverage: nix develop .#fuzz -c ./scripts/metrics.sh --coverage
# COVERAGE_PROFILE names comma-separated firmware features (default if absent).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = --coverage ]; then
  shift
  [ "$#" -eq 0 ] || { echo "usage: metrics.sh --coverage" >&2; exit 1; }
  # Run in .#fuzz: condition coverage belongs to its pinned nightly compiler.
  python3 - <<'PY'
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

root = Path.cwd()
profile = os.environ.get("COVERAGE_PROFILE", "default")
features = [] if profile == "default" else profile.split(",")
declared = tomllib.loads((root / "firmware/Cargo.toml").read_text())["features"]
if any(feature not in declared for feature in features):
    raise SystemExit(f"unknown firmware feature in COVERAGE_PROFILE={profile}")
host = re.search(r"^host: (.+)$", subprocess.check_output(["rustc", "-vV"], text=True), re.M)[1]
out = Path(os.environ.get("COVERAGE_OUT", f"target/coverage-{profile}-{time.time_ns()}"))
out.mkdir(parents=True, exist_ok=False)
identity = {
    "profile": profile,
    "target": host,
    "compiler": subprocess.check_output(["rustc", "-vV"], text=True),
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "scope": "raw host workspace; firmware and rsk-wipe excluded; verification helpers retained",
    "instrumentation": "condition outcomes; not MC/DC; match, ? and for require semantic evidence",
    "status": "incomplete",
    "commands": [],
}
(out / "source.patch").write_bytes(subprocess.check_output(["git", "diff", "HEAD", "--binary"]))
(out / "toolchain.txt").write_text(identity["compiler"])
env = dict(os.environ, RUSTFLAGS=os.environ.get("RUSTFLAGS", "") + " -Zcoverage-options=condition")
identity["rustflags"] = env["RUSTFLAGS"]

def source_hashes(save_untracked=False):
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], text=True).split("\0")
    untracked = set(subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], text=True).split("\0"))
    hashes = {}
    for name in sorted(set(names)):
        if not (name.startswith(("crates/", "firmware/", "vendor/", ".cargo/"))
                or name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "clippy.toml",
                            "flake.nix", "flake.lock", "scripts/metrics.sh")):
            continue
        path = root / name
        if path.resolve().is_relative_to(out.resolve()):
            continue
        content = path.read_bytes() if path.is_file() else None
        hashes[name] = hashlib.sha256(content).hexdigest() if content is not None else None
        if save_untracked and name in untracked and content is not None:
            saved = out / "untracked" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(content)
    return hashes

identity["source_sha256"] = source_hashes(save_untracked=True)

def run(command, name):
    started = time.monotonic()
    with (out / name).open("w") as log:
        result = subprocess.run(command, env=env, stdout=log,
                                stderr=subprocess.PIPE if name.endswith(".json") else log)
    if result.stderr is not None:
        (out / (name + ".stderr")).write_bytes(result.stderr)
    identity["commands"].append({"argv": command, "exit": result.returncode,
                                 "seconds": time.monotonic() - started, "log": name})
    (out / "manifest.json").write_text(json.dumps(identity, indent=2) + "\n")
    if result.returncode:
        identity["status"] = "failed"
        (out / "manifest.json").write_text(json.dumps(identity, indent=2) + "\n")
        raise SystemExit(f"coverage command failed ({result.returncode}); inspect {out / name}")

metadata = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host]
run(metadata, "default.metadata.json")
base = json.loads((out / "default.metadata.json").read_text())
base_features = {node["id"]: set(node["features"]) for node in base["resolve"]["nodes"]}
run(metadata + (["--features", ",".join("firmware/" + f for f in features)] if features else []),
    "firmware.metadata.json")
shipping = json.loads((out / "firmware.metadata.json").read_text())
names = {package["id"]: package["name"] for package in shipping["packages"]}
host_features = sorted(names[node["id"]] + "/" + feature
                       for node in shipping["resolve"]["nodes"]
                       if names[node["id"]].startswith("rsk-") and names[node["id"]] != "rsk-wipe"
                       for feature in set(node["features"]) - base_features.get(node["id"], set()))
identity["host_feature_args"] = host_features
selection = ["--workspace", "--exclude", "firmware", "--exclude", "rsk-wipe", "--target", host]
feature_args = ["--features", ",".join(host_features)] if host_features else []
run(["cargo", "llvm-cov", *selection, *feature_args, "--json", "--output-path", str(out / "coverage.json")],
    "tests.log")
if not re.search(r"test result: ok\. [1-9][0-9]* passed;", (out / "tests.log").read_text()):
    raise SystemExit(f"no executed tests: {out / 'tests.log'}")
report = json.loads((out / "coverage.json").read_text())["data"][0]
if not report["files"] or report["totals"]["lines"]["count"] == 0:
    raise SystemExit("missing coverage evidence")
identity["totals"] = report["totals"]
run(["cargo", "llvm-cov", "report", "--target", host, "--branch", "--lcov",
     "--output-path", str(out / "coverage.lcov")], "lcov.log")
run(["cargo", "llvm-cov", "report", "--target", host, "--branch", "--html",
     "--output-dir", str(out / "html")], "html.log")
if source_hashes() != identity["source_sha256"]:
    raise SystemExit("coverage source changed during measurement; report remains incomplete")
identity["status"] = "complete"
(out / "manifest.json").write_text(json.dumps(identity, indent=2) + "\n")
print(f"{profile}: {identity['totals']['lines']}; raw reports in {out}")
PY
  exit 0
fi

crates=("$@")
if [ "${#crates[@]}" -eq 0 ]; then
  crates=(
    crates/rsk-fido/src
    crates/rsk-piv/src
    crates/rsk-openpgp/src
    crates/rsk-oath/src
    crates/rsk-mgmt/src
  )
fi

echo "== complexity — heaviest functions (rust-code-analysis) =="
echo "   scope: ${crates[*]}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rca_args=()
for c in "${crates[@]}"; do rca_args+=(-p "$c"); done
nix shell --inputs-from . nixpkgs#rust-code-analysis -c rust-code-analysis-cli -m -O json -o "$tmp" "${rca_args[@]}"
python3 scripts/metrics_complexity.py "$tmp"

echo
echo "== firmware size by crate (cargo-bloat, release) =="
nix shell --inputs-from . nixpkgs#cargo-bloat -c cargo bloat --release -p firmware --crates -n 20

echo
echo "== firmware size by function (cargo-bloat, release) =="
nix shell --inputs-from . nixpkgs#cargo-bloat -c cargo bloat --release -p firmware -n 20

echo
echo "== generic monomorphization (cargo-llvm-lines, release) =="
nix shell --inputs-from . nixpkgs#cargo-llvm-lines -c cargo llvm-lines --release -p firmware | head -25
