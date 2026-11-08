#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out="$root/target/mcdc.$(date +%s).$$"
mkdir -p "$root/target"
mkdir "$out"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
echo "MC/DC reports: $out"

host_target=$(rustc -vV | sed -n 's/^host: //p')
revision=bd6c9d76426d446fb57bcbe5df7791820c97fac1
tool="$scratch/supercov"
(
    git init -q "$tool"
    git -C "$tool" fetch -q --depth 1 https://github.com/supercorp-ai/supercov.git "$revision"
    git -C "$tool" checkout -q --detach "$revision"
    git -C "$tool" apply \
        "$root/third_party/mcdc-supercov-anonymous-const.patch" \
        "$root/third_party/mcdc-supercov-pin-expression.patch" \
        "$root/third_party/mcdc-supercov-source-decisions.patch"
    cargo build --locked --manifest-path "$tool/Cargo.toml" \
        --target "$host_target" --target-dir "$scratch/tool-target" -p supercov
) >"$out/tool.log" 2>&1 || { cat "$out/tool.log" >&2; exit 1; }
supercov="$scratch/tool-target/$host_target/debug/supercov"

# Cached depinfo can carry feature-only decisions into a later report.
source="$scratch/source"
mkdir "$source"
cp -R .cargo .gitignore Cargo.toml Cargo.lock crates firmware rsk-wipe third_party "$source"
cd "$source"

# Per-test traces for the whole workspace exceed the hosted runner's disk.
sources=(
    crates/rsk-fido/src/getassertion.rs
    crates/rsk-fido/src/state.rs
    crates/rsk-piv/src/auth.rs
    crates/rsk-openpgp/src/pin.rs
    crates/rsk-device/src/presence.rs
    crates/rsk-fs/src/fs.rs
    crates/rsk-store/src/verified_flash.rs
)
source_roots=$(IFS=,; echo "${sources[*]}")
SUPERCOV_SOURCE_ROOTS="$source_roots" SUPERCOV_KEEP_WORKSPACE=1 "$supercov" -- \
    cargo test --locked --target "$host_target" --lib \
        -p rsk-fido -p rsk-piv -p rsk-openpgp -p rsk-device -p rsk-fs -p rsk-store \
        -- issued_tokens_exercise_each_getassertion_condition pin_uv_auth_token_ \
        auth_decisions pin::tests:: presence::tests:: fs:: \
        verification_checks_later_program_chunks_and_the_last_word_of_an_erase \
    2>&1 | tee "$out/tests.log"
"$supercov" runs latest --json >"$out/summary.json"
tar -czf "$out/evidence.tar.gz" -C .supercov runs
python3 - "$out/summary.json" "$source_roots" <<'PY' | tee "$out/result.md"
import json
import sys

with open(sys.argv[1]) as report:
    response = json.load(report)
if response["ok"] is not True:
    sys.exit("Supercov could not read the MC/DC run")
run = response["data"]
sources = set(sys.argv[2].split(","))
scope = run["sourceScope"]
if set(scope["roots"]) != sources or scope["included"] != len(sources):
    sys.exit("MC/DC run did not measure the selected source files")

coverage = run["coverage"]
witnesses = run.get("coverageByTests", {}).get("coveredConditions", 0)
if (run["valid"] is not True or run["stale"] is not False
        or run["testExitCode"] != 0 or run["testOutcomes"]["passed"] <= 0
        or run["measurement"]["evidenceCorruptions"] != 0
        or not 0 < witnesses <= coverage["conditions"]):
    sys.exit("MC/DC run did not produce valid test witness evidence")

print("### MC/DC (host security decisions)")
print()
print(f"{run['testOutcomes']['passed']} tests passed.")
print(f"{witnesses}/{coverage['conditions']} conditions have test witness pairs.")
print(f"Supercov run `{run['run']}`. See the raw summary for measurement limits.")
PY
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
    cat "$out/result.md" >>"$GITHUB_STEP_SUMMARY"
fi
