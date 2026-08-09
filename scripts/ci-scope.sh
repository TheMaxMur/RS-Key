#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Which CI jobs a change can possibly affect.
#
# Reads one changed path per line on stdin and writes `name=true|false` lines —
# GITHUB_OUTPUT's format — for the workflows to gate on. The rules live here
# rather than in a `paths:` filter or a third-party action for two reasons: they
# are testable (`--self-test`, which `check.sh` runs), and adding an action to a
# repository that pins every SHA and vets every dependency is a trust decision
# this does not need.
#
# **Fails open.** An unrecognised path turns everything on, and so does an empty
# input: the failure mode of a wrong rule here is a job that silently does not
# run, and a false green is worse than a wasted runner.
set -euo pipefail

# Paths that cannot change what any build produces. Everything else is code
# until proven otherwise — the list is deliberately short, and a new top-level
# directory lands outside it.
DOCS_ONLY='^(docs/|assets/|book\.toml$|[^/]*\.md$|\.github/workflows/pages\.yml$)'

# The firmware image and everything it is built from. Only the parts of `nix/`
# that reach a build are in: `flake.lock` and `devshells.nix` pin the toolchain,
# so a compiler bump changes every image without touching a line of Rust — while
# `ccid.nix` or `host-tools.nix` cannot change an image at all.
FIRMWARE='^(firmware/|crates/|Cargo\.(toml|lock)$|rust-toolchain|nix/(firmware|devshells)\.nix$|flake\.(nix|lock)$|third_party/sequential-storage|\.github/workflows/ci\.yml$)'

# What the emulator runs, and what it runs against. `crates/` is in because the
# emulator IS those crates; `tests/` and `third_party/` are the suites themselves.
EMULATOR='^(tools/emu/|tests/|third_party/|crates/|firmware/|scripts/(emu-suites|usbip-suites|usbip-guest|check)\.sh$|nix/|flake\.(nix|lock)$|Cargo\.(toml|lock)$|\.github/workflows/emulator\.yml$)'

classify() {
  local files firmware=false emulator=false docs_only=true n=0
  files="$(cat)"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n=$((n + 1))
    [[ "$f" =~ $DOCS_ONLY ]] || docs_only=false
    [[ "$f" =~ $FIRMWARE ]] && firmware=true
    [[ "$f" =~ $EMULATOR ]] && emulator=true
  done <<<"$files"

  # No file list means we could not work out the base — treat it as "everything".
  if [ "$n" -eq 0 ]; then
    firmware=true
    emulator=true
    docs_only=false
  fi

  echo "firmware=$firmware"
  echo "emulator=$emulator"
  echo "docs_only=$docs_only"
}

self_test() {
  local fails=0
  # case | stdin | expected substring(s), space-separated
  check() {
    local name="$1" input="$2" want="$3" got
    got="$(printf '%s\n' "$input" | classify | tr '\n' ' ')"
    for w in $want; do
      case " $got " in
        *" $w "*) ;;
        *)
          echo "FAIL $name: want '$w' in '$got'"
          fails=$((fails + 1))
          ;;
      esac
    done
  }

  check "a doc alone"          "docs/guides/display.md"      "firmware=false emulator=false docs_only=true"
  check "the README"           "README.md"                   "docs_only=true"
  check "a screenshot"         "docs/images/display-pin.png" "docs_only=true"
  check "a doc + a crate"      "docs/x.md
crates/rsk-fido/src/getinfo.rs"                              "firmware=true emulator=true docs_only=false"
  check "the firmware"         "firmware/src/main.rs"        "firmware=true docs_only=false"
  check "an on-device test"    "tests/10_fido_getinfo.py"    "firmware=false emulator=true docs_only=false"
  check "the host CLI"         "tools/rsk/led.py"            "firmware=false emulator=false docs_only=false"
  check "the toolchain pin"    "flake.lock"                  "firmware=true emulator=true docs_only=false"
  # The nix tree is split: what pins the toolchain reaches every image, what
  # packages a host tool reaches none of them.
  check "nix/firmware.nix"     "nix/firmware.nix"            "firmware=true"
  check "nix/ccid.nix"         "nix/ccid.nix"                "firmware=false emulator=true"
  check "nix/host-tools.nix"   "nix/host-tools.nix"          "firmware=false"
  check "this file"            "scripts/ci-scope.sh"         "firmware=false emulator=false docs_only=false"
  check "nothing known"        ""                            "firmware=true emulator=true docs_only=false"
  # A path nobody has classified must not read as documentation.
  check "a new top-level dir"  "somewhere-new/thing.rs"      "docs_only=false"

  if [ "$fails" -eq 0 ]; then
    echo "ci-scope: self-test ok"
  else
    echo "ci-scope: $fails failure(s)" >&2
    return 1
  fi
}

case "${1:-}" in
  --self-test) self_test ;;
  "") classify ;;
  *)
    echo "usage: $0 [--self-test]   # changed paths on stdin" >&2
    exit 2
    ;;
esac
