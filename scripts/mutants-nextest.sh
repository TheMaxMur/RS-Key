#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail

check_limits() {
  local memory swap memory_limit=4294967296
  if [ "$(uname -s)" != Linux ] ||
     ! read -r memory < /sys/fs/cgroup/memory.max ||
     ! read -r swap < /sys/fs/cgroup/memory.swap.max; then
    echo "FAIL: mutations require a Linux cgroup with at most 4 GiB and no swap" >&2
    exit 1
  fi
  case "$memory" in
    ''|*[!0-9]*) echo "FAIL: mutation memory is unbounded" >&2; exit 1 ;;
  esac
  if [ "${#memory}" -gt "${#memory_limit}" ] ||
     [ "$memory" -le 0 ] || [ "$memory" -gt "$memory_limit" ] || [ "$swap" != 0 ]; then
    echo "FAIL: mutation cgroup must enforce at most 4 GiB and zero swap" >&2
    exit 1
  fi
}

if [ "${1:-}" = --check-limits ]; then
  check_limits
  exit 0
fi

if [ "${1:-}" != nextest ] || [ "${2:-}" != run ]; then
  exec "${MUTANTS_NEXTEST_BIN:?}" "$@"
fi
shift 2
check_limits
for arg in "$@"; do
  if [ "$arg" = --no-run ]; then
    exec "${MUTANTS_NEXTEST_BIN:?}" nextest run --profile mutants --no-tests=pass "$@"
  fi
done

# Linux enforces this inherited address-space bound before allocation can grow.
(
  ulimit -v 1048576
  exec "${MUTANTS_NEXTEST_BIN:?}" nextest run --profile mutants --test-threads=1 --no-tests=pass "$@"
)

# Nextest runs the library binaries; the Cargo runner also exercised doctests.
exec timeout --signal=KILL 60s cargo test --doc "$@"
