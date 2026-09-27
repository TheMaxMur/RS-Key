# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Sourced by scripts/check.sh after its `set` line and its `cd` to the root: the
# row helper, the signal verdicts and the pytest base. It runs no row itself.

# The EXIT trap check.sh sets already runs on a fatal signal (measured), so these
# are for the verdict, not the cleanup: without the INT one, a SIGINT delivered
# to the runner alone lets the interrupted run report rc 0.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The temp a runner makes with no `mktemp` in it: pytest's `tmp_path` lives
# under $TMPDIR, and `nix develop` hands every invocation a FRESH
# /tmp/nix-shell.XXXXXX it never removes — so pytest's own "keep the last three
# runs" retention never meets a previous run, and every gate leaves its scratch
# behind for good. 361 orphaned bases and 8.9 GB in one day; 351 MB of that per
# run is the gate-scripts row, spread over ~1400 directories with no fat one to
# slim. Same volume-to-zero as check.sh's mktemp sites.
#
# A pinned --basetemp is removed and recreated by pytest at startup, so a row
# holds one run instead of every run. It must not be inside the checkout: under
# `target/`, `git rev-parse` answers from RS-Key's own .git and test_verdict_gate's
# "git cannot answer here" case goes red (measured, 1788 of 1789). pytest makes the
# leaf, not its parents. It wipes what it is pointed at, so each row gets a leaf
# and each checkout a base: one per user let one worktree's gate wipe another's.
GATE_PYTEST_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest/$(git rev-parse --show-toplevel | git hash-object --stdin | cut -c1-12)"
mkdir -p "$GATE_PYTEST_TMP"
# A passing test's directory goes as it passes, a failing one's stays — the only
# kind anybody opens. 351 MB → 1 MB on the gate-scripts row, which is what keeps a
# base in a cache directory nobody thinks to sweep from becoming a hoard.
GATE_PYTEST_KEEP=(-o tmp_path_retention_policy=failed)

run() { echo; echo "== $1 =="; shift; "$@"; }
