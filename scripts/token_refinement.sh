#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  --generate)
    python scripts/export_token_relation.py
    python scripts/generate_token_edges.py
    ;;
  --check)
    python scripts/export_token_relation.py --check
    python scripts/generate_token_edges.py --check
    ;;
  *)
    echo "usage: scripts/token_refinement.sh --generate|--check" >&2
    exit 2
    ;;
esac
