#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null; then
  echo "FAIL: Docker is required to enforce mutation memory limits" >&2
  exit 1
fi
rsk_root="$PWD"
rsk_output="${MUTANTS_OUT:-target/mutants}"
mkdir -p "$rsk_output"
rsk_output="$(cd "$rsk_output" && pwd)"
rsk_image="$(docker image inspect nixos/nix:latest --format '{{index .RepoDigests 0}}' 2>/dev/null)" || {
  docker pull nixos/nix:latest
  rsk_image="$(docker image inspect nixos/nix:latest --format '{{index .RepoDigests 0}}')"
}
if ! [[ "$rsk_image" =~ ^nixos/nix@sha256:[0-9a-f]{64}$ ]]; then
  echo "FAIL: mutation image has no immutable registry digest" >&2
  exit 1
fi
printf '%s\n' "$rsk_image" > "$rsk_output/container-image.txt"
rsk_run="$(mktemp -d "$rsk_output/.runner.XXXXXX")"
cleanup() {
  if [ -s "$rsk_run/id" ]; then
    docker rm -f "$(cat "$rsk_run/id")" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup; rm -rf "$rsk_run"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Acquire ownership before starting tests; cancellation waits for the CID.
(
  trap '' INT TERM
  # Nix renames canonicalized read-only directories across parents.
  exec docker create --init --cidfile "$rsk_run/id" --name rsk-mutants-safe \
  --memory=4g --memory-swap=4g --cpus=2 --pids-limit=256 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --security-opt=no-new-privileges \
  --mount "type=bind,src=$rsk_root,dst=/repo,readonly" \
  --mount type=volume,src=rsk-mutants-nix,dst=/nix \
  --workdir=/repo --env CARGO_BUILD_JOBS=1 --env CARGO_HOME=/nix/rsk-mutants-cargo-home --env TMPDIR=/tmp \
  --env "MUTANTS_SHARD=${MUTANTS_SHARD:-1/1}" --env MUTANTS_OUT=/work \
  --env 'NIX_CONFIG=experimental-features = nix-command flakes
sandbox = false
build-users-group =
max-jobs = 1
cores = 1' \
  "$rsk_image" \
  sh -ec '
    # Nix uses libgit2, which reads the config file but ignores GIT_CONFIG_COUNT.
    git config --global --add safe.directory /repo
    # Reports must stay outside the read-only source mount.
    mkdir -p /work/mutants.out
    # The Nix image may have no env at the shebang path used by the test runners.
    if [ ! -x /usr/bin/env ]; then
      mkdir -p /usr/bin
      ln -sf "$(command -v env)" /usr/bin/env
    fi
    exec nix develop --profile /work/nix-profile git+file:///repo -c ./scripts/mutants-all.sh "$@"
  ' sh "$@"
) >/dev/null
rsk_container="$(cat "$rsk_run/id")"
docker start --attach "$rsk_container" &
rsk_docker_pid=$!
rsk_status=0
wait "$rsk_docker_pid" || rsk_status=$?

# Docker copies results out as the host user, including partial reports on failure.
if docker cp "$rsk_container:/work/mutants.out" "$rsk_run/"; then
  if [ -e "$rsk_output/mutants.out" ]; then
    mv "$rsk_output/mutants.out" "$rsk_run/previous-report"
  fi
  mv "$rsk_run/mutants.out" "$rsk_output/"
elif [ "$rsk_status" -eq 0 ]; then
  exit 1
fi
exit "$rsk_status"
