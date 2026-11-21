# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Run the NS board's complete reply-buffer tests in the existing host gate."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_ns_reply_guard_clears_every_exit_and_exact_byte_span(tmp_path):
    metadata = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    host = next(line.removeprefix("host: ") for line in metadata.stdout.splitlines()
                if line.startswith("host: "))
    binary = tmp_path / "ns-reply-tests"
    compiled = subprocess.run(
        ["rustc", "--edition=2024", "--test", "--target", host,
         str(ROOT / "firmware/trustzone/nonsecure/reply-tests.rs"), "-o", str(binary)],
        capture_output=True, text=True, timeout=120,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    assert tested.returncode == 0, tested.stdout + tested.stderr
    for name in ("all_alignments_lengths_and_byte_edges_preserve_canaries",
                 "early_error_clears_the_full_reply",
                 "dropping_pending_future_clears_the_full_reply"):
        assert f"reply::tests::{name} ... ok" in tested.stdout, tested.stdout
