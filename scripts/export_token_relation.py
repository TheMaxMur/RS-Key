#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Capture the token relation serialized by TLA+ without restating its domain."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"
PREFIX = '"TOKEN|'


def die(message: str) -> None:
    raise SystemExit(f"token-export: {message}")


def export() -> list[str]:
    jar = os.environ.get("TLA2TOOLS_JAR")
    java = os.environ.get("JAVA") or shutil.which("java")
    if not jar or not java:
        die("TLA2TOOLS_JAR/java unavailable; run inside `nix develop`")
    with tempfile.TemporaryDirectory(prefix="rsk-token-export-") as raw_tmp:
        work = Path(raw_tmp)
        for name in [
            "RSKeyTokenAbstract.tla",
            "RSKeyTokenExport.tla",
            "TokenExport.cfg",
        ]:
            shutil.copy2(FORMAL / name, work / name)
        result = subprocess.run(
            [
                java,
                "-XX:+UseParallelGC",
                "-Xmx2g",
                "-cp",
                jar,
                "tlc2.TLC",
                "-nowarning",
                "-workers",
                "2",
                "-config",
                "TokenExport.cfg",
                "RSKeyTokenExport",
            ],
            cwd=work,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    if result.returncode != 0:
        die(f"TLC exited {result.returncode}:\n{result.stdout[-4000:]}")
    lines = sorted(
        {
            line[1:-1]
            for line in result.stdout.splitlines()
            if line.startswith(PREFIX) and line.endswith('"')
        }
    )
    if not lines:
        die("TLC emitted no TOKEN records")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=FORMAL / "generated" / "token_relation.txt",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = "\n".join(export()) + "\n"
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != payload:
            die(f"{args.output} is stale; regenerate without --check")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(f"token-export: GREEN records={payload.count(chr(10))}")


if __name__ == "__main__":
    main()
