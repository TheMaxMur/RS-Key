# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise the Nix flash app with a recording tool, never a connected board."""
import os
from pathlib import Path
import subprocess
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def flash(tmp_path):
    source = (ROOT / "nix/apps.nix").read_text().split("flashApp =", 1)[1]
    script = source.split("text = ''", 1)[1].split("\n    '';", 1)[0]
    script = textwrap.dedent(script).replace("''${", "${").replace("${firmwarePackage}", str(tmp_path))
    (tmp_path / "firmware.elf").write_bytes(b"ELF")
    (tmp_path / "firmware.uf2").write_bytes(b"UF2")
    for name in ("secure_boot_key.pem", "otp_secureboot.json"):
        (tmp_path / name).write_text("fixture")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "picotool"
    tool.write_text('''#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["FLASH_LOG"], "a") as log:
    log.write(" ".join(args) + "\\n")
if args[0] == "seal":
    assert pathlib.Path(args[3]).read_bytes() == b"ELF", "seal requires ELF"
    pathlib.Path(args[4]).write_bytes(b"SIGNED_ELF")
elif args[:2] == ["uf2", "convert"]:
    assert pathlib.Path(args[2]).read_bytes() == b"SIGNED_ELF"
    pathlib.Path(args[-1]).write_bytes(b"SIGNED_UF2")
elif args[0] == "load":
    assert pathlib.Path(args[1]).read_bytes() == b"SIGNED_UF2"
''')
    tool.chmod(0o755)
    for name in ("rsk", "gpgconf"):
        tool = bin_dir / name
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o755)
    log = tmp_path / "flash.log"

    def run(*args):
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
                   RS_KEY_SECRETS=str(tmp_path), FLASH_LOG=str(log))
        result = subprocess.run(["bash", "-euc", script, "rsk-flash", *args],
                                env=env, input="n\n", text=True, capture_output=True)
        return result, log.read_text() if log.exists() else ""

    return run, tmp_path


@pytest.mark.parametrize("explicit", [False, True])
def test_flash_signs_combined_elf_then_converts(flash, explicit):
    run, path = flash
    args = [str(path / "firmware.elf")] if explicit else []
    result, log = run("--yes", *args)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.splitlines()
    assert calls[0].startswith("seal --sign --hash ")
    assert calls[1].startswith("uf2 convert ")
    assert sum(call.startswith("load ") for call in calls) == 1


def test_flash_refuses_uf2_before_signing_or_device_access(flash):
    run, path = flash
    result, log = run("--yes", str(path / "firmware.uf2"))
    assert result.returncode != 0
    assert "combined ELF" in result.stderr
    assert log == ""
