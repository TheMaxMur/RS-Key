# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The report/APDU shim must reject suites which reach physical USB directly."""

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
RAW_USB_ENTERED = "raw USB suite entered through the emulator shim"


@pytest.mark.parametrize("suite", ["100_trustzone_usb_regressions", "101_trustzone_otp_status", "108_trustzone_hardware"])
def test_raw_usb_suites_are_refused_before_their_physical_backend_is_imported(suite):
    backend = "tz_hardware_run" if suite == "108_trustzone_hardware" else "usb"
    arguments = (["physical", "--image-dir", "/unused", "--serial", "rs-key-0001", "--work", "/unused"]
                 if suite == "108_trustzone_hardware" else ["--serial", "rs-key-0001", "--reader", "RS-Key RS-Key Security Key"])
    setup = f'''
import importlib.abc, importlib.util, sys
class RejectRawUsb(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == {backend!r}:
            raise RuntimeError({RAW_USB_ENTERED!r})
sys.meta_path.insert(0, RejectRawUsb())
spec = importlib.util.spec_from_file_location("emu_scope", "tests/emu.py")
emu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emu)
sys.argv = ["emu.py", "tests/{suite}.py"] + {arguments!r}
'''
    refused = subprocess.run([sys.executable, "-c", setup + "emu.main()"], cwd=ROOT,
                             text=True, capture_output=True, timeout=10)
    assert refused.returncode == 77, refused.stdout + refused.stderr
    assert "SKIP:" in refused.stdout and RAW_USB_ENTERED not in refused.stderr
    unguarded = subprocess.run(
        [sys.executable, "-c", setup + f"emu.UNSUPPORTED.pop({suite!r}); emu.main()"],
        cwd=ROOT, text=True, capture_output=True, timeout=10)
    assert unguarded.returncode == 1 and RAW_USB_ENTERED in unguarded.stderr, (
        "the negative control did not reach the raw USB suite", unguarded.stdout, unguarded.stderr)
