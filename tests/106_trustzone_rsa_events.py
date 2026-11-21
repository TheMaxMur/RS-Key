#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Synchronize RSA session events inside a disposable firmware private operation."""

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = args.work.resolve()
    work.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="rskey-rsa-events-") as folder:
        run(args, root, work, Path(folder) / "source")


def run(args, root, work, tree):
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", str(root), str(tree)], check=True)
    names = subprocess.check_output(["git", "diff", "--name-only", "HEAD", "-z"], cwd=root).decode().split("\0")
    names += subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
    for name in filter(None, names):
        source, target = root / name, tree / name
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        elif target.exists():
            target.unlink()
    source = tree / "crates/rsk-rsa/src/crt.rs"
    body = source.read_text()
    needle = "pub fn private_op("
    assert body.count(needle) == 1
    body = body.replace(needle, "#[unsafe(no_mangle)]\n"
        "pub static RSK_RSA_PAUSE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);\n\n" + needle)
    needle = "\n    let mlen = crt.modulus_len();"
    assert body.count(needle) == 1
    body = body.replace(needle, """
    if RSK_RSA_PAUSE.compare_exchange(1, 2, core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire).is_ok() {
        while RSK_RSA_PAUSE.load(core::sync::atomic::Ordering::Acquire) == 2 {
            core::hint::spin_loop();
        }
    }
""" + needle)
    source.write_text(body)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("RSK_TZ_") and key != "CARGO_TARGET_DIR"}
    env.update(RSK_TZ_PROBE_ADDRESS="", RSK_TZ_GATEWAY_PROBES="0", CARGO_BUILD_JOBS="2")
    subprocess.run(["bash", "scripts/build.sh", "--features", "no-touch"], cwd=tree, env=env, check=True)
    image = tree / "target/trustzone/combined.elf"
    shutil.copyfile(image, work / "rsa-events.elf")
    listing = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image)], text=True)
    barrier = int(next(line.split()[0] for line in listing.splitlines()
                       if line.endswith(" RSK_RSA_PAUSE")), 16)
    assert 0x20000000 <= barrier <= 0x2006fffc
    import sys
    sys.path.insert(0, str(root / "tools/emu"))
    import image_assurance as laboratory
    spec = importlib.util.spec_from_file_location("sessions", root / "tests/96_trustzone_sessions.py")
    sessions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sessions)
    device = laboratory.Device(args.emulator.resolve(), image, work / "store.bin", work, "rsa-events")
    parameters = argparse.Namespace(fido_port=device.fido_port, ccid_port=device.ccid_port,
                                   inspect_port=device.inspect_port, rsa_barrier=barrier)
    try:
        for event in ("abort", "usb-reset", "usb-disconnect"):
            sessions.rsa_event(parameters, event, "sign")
    finally:
        device.close()
    print("PASS: RSA ABORT/reset/disconnect at the private-operation barrier.", flush=True)


if __name__ == "__main__":
    main()
