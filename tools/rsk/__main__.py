# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk — RS-Key device CLI entry point (`python -m rsk`, or `rsk` in the shell)."""
import argparse

from . import (__version__, audit, backup, bench, fido, hw, identify, inventory, led, lock,
               offboard, openpgp, otp, pair, reboot, secureboot, status)

GROUPS = [status, inventory, identify, backup, pair, lock, secureboot, otp, fido, led, hw,
          openpgp, reboot, audit, offboard, bench]


def main():
    p = argparse.ArgumentParser(
        prog="rsk", description="RS-Key device CLI — status, fleet inventory, seed backup, "
        "primary+backup pairing, seed lock, secure boot, OTP, FIDO, LED, LED hardware wiring, "
        "OpenPGP, reboot, audit, offboard, identify.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"rsk {__version__}")
    sub = p.add_subparsers(dest="group", required=True, metavar="<group>")
    for mod in GROUPS:
        mod.register(sub)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
