# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk — the RS-Key device CLI.

One command consolidating the host-side tools: device status, wallet-style seed
backup, secure-boot provisioning, OTP-MKEK burn/lock, FIDO management, LED config,
OpenPGP reset, and hands-free reboot. Run from `nix develop` (the flake provides
`rsk` on PATH and all Python deps) or as `python -m rsk`.
"""
__version__ = "0.3.35"
