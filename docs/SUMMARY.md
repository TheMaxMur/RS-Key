<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Summary

[Introduction](index.md)

# Getting started

- [Quick start](quickstart.md)
- [Hardware](hardware.md)
- [Build options](build.md)
- [Releases & verification](releases.md)
- [Supply chain](supply-chain.md)
- [Linux host setup](linux.md)
- [Windows host setup](windows.md)

# Using the device

- [The `rsk` CLI](guides/cli.md)
- [FIDO2 / WebAuthn / U2F](guides/fido2.md)
- [SSH keys (`-sk`)](guides/ssh.md)
- [Git: signing + auth](guides/git.md)
- [OpenPGP card](guides/openpgp.md)
- [PIV](guides/piv.md)
- [OATH — TOTP / HOTP](guides/oath.md)
- [OTP slots](guides/otp.md)
- [Seed backup](guides/seed-backup.md)
- [Backup key (pair)](guides/backup-key.md)
- [Soft-lock](guides/soft-lock.md)
- [LED](guides/led.md)
- [Trusted display](guides/display.md)
- [Terminal cockpit (rsk-tui)](guides/tui.md)
- [Audit journal](guides/audit.md)
- [Enterprise attestation](guides/attestation.md)
- [AAGUID & metadata](guides/aaguid-metadata.md)
- [Fleet tooling](guides/fleet.md)
- [FIPS-style profile](guides/fips.md)

# Production hardening

- [Production setup](production.md)
- [Signing keys](signing-keys.md)
- [OTP fuses (RP2350)](otp-fuses.md)
- [Anti-rollback](anti-rollback.md)

# Security

- [Threat model](threat-model.md)
- [Limitations](limitations.md)
- [`unsafe` audit](unsafe.md)
- [Constant-time audit](ct-audit.md)

# Internals

- [Architecture](architecture.md)
- [Host protocol](protocol.md)
- [Testing](testing.md)
- [Interop matrix](interop.md)
- [Versions](versioning.md)
- [Motivation](motivation.md)

<!-- The governance files (CONTRIBUTING, SECURITY, COMPLIANCE) live at the repo
     root and are linked from the Introduction page. They are intentionally not
     nav entries: mdBook does not support external URLs in SUMMARY.md (it rewrites
     .md -> .html and creates broken local stub files). -->

