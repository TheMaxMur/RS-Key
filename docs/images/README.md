<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# docs/images

Illustrations for the documentation. Referenced from the `docs/*.md` pages with
**relative** paths (`![…](images/foo.svg)`) so they render both on GitHub and in
the mdBook site.

- Prefer **SVG** for diagrams (crisp, tiny, no theme baked in), **PNG** for
  screenshots, **GIF/APNG** for motion. Keep binaries small: the versioned site
  duplicates `docs/` per build.
- Diagrams are hand-authored unless the Source column says **generated**, and
  self-contained (their own light card, so they read on both the light `rust`
  and dark `ayu` themes; mdBook embeds SVG as an `<img>`, which does not inherit
  page CSS). Palette: two ramps only. Rust for the firmware/code, teal for the
  KV store.
- Third-party screenshots (browser dialogs, `ykman`, GnuPG, ...) keep their
  origin noted here.

| File | What | Source |
|---|---|---|
| `what-it-is.svg` | Landing figure: board + this firmware = what it then does | original — from `README.md` / `index.md` |
| `flash-map.svg` | RP2350-One 4 MB flash address map | original — from `firmware/memory.x` / `flash_storage.rs` |
| `flash-map-sizes.svg` | 4 MB vs 16 MB layout (how `FLASH_SIZE` scales it) | original — from `firmware/build.rs` |
| `ctaphid-frame.svg` | CTAPHID 64-byte init + continuation frame layout | original — from `protocol.md` §1.2 / `tools/rsk/ctaphid.py` |
| `apdu-cases.svg` | ISO-7816 short-APDU cases 1–4 (header, Lc, data, Le) | original — from `protocol.md` §1.1 / `tools/rsk/ccid.py` |
| `phy-record.svg` | EF_PHY TLV record + a worked three-record example | original — from `crates/rsk-phy/src/lib.rs` |
| `cred-box.svg` | FIDO credential box + 42-byte resident id byte layout | original — from `crates/rsk-fido/src/credential.rs` |
| `boot-flow.svg` | Boot sequence: bootrom → provision (pre-attach) → serve | original — from `firmware/src/main.rs` |
| `crate-graph.svg` | Crate dependency layers (binaries → composition roots → applets → shared records → platform → crypto facade → algorithms) | **generated** — `python scripts/crate_graph.py`, from the workspace `Cargo.toml` manifests; the gate fails when it is stale |
| `otp-fuse-map.svg` | OTP rows RS-Key provisions, by page + write path | original — from `tools/rsk/otp.py` / `secureboot.py` |
| `secure-boot-chain.svg` | Host sign → BOOTSEL flash → bootrom verify chain | original — from `production.md` / `picotool seal` |
| `rollback-timeline.svg` | 48-bit rollback thermometer + boot decision | original — from `anti-rollback.md` |
| `led-status.svg` | Status-LED cheat sheet (state → colour/effect), SMIL-animated | original — from `guides/led.md` |
| `tui-cockpit.svg` | rsk-tui cockpit terminal mockup (Overview section) | original — modeled on the running cockpit (`tools/tui`), serial redacted |
| `threat-tiers.svg` | Defense tiers vs out-of-scope (what RS-Key defends) | original — from `threat-model.md` |
| `soft-lock-states.svg` | Soft-lock state machine (Sealed / Locked / Unlocked) | original — from `guides/soft-lock.md` |
| `seed-backup-window.svg` | Seed-export one-time window (No seed / Open / Finalized) | original — from `guides/seed-backup.md` |
| `backup-key-redundancy.svg` | Primary + backup key enrolled at each account | original — from `guides/backup-key.md` |
| `display-home.png` | Trusted display — Home / "Ready" screen | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-pin.png` | Trusted display — Device PIN pad | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-passkeys.png` | Trusted display — Passkeys (empty) | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-apps.png` | Trusted display — Apps browser | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-settings.png` | Trusted display — Settings menu | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-locked.png` | Trusted display — Locked screen | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-approve.png` | Trusted display — Sign-in Approve / Deny prompt | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-approve-lookalike.png` | Trusted display — Approve prompt, padded look-alike rpId clipped to its registrable domain | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-register.png` | Trusted display — "Save new passkey?" enrollment prompt | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-service.png` | Trusted display — Passkeys — per-service detail (accounts, rename) | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-openpgp.png` | Trusted display — Apps — OpenPGP overview | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-piv.png` | Trusted display — Apps — PIV overview | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-oath.png` | Trusted display — Apps — OATH credential list | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-firmware.png` | Trusted display — Settings — Firmware (build, serial, secure-boot state) | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-audit.png` | Trusted display — Settings — Audit log | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `display-backup.png` | Trusted display — Settings — Backup / seed-export window | original — rendered by `rsk_ui::render` at the panel's 240×320 (`rsk-emu --screenshots`) |
| `board-one.jpg` | Photo — Waveshare RP2350-One (reference board) | **Waveshare product photo**, used with attribution (hardware.md) |
| `board-zero.jpg` | Photo — Waveshare RP2350-Zero (mini USB-C stick) | **Waveshare product photo**, used with attribution |
| `board-display.jpg` | Photo — Waveshare RP2350-Touch-LCD-2.8 (display board) | **Waveshare product photo**, used with attribution |
| `board-tenstar.jpg` | Photo — TenStar RP2350-USB (mini USB-A stick) | own device photo, composited on white, EXIF stripped |
