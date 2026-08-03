<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# docs/images

Illustrations for the documentation. Referenced from the `docs/*.md` pages with
**relative** paths (`![…](images/foo.svg)`) so they render both on GitHub and in
the mdBook site.

- Prefer **SVG** for diagrams (crisp, tiny, no theme baked in), **PNG** for
  screenshots, **GIF/APNG** for motion. Keep binaries small: the versioned site
  duplicates `docs/` per build.
- Diagrams are hand-authored and self-contained (their own light card, so they
  read on both the light `rust` and dark `ayu` themes; mdBook embeds SVG as an
  `<img>`, which does not inherit page CSS). Palette: two ramps only. Rust for
  the firmware/code, teal for the KV store.
- Third-party screenshots (browser dialogs, `ykman`, GnuPG, ...) keep their
  origin noted here.

| File | What | Source |
|---|---|---|
| `what-it-is.svg` | Landing figure: board + this firmware = what it then does | original — from `README.md` / `index.md` |
| `flash-map.svg` | RP2350-One 4 MB flash address map | original — from `firmware/memory.x` / `flash_storage.rs` |
| `flash-map-sizes.svg` | 4 MB vs 16 MB layout (how `FLASH_SIZE` scales it) | original — from `firmware/build.rs` |
| `ctaphid-frame.svg` | CTAPHID 64-byte init + continuation frame layout | original — from `protocol.md` §1.2 / `tools/rsk/ctaphid.py` |
| `apdu-cases.svg` | ISO-7816 short-APDU cases 1–4 (header, Lc, data, Le) | original — from `protocol.md` §1.1 / `tools/rsk/ccid.py` |
| `phy-record.svg` | EF_PHY TLV record + a worked three-record example | original — from `crates/rsk-rescue/src/phy.rs` |
| `cred-box.svg` | FIDO credential box + 42-byte resident id byte layout | original — from `crates/rsk-fido/src/credential.rs` |
| `boot-flow.svg` | Boot sequence: bootrom → provision (pre-attach) → serve | original — from `firmware/src/main.rs` |
| `crate-graph.svg` | Crate dependency layers (binary → applets → platform libs) | original — from the workspace `Cargo.toml` manifests |
| `otp-fuse-map.svg` | OTP rows RS-Key provisions, by page + write path | original — from `tools/rsk/otp.py` / `secureboot.py` |
| `secure-boot-chain.svg` | Host sign → BOOTSEL flash → bootrom verify chain | original — from `production.md` / `picotool seal` |
| `rollback-timeline.svg` | 48-bit rollback thermometer + boot decision | original — from `anti-rollback.md` |
| `led-status.svg` | Status-LED cheat sheet (state → colour/effect), SMIL-animated | original — from `guides/led.md` |
| `tui-cockpit.svg` | rsk-tui cockpit terminal mockup (Overview section) | original — modeled on the running cockpit (`tools/tui`), serial redacted |
| `threat-tiers.svg` | Defense tiers vs out-of-scope (what RS-Key defends) | original — from `threat-model.md` |
| `soft-lock-states.svg` | Soft-lock state machine (Sealed / Locked / Unlocked) | original — from `guides/soft-lock.md` |
| `seed-backup-window.svg` | Seed-export one-time window (No seed / Open / Finalized) | original — from `guides/seed-backup.md` |
| `backup-key-redundancy.svg` | Primary + backup key enrolled at each account | original — from `guides/backup-key.md` |
| `display-home.jpg` | Photo — trusted display, Home / "Ready" screen | own device photo (Waveshare RP2350-Touch-LCD-2.8), cropped, EXIF stripped |
| `display-pin.jpg` | Photo — trusted display, Device PIN pad | own device photo, cropped, EXIF stripped |
| `display-passkeys.jpg` | Photo — trusted display, Passkeys (empty) | own device photo, cropped, EXIF stripped |
| `display-apps.jpg` | Photo — trusted display, Apps browser | own device photo, cropped, EXIF stripped |
| `display-settings.jpg` | Photo — trusted display, Settings menu | own device photo, cropped, EXIF stripped |
| `display-locked.jpg` | Photo — trusted display, Locked screen | own device photo, cropped, EXIF stripped |
| `board-one.jpg` | Photo — Waveshare RP2350-One (reference board) | **Waveshare product photo**, used with attribution (hardware.md) |
| `board-zero.jpg` | Photo — Waveshare RP2350-Zero (mini USB-C stick) | **Waveshare product photo**, used with attribution |
| `board-display.jpg` | Photo — Waveshare RP2350-Touch-LCD-2.8 (display board) | **Waveshare product photo**, used with attribution |
| `board-tenstar.jpg` | Photo — TenStar RP2350-USB (mini USB-A stick) | own device photo, composited on white, EXIF stripped |
