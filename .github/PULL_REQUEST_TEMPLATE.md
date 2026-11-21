## What

<!-- What changes, and why. A couple of sentences is fine; link the issue if there is one. -->

## How it was tested

<!-- Keep what applies, delete the rest. -->

- [ ] `nix develop -c ./scripts/check.sh` passes locally
- [ ] `nix develop -c ./scripts/check-assurance.sh` passes locally (once, before opening this PR)
- [ ] On hardware: board = …, what was exercised = …
- [ ] Host-only change (CLI / docs / CI) — no device behavior touched

## Checklist

<!-- Tick what applies; "N/A" is fine — most host-only PRs leave the firmware lines blank. -->

- [ ] Device behavior / image changed → `config.device_release` (bcdDevice) bumped by one (hex)
      in `firmware/src/main.rs` — host-only (CLI / docs / CI / build) does not (CONTRIBUTING.md)
- [ ] Fixes something a downgrade would reopen → flag whether the next release should advance the
      rollback **epoch** (`docs/production.md`, stage 3) — a seal-time `--rollback` call, not a code bump
- [ ] New or changed `unsafe` → justified in `docs/unsafe.md`
- [ ] User-visible behavior → the matching guide under `docs/` updated
- [ ] New files carry the SPDX header (`AGPL-3.0-only`)
- [ ] Commit messages use the zone prefix style (`fido:`, `piv:`, `rsk:`, `docs:`, …)
