<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Roadmap

- **Conformance.** Close protocol differences case by case. Compare
  applicable FIDO cases against pico-fido under the same tool and profile,
  and keep accepted differences visible in [Interop](interop.md).
- **Trusted display.** Extend physical coverage for gestures, device PIN
  entry and browser behavior. See the [display guide](guides/display.md).
- **Testing and formal models.** Extend decision coverage, test recovery
  under compound failures and connect more modeled security properties
  to the firmware paths that implement them. The
  [testing roadmap](testing-roadmap.md) gives completion criteria.
- **Post-quantum protocols.** Follow the standards and client support
  for key exchange. The existing ML-DSA signing paths have their own
  command and vector tests.
- **Host tooling.** Improve board setup and ordinary use through the
  [CLI](guides/cli.md), [TUI](guides/tui.md) and platform setup guides.
- **Release verification.** Make it easier to check the exact artifacts
  users download. See [Releases & verification](releases.md).

The project supports the tip of `main`. See
[Limitations](limitations.md) for certification and other scope limits,
and [CHANGELOG](https://github.com/TheMaxMur/RS-Key/blob/main/CHANGELOG.md)
for release history.
