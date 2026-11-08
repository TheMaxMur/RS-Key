<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Platform assumptions

The firmware and its models depend on properties outside the Rust
applets. The RP2350 must enforce the access policy. The boot ROM must
honor the provisioning and signature policy. Flash and SRAM must behave
as the storage and reset code expect. Compilers, solvers and peripheral
models also affect what a test or proof can establish.

Each assumption has a `PLAT-*` identifier. The
[platform register](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/platform-assumptions.md)
records the expected behavior, what can establish it, and whether there
is evidence. Read the scope of a passing board result before applying it
to another stepping, boot policy or build. The
[board records](https://github.com/TheMaxMur/RS-Key/tree/main/assurance/board)
keep the test criteria with the observations.

See [TrustZone](architecture.md#trustzone) for the firmware boundary,
[Testing](testing.md) for model and hardware checks, and
[Limitations](limitations.md) for assumptions that fall outside the
project's claims.
