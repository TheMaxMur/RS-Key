<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Roadmap

Where RS-Key is going, and where it is deliberately not going. Directions, not
dates: this is a single-maintainer project, and a schedule would be a promise
nobody here can keep. What has already happened is in
[CHANGELOG.md](https://github.com/TheMaxMur/RS-Key/blob/main/CHANGELOG.md); why
some things will never happen is argued in [limitations.md](limitations.md).
This page is the middle.

Everything below is a direction, which means it can be abandoned. A direction
that stops being true gets deleted from this page rather than quietly left to
rot — if you find one that no longer matches the tree, that is a bug worth an
issue.

## Where the work is going

**Post-quantum, at the speed of the protocol.** ML-DSA-44, -65 and -87
credentials work today, checked against the NIST ACVP vectors. ML-KEM-768 is
compiled in and reached by nothing, because no CTAP PIN/UV protocol uses it
yet. The direction is to follow that standardisation rather than run ahead of
it: shipping a key-exchange no host speaks would be motion, not progress.

**Formal verification, from pilots to coverage.** The models and their
harnesses already run in CI, with three refinement pilots — the PIN token, the
cross-reset state, the store — tying a model to the code it claims to abstract
([formal.md](formal.md)). The direction is more of the security-relevant state
under models that actually run, and keeping the checks-of-the-checks honest:
a proof nobody executes is documentation with a false badge on it.

**Conformance parity.** The bar is a real YubiKey and the specification, in
that order when they disagree and the spec is on our side, and the other order
when it is not — matching a behaviour real hosts depend on beats being right
alone ([interop.md](interop.md)). The direction is closing divergences one at a
time, each with the measurement that found it.

The next target is conformance parity with pico-fido, compared by applicable
case IDs under the same tool version and profile. Record each build and the
reasons for pending cases: host-test counts and a different runner's totals do
not establish parity. The complete official run on
2026-10-04 reached **250 passed / 4 failed / 70 pending** in 685.92 seconds
([testing.md](testing.md#fido-conformance)).

The `uvm` and `pinComplexityPolicy` extension paths now have dispatcher tests,
including authenticated policy configuration, RP privacy, PIN changes and
reset. Keep the accepted per-device attestation design visible in the results:
its empty root list affects official metadata tests. The standard MDS3 legal
header is restored; P-36 passes in the official Metadata-group rerun, which
reached **25 passed / 1 failed / 11 pending**. A new complete run remains pending.
A published result must list the remaining outcomes alongside its pass count.

The seven failures in the private Go replay are accounted for: three runner
defects are fixed, two enterprise cases pass with the official test fixture,
and two are the accepted empty-root differences. The complete emulator replay
is **223 passed / 2 failed / 70 skipped**, with no exclusions. The official
hardware run also exposed three no-touch HID failures and the old tool's
strictly increasing non-resident counter assertion. The subsequent official
HID-group run on the touch image reached **16 passed / 0 failed**, including
the three previously failing cases. The enterprise test certificate is now
installed, and the complete October 4 touch run passes both EA comparisons and
those three HID cases. Compare the remaining counter and metadata failures and
pending cases against pico-fido; there is no fixed pass-count target.
A separate `largeblob-ext` emulator replay exercised eleven
additional cases but made eleven others inapplicable, retaining **223 passed /
2 failed / 70 skipped**. That alternative build is not a pass-count increase.
A software reboot does not satisfy the board's CTAP Reset window.

**The trusted display.** The variant with a screen is where the anti-phishing
promise lives: what you are approving, shown by something the host cannot
repaint ([guides/display.md](guides/display.md)). The direction is to make that
path as boring and as well-tested as the headless one, because a display that
is occasionally wrong is worse than no display.

**Host tooling.** Fewer steps between a fresh board and a working key — the
`rsk` CLI, the TUI cockpit, and the platform notes for Linux and Windows. Most
of the friction people actually hit is here, not in the firmware.

**Supply chain.** Releases are signed and carry build provenance; the direction
is that every artifact can be verified without taking this repository's word
for anything ([supply-chain.md](supply-chain.md)).

## What this project will not do

Some of these are settled and argued elsewhere; they are listed here so the
absence is a decision rather than an omission.

- **Pursue certification.** Not certified by the FIDO Alliance and not seeking
  it: certification needs a legal entity and fees a hobby project does not
  have. If your threat model requires a certified key, buy one.
- **Maintain release branches.** The tip of `main` is what is supported; a fix
  is a commit there plus an advisory
  ([SECURITY.md](https://github.com/TheMaxMur/RS-Key/blob/main/SECURITY.md)).
- **Promise dates.** See the top of this page.

## How this page changes

By pull request, like everything else, and the maintainer decides
([GOVERNANCE.md](https://github.com/TheMaxMur/RS-Key/blob/main/GOVERNANCE.md)).
Proposals belong in an issue first — the cheapest moment to hear that something
is out of scope is before it is written.
