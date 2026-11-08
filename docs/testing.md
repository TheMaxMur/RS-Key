<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Testing

RS-Key tests command handling in Rust, drives the same protocols through
an emulator and a real USB device, and boots the combined firmware ELF on
a model of the RP2350. A test of one layer can pass while another fails.
For example, a host test can verify that a USB reset clears a PIN token.
To find out whether Secure firmware sees that reset when Non-secure code
ignores it, run the image suite. For actual USB timing, use a board.

## The two commands

Run from the repository root. Nix supplies the pinned tools.

```sh
nix develop -c ./scripts/check.sh
nix develop -c ./scripts/check-assurance.sh
```

`check.sh` is the per-commit gate. It builds and checks firmware, runs
host tests across feature sets, checks the final image and tests the
supporting tools. `check-assurance.sh` checks the model wiring, assurance
registries, citations, test rosters and published evidence. Pull requests
also run bounded proofs and emulator jobs. See [CI parity](#ci-parity)
for the split.

| Harness | What executes | Example failure it finds |
|---|---|---|
| Cargo tests | Rust crates and test backends on the host | A PIN retry counter changes after a rejected request |
| Applet emulator | Shared applet and store crates, with host transport and device hooks | A malformed CCID exchange leaves a selected applet in the wrong state |
| Image emulator | Secure and Non-secure firmware ELF on modeled RP2350 hardware | A reply from an old USB epoch reaches a new session |
| USB/IP | An emulator backend and a Linux USB host stack | A client rejects a descriptor or fails to open a HID interface |
| Board | Firmware on RP2350 silicon, driven over USB or through board inputs | A real reset, panel gesture, OTP access or cache behavior differs from the model |
| Independent client or oracle | A protocol client, test vector, reference implementation or second device | A signature passes an internal round trip but fails independent verification |

## Host tests

The firmware is `no_std`. Parsers, applet state machines, record codecs,
cryptography and much of the transport and recovery logic live in
`crates/rsk-*` so Cargo can test them on the host. The host suite exercises
request parsing and response encoding, PIN and token policy, applet
selection and state changes, flash recovery, and crypto against known
answers. The firmware supplies the hardware implementations of the traits
those crates use.

The workspace defaults to the embedded target. Select the host explicitly.

```sh
nix develop
host_target="$(rustc -vV | sed -n 's/^host: //p')"
cargo test -p rsk-fido -p rsk-store --target "$host_target"
```

Feature sets change behavior. For example, `always-uv` changes which FIDO
requests require user verification, `fips` filters algorithms, and storage
profiles change which records can appear on flash. The gate exercises the
declared host configurations and builds firmware for multiple flash sizes
and a display board. See [Build options](build.md) for feature constraints
and the [configuration matrix](assurance-matrix.md) for assurance scope.

### Boundary values and regression tests

Tests cover empty and truncated requests, exact buffer limits, excessive
lengths, wrong tags, invalid enum values and counter boundaries. The
stateful cases follow a command across retries, cancellation, applet
changes, reboot or interrupted writes. For an authorization bug, the
expected result includes what did and did not change. A rejection status
is insufficient if the device also consumes a retry, retains a token or
leaves a partially updated record.

Regression tests use the narrowest harness that can reproduce the fault.
Host tests can fix the order of a read failure and a retry. Image tests
can place a reset between dispatch and reply. USB tests check observable
protocol behavior such as framing and status words through the ordinary
client path.

## Without a board — the emulator

The default `rsk-emu` backend runs the real applet and store crates on the
host. Its NOR model uses the same flash geometry and storage code as the
device. It has its own worker sequencing and device hooks. CTAPHID and
CCID travel over sockets. `tests/emu.py` supplies compatible HID and
smart-card modules to the numbered Python tests and can request an emulator
replug. It refuses tests that need raw USB or physical effects, with a reason
and exit status 77.

```sh
nix develop -c ./scripts/emu-suites.sh
```

That runner starts clean stores for separate sessions, runs applicable
numbered suites, runs upstream card tests, and compares selected public
descriptors and capabilities against the checked-in YubiKey baseline.
For single-test commands and emulator options, see the
[emulator README](https://github.com/TheMaxMur/RS-Key/blob/main/tools/emu/README.md).

### The image itself — `--image`

The image backend starts the combined Secure/Non-secure ELF through the
RP2350 boot ROM on picoem. Firmware talks to models of the USB controller,
OTP, flash, SHA-256, TRNG and other peripherals. Its USB host controller
enumerates the firmware and sends endpoint traffic. These tests execute
the linked worker, its applets, the NS transports, interrupt routing and
the gateway ABI. Loading an ELF this way leaves production signature
enforcement and physical bus behavior for board tests.

```sh
nix develop -c ./scripts/image-suites.sh
```

The runner builds an ordinary no-touch image and separately builds
diagnostic images. It keeps their logs and reports apart. Its checks
include startup, crypto keepalives, gateway spans and tickets, hostile NS
loads and stores, reset and reconfiguration, presence, core1 failure,
and recovery after a Secure or Non-secure fault. The inspection port gives
selected tests access to modeled SRAM, stack pointers and power cuts.

The image tools in
[`tools/emu`](https://github.com/TheMaxMur/RS-Key/tree/main/tools/emu)
also drive operation and persistence matrices. They verify signatures,
inspect per-command stack high-water marks, search for known secret bytes
after an operation, and cut power with writes in flight. Dedicated runners
exercise backup and restore, RSA key generation, OTP provisioning and
BOOTSEL/PICOBOOT traffic.

Run an individual image scenario after the full runner has built its inputs,
using a fresh output directory. The example below reruns power cuts. Set
`emu` to the native emulator binary and `elf` to the runner's ordinary
partitioned ELF.

```sh
python tools/emu/image_assurance.py --emulator "$emu" --image "$elf" \
  --work target/image-cuts --only cuts
```

`basic` covers startup and the boundary probes with the corresponding
diagnostic ELFs. `stack` exercises stack-heavy operations, including
ML-DSA and RSA. `operations` checks the command matrix against the
applet and image backends. The separate `upgrade` scenario needs an
older release image and checks persistence across the firmware change.
Reports identify the emulator and images by hash.

### USB/IP

`rsk-emu --usbip` exports a USB device to Linux. A guest using `vhci_hcd`
can run libusb, HID and PC/SC clients through the normal OS stack.
`scripts/usbip-suites.sh` runs the USB-dependent suites in that setup.
This covers host enumeration and client binding that the socket shim
bypasses. The controller and link are still modeled. Use a physical
device for electrical behavior, real power cycles and on-device timing.

### Display image testing

`tools/emu/image_display.py` runs a touch-enabled display image with the
modeled panel and touch input. Its ceremony cases check approve, deny,
cancel, and a hold too short to approve. Other cases exercise stale touch,
press and release behavior, deadlines, and on-device PIN entry for FIDO
and CCID. The driver checks both the visible prompt and the host reply.
The PIN cases distinguish digits shown on the device from the result
returned through the transport.

| Selector | Assertion |
|---|---|
| `ceremonies` | Deny and cancel produce their host statuses. A short hold cannot approve sign-in. Approval returns a usable credential or assertion. |
| `stale` | A queued touch from an earlier prompt cannot approve a new one. |
| `physical` | A slide, lift or cancel from another channel does not authorize the pending request. |
| `timeout` | The image clock expires the prompt and the host receives the terminal response. |
| `pin` | Device PIN setup, mismatch, cancellation, retries and recovery across reboot follow policy. |
| `fido-pin` | ClientPIN obtains a token via the display and uses it in an authenticated command. |
| `ccid-pin` | CCID Secure PIN operations reach the applet with the expected PIN handling. |

Run a single case from the Nix shell with a combined image built for the
display board and a native `rsk-emu` binary. For example, for a denial:

```sh
python tools/emu/image_display.py --emulator "$emu" --image "$elf" \
  --work target/display-deny --only ceremonies --case deny
```

The headless test feeds events to the emulator's input queue. A physical
panel run still checks its controller, touch alignment, hold timing and
the browser's behavior after the authenticator answers.

## Storage and failure injection

The unit-test store and the emulated NOR flash let the suite choose where
a write fails. Tests exercise the same storage invariants from different
places.

| Failure | What the test looks for |
|---|---|
| Read, program or erase error | The operation reports the right error. An unreadable record does not silently become an empty slot or a default authorization state. |
| Silent lost or torn write | Recovery recognizes what actually reached flash, including an incomplete record or a write that returned success without persisting. |
| Corrupt, truncated or substituted record | Length checks and record authentication reject the data. A record for another key or role cannot stand in for the requested one. |
| Reset during mutation | On reopen, committed data is coherent and any accepted pre- or post-operation result satisfies the operation's recovery contract. |
| Second failure during recovery | The next mount can recover again. Interrupted cleanup cannot make a deleted credential or an old authorization usable. |
| Full store, wrap or reclamation | Capacity errors and compaction preserve live records and counter ordering. |

The stateful `fs_ops` fuzzer compares sequences of storage operations with
an independent model. `power_cut` adds cuts and remounts across record and
recovery boundaries. The image tests take the same question to the
delivered ELF by interrupting a modeled program or erase and rebooting
with the flash left behind. Each result is tied to the fault positions and
profile exercised. Endurance, brownouts and the XIP behavior of real
flash during an erase need hardware measurements.

## Independent result checks

A round trip can preserve the same error in its writer and reader. Crypto
tests include known-answer vectors from ACVP and Wycheproof, and command
tests verify outputs with host implementations where possible. The
ML-DSA tests include independent client or cross-verification paths.
Signature checks verify the message and the key as well as the return
status. Storage tests compare with an independent state model or reopen
persisted bytes and query through the normal command path.

| Applet | Examples exercised through commands |
|---|---|
| FIDO2 and U2F | Registration, assertions, PIN/UV token scope, retries, resident credentials, extensions, reset and attestation |
| PIV and OpenPGP | PIN and management authentication, private operations, key and certificate lifecycle, command chaining and reset |
| OATH and OTP | TOTP/HOTP calculations, counters, authorization, HID and keyboard reports, touch waiting and cancellation |
| Management and recovery | Settings, soft lock, backup and restore, OTP migration and factory reset |

## On-device tests

Numbered scripts under `tests/` drive a key over USB. Use a disposable
board or a dedicated test state. Some suites change credentials, counters
and configuration or request reset. Read the script's arguments before
selecting a board. Most automation uses a test build with `no-touch`.
Presence, trusted-display and timing tests need their stated hardware
and build settings.

```sh
nix develop -c python tests/10_fido_getinfo.py
nix develop -c python tests/80_piv.py
```

The test groups cover CTAPHID and CCID transport, applet lifecycles,
persistence, PIN pad and button behavior, and hardware-related TrustZone
checks. The USB reset suites use the real host stack when they require raw
USB. A software reboot is a separate case from removing power, particularly
for the CTAP Reset window and tests that require cold boot.

### TrustZone on hardware

`tests/108_trustzone_hardware.py` builds disposable diagnostics in a
separate checkout and runs a model or physical case against the matching
image. It checks that a hostile NS access faults with the expected status,
that the fault fences USB and clears pending work, and that PIV is usable
after recovery. Read and write matrices cover selected protected resources.
The board runner identifies the image and board and records the observed
fault rather than treating a lost USB connection as success. A positive
control must complete an ordinary NS access. For a protected peripheral
load or store, the diagnostic compares the captured fault address and
status with the expected access and checks that USB has been fenced.
Removing the fence in a control image must fail the latter check.

```sh
nix develop -c python tests/108_trustzone_hardware.py build --work target/tz-hw-image
```

After the maintainer loads the matching diagnostic onto a test board,
the `physical` subcommand takes `--image-dir`, `--serial` and a fresh
`--work` directory. Pass `--matrix read` or `--matrix write` to select
a resource sweep. `verify-record` checks a saved capture. These images
are laboratory artifacts.

`tests/101_trustzone_otp_status.py` checks the public OTP-status protocol
and access policy through the host paths it exercises. A privileged NS
load from page 58 is a separate test from reading OTP in BOOTSEL. Its
negative result needs a positive control, such as a successful read of
ordinary NS RAM. Results before and after sealing, and results with
enforced Secure Boot, describe distinct configurations. The
[TrustZone verification record](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/trustzone-verification.md)
and [board evidence](https://github.com/TheMaxMur/RS-Key/tree/main/assurance/board)
give the scope of recorded runs.

## The vendored upstream suites

`tests/third_party.py` runs upstream tests using the client's own stack.
The OpenPGP suites exercise card commands and status words. Yubico's
`ykman` tests cover PIV, OATH, OTP, OpenPGP and management. Over the card
socket they can see CCID only. The pico-fido suite and selected
`python-fido2` suites use an appropriate USB path. A runner records cases
outside the interface or advertised feature set separately.

```sh
nix develop -c python tests/third_party.py openpgp
nix develop -c python tests/third_party.py ykman
```

### FIDO conformance

The FIDO Alliance tools, the vendored pico-fido tests and the native Rust
conformance tests have different case lists. Compare case IDs under the
same tool, profile, attestation fixture and presence policy. Keep failures
and pending reasons with the pass count. In particular, optional extension
advertisement, enterprise credentials and HID behavior affect applicability.
Recorded runs are in the
[testing evidence](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/testing-evidence.md#fido-conformance).

### Real-world interop

The [interop matrix](interop.md) lists the clients and operations exercised
on real hosts. The reproducible emulator sweep checks getInfo, ATR and
management DeviceInfo against a frozen YubiKey baseline. Two-device
differential tests and browser, desktop, or touch ceremonies need the
actual clients and devices. The comparison rules record accepted
differences explicitly.

## Fuzzing

`fuzz/` uses libFuzzer with the pinned nightly. Some targets feed bytes to
a parser or record decoder. Stateful targets generate related operations
over one session or one flash image. These can find a bad transition after
several individually valid commands. Oracles check properties such as
whether a rejected command changed state or recovery exposed an object
that had already been removed.

```sh
nix develop .#fuzz -c ./scripts/fuzz-all.sh
nix develop .#fuzz -c ./scripts/miri-all.sh
```

Committed seeds, generated dictionaries and external corpora reach inputs
that random bytes seldom produce. For example, a seed can get through
CTAPHID reassembly, CBOR decoding and PIN authorization before a
mutation changes a later operation. A frame fuzzer and a session fuzzer
reach different classes of bugs.

| Target or group | Input and oracle |
|---|---|
| `apdu_frame`, `ccid_frame`, `ctaphid_roundtrip` | Frames and reassembly. Check bounds, length handling and valid round trips. |
| `fido_cbor`, `fido_session`, `fido_session_token` | Request bytes and command sequences. Check dispatch, authorization and state after refusals. |
| `cross_applet` and OATH variants | Switch applets between commands. Check that one applet's authentication and capabilities do not authorize another. |
| `fs_ops`, `power_cut`, `authenticated_store_v2` | Mutations and damaged or partially written media. Check recovered state and authenticated record handling. |
| `otp_hid`, `ccid_secure_pin`, `display_label` | Host reports and display input. Exercise length, copy and presentation boundaries. |
| Crypto targets | Valid and malformed encodings, known invariants and implementation comparisons where available. |

For a focused run use `cargo fuzz run power_cut -- -max_total_time=60`
from `nix develop .#fuzz`. `fuzz-coverage.sh` reports source
coverage from corpus replay. `fuzz-dimensions.py` reports which fault and
operation ranges a corpus actually visits. A coverage report describes the
inputs retained for that run. Minimized failing inputs can be replayed,
then pinned as regression tests when the expected behavior is known.

## Branch and condition measurements

Line coverage tells whether a source line ran. Branch coverage tells
whether its decision took each outcome. Modified condition/decision
coverage (MC/DC) asks whether each Boolean condition can independently
change the decision. For `pin_valid && presence`, the pair
`(true, true)` and `(true, false)` tests the effect of presence. Testing
`(false, false)` alone also reaches the deny branch but tells nothing about
that effect. Short-circuit evaluation and conditions coupled by an
invariant matter when choosing pairs.

The scheduled line-coverage row uses `cargo llvm-cov` on the host crates.
Use the nightly shell for branch and condition instrumentation.

```sh
nix develop .#fuzz
host_target="$(rustc -vV | sed -n 's/^host: //p')"
CARGO_TARGET_DIR=target/coverage-branch cargo llvm-cov --branch \
  --target "$host_target" --workspace \
  --exclude firmware --exclude firmware-ns --exclude rsk-wipe
```

Use a separate build with `RUSTFLAGS='-Z coverage-options=condition'`
for condition instrumentation. Omit `--branch` from that build command,
since it selects branch mode. Inspect the source review for decisions
the compiler does not instrument, including some error propagation.
The MC/DC reports use Supercov with source-bound witnesses for selected
command decisions and wider library measurements. They keep frontend
limitations, coupled decisions and uncovered conditions visible. Host
numbers apply to the instrumented profiles. Worker measurements and image
checks have separate scope, especially for const evaluation, expanded
macros, C and assembly. See the
[coverage reports](https://github.com/TheMaxMur/RS-Key/tree/main/assurance/reports).

### Mutation and negative controls

A mutation deliberately changes a condition or removes a check. A surviving
mutation prompts a review of whether the changed behavior is observable,
whether a case is missing, and whether the relevant target even ran.
`scripts/mutants-container.sh` runs the host mutation suite. For a crate
change, `--in-diff HEAD` limits the run to the working diff. The deep
workflow compares the broad run with the accepted survivor list.

Image tests also use deliberate faults, for example an NS attempt to write
USBCTRL or DMA registers. The corresponding normal operation serves as a
positive control. Gate tests make an invalid change and check that the row
which runs in CI rejects it. A build error, an unrelated assertion or a
skipped test gives no evidence about the intended defect.

## Kani proofs

Kani checks bounded Rust harnesses for specific properties such as codec
round trips, buffer bounds, arithmetic or allowed transitions. The
harness fixes the input domain and unwind limits. The proof applies
within that domain. The tier runner checks the proof roster and tracks
the checks and covers each tier is expected to execute.

Install the Kani version pinned in [CI](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/ci.yml)
with `cargo install --locked kani-verifier --version <pin>`, then run
`cargo kani setup` outside the Nix shell. Setup fetches the model checker
bundle. Run the pull-request tiers from the repository root.

```sh
./scripts/kani.sh pr
./scripts/kani.sh state
```

A harness for the APDU dispatcher checks pairs of short APDUs for
command-chaining isolation. Crypto and record helpers check properties
such as modular reduction and encoded-length bounds. Some harnesses
use smaller buffers under `cfg(kani)`. See the
[proof roster](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/testing-evidence.md#kani-proofs)
for those bounds and the weekly tiers. Cover statements exercise
required paths so a proof cannot pass simply because its setup excludes
the interesting inputs.

## The security-state model (TLA+)

TLC explores finite models of authentication, reset and storage state.
Safety checks look for forbidden states. Liveness checks ask whether
modeled progress eventually occurs under the stated assumptions. The
checked-in runners apply deliberate model mutations. A model mutant must
violate the expected property. Co-refutation carries selected defects
into Rust and expects a named test to fail for the matching reason.

```sh
nix develop -c ./formal/run-tlc.sh safety
nix develop -c ./formal/run-tlc.sh liveness
nix develop -c python scripts/comutate.py run
```

### Formal claims — what is and is not verified

The [formal model](formal.md) explains what each model abstracts.
[Platform assumptions](platform-assumptions.md) covers dependencies the
models take as inputs, including hardware behavior and tool fidelity.
A Kani proof of a codec and a TLC result about a session apply to their
specified scopes. Trace and refinement checks connect some of those
scopes to Rust. RS-Key has no whole-firmware proof.

## Dynamic analysis and resource limits

Miri replays supported host code to find Rust undefined behavior,
including invalid memory accesses and aliasing. The image suite samples
embedded stack use and searches SRAM for known test secrets after
commands and reset. These tests can find leftover state at the points
they inspect. The [unsafe audit](unsafe.md) and the
[constant-time audit](ct-audit.md) cover implementation details outside
those observations.

Host and image cases exercise maximum frames, APDU chaining, crypto
scratch space and concurrent activity such as USB keepalives during RSA.
Most buffers have fixed bounds. The RSA path also uses a bounded heap
that wipes freed blocks.
The build checks the final section placements, flash fences and declared
resource limits. The board-only residue diagnostics and latency harness
measure the physical device.

### Optimized and unoptimized images

Run the ordinary release ELF for firmware behavior, timing and layout
checks. The separate Rust `opt-level=0` image campaign checks that selected
operations also complete and fit when Rust optimization is disabled.
The campaign uses domain-specific build settings, and C and assembly
remain separately compiled. The
[image campaign record](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/testing-campaigns.md)
lists the exact profiles and observed outcomes.

## Host tools

The Python `rsk` CLI and Rust TUI have their own tests. They cover command
arguments, status parsing and presentation, and transport behavior.
The TUI is a separate Cargo workspace and has a separate Nix shell. The
gate runs its format, lint and test rows alongside the firmware and
emulator checks.

## Latency harness

`rsk bench` uses a diagnostic firmware feature to time operations with
the RP2350 timer, excluding USB round trips. It reports a cold sample,
warm median and median absolute deviation. Save both runs and use
`rsk bench --compare` to compare builds in the same setup. A linker layout
change can move hot code relative to the XIP cache. The image backend
does not model physical cache misses, so suite 105 measures getInfo on
a board.

## CI parity

| When | What runs |
|---|---|
| Per commit locally | `check.sh`, including builds, host tests, static checks and supporting tool tests |
| Pull request | The gate and assurance jobs, bounded proofs, and emulator jobs in their workflow environments |
| Scheduled | Longer proof and TLC tiers, fuzzing and corpus reports, Miri, mutation and reproducibility checks as defined by the workflows |
| Release | Clean build and reproducibility checks, artifact manifests, signing and verification. Board runs have separate records. |

Static checks include Clippy, dependency and supply-chain checks, an
audit of executable sections, image composition and storage boundaries,
and constant-time and owner-binding checks on the built code. Read
[`ci.yml`](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/ci.yml),
[`emulator.yml`](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/emulator.yml)
and [`deep-checks.yml`](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/deep-checks.yml)
for the current triggers and profiles.

## Reproducing a result

Use [Reproducing the evidence](reproducing.md) to choose a tier. For a
result you intend to compare, keep the commit, image hash, feature and
board configuration, tool versions, exact command and outcome. For
a failure-injection result, keep the failing phase and fault position.
For a fuzz result, keep the minimized input and the oracle that failed.
Keep skipped and refused cases with their reasons. A board report also
needs the silicon stepping, boot policy and whether the run started from
cold power.

Long run logs, coverage catalogues, mutation reviews and hardware scope
records live under
[`assurance/reports`](https://github.com/TheMaxMur/RS-Key/tree/main/assurance/reports).
The [testing roadmap](testing-roadmap.md) lists work still open.
