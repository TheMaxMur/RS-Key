<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# TrustZone boundary and resource ownership

This is the chosen boundary for production TrustZone integration. It is a design
contract, not an isolation claim for the current firmware. The ordinary build
has no Secure/Non-secure split. The experiment inspected on 2026-10-14 at
`bcdDevice 0x0AA5` runs transports in Non-secure (NS) and the worker and applets in
Secure (S), but still trusts NS to report USB lifecycle events. This document
changes no executable code, wire format, persistent layout or retry policy.

## Attacker and trusted code

Assume arbitrary code execution in privileged NS, including its interrupt
handlers. The attacker can replace transport state, buffers, channel identifiers,
session counters and every NS callback; call gateways directly; suppress, replay
or fabricate messages; and stop serving USB. NS claims about the host or user
are untrusted inputs.

The S trusted computing base includes startup and security configuration, the
CMSE gateways, worker, all applets and their parsers, crypto, storage, entropy,
presence and trusted display, core1's RSA engine, and the USB hardware front-end
chosen below. TrustZone does not isolate these S components from one another.
The bootrom, signed-image coverage, compiler-generated entry/return sequences
and silicon access filters are dependencies to validate before claiming this
boundary. The existing [threat model](threat-model.md) still applies to the
ordinary firmware.

The target is to prevent NS from reading retained private keys or OTP roots,
changing S memory/code or protected peripheral policy, and manufacturing PIN,
management-key or physical-presence authorization inside S. Existing authorized
protocol outputs remain available. A compromised NS can act as a hostile host
within rights that a user has actually granted; plain APDU PINs, imported secrets
and response bytes that traverse NS are visible to it. A PIN entered on the
trusted display stays in S. USB availability, secrecy of plaintext transport
payloads, physical fault injection and the existing external-flash XIP residual
are not new TrustZone guarantees. Reset revokes cached S authorization; it cannot
make a PIN previously seen in a plain APDU unknown to NS or prevent NS from
authenticating again with a credential it knows under the existing applet policy.

## Resource owners

Ownership below includes access through aliases, DMA, ROM services and the other
core. A default register value is not evidence of an enforced boundary. Unused
peripherals remain S-only until a specific NS use is justified.

| Resource | Current experiment | Production owner and permitted NS use |
|---|---|---|
| Core0 | S worker in SWI_IRQ_0; NS USB/executor | S startup, worker and security policy; NS class/transport executor |
| Core1, RSA mailbox, its DRBG and stack | S RSA engine | S only; NS cannot launch work, read primes or disturb its flash-pause protocol |
| S code, vector tables and NSC gateways | S flash plus CMSE veneers | S boot/update policy; NS enters only declared NSC gateways |
| NS code and vector table | Embedded NS image | NS execution; S verifies the complete image and controls updates |
| KV main/counters and flash programming | S worker | S only, including QMI/XIP controls and destructive ROM operations |
| S SRAM, stacks, allocator, applet state and request exchange | S | S only; no shared Rust references, mutexes, wakers or secret-bearing mailbox |
| NS SRAM and transport buffers | NS | NS; S validates spans and copies requests into S storage |
| USBCTRL, USB DPRAM/control words, USBCTRL_IRQ, masks and event acknowledgement | NS direct HAL driver | S bounded hardware front-end; NS gets endpoint operations and copied events, not raw MMIO/DPRAM access |
| USB bus epoch and reset latch | NS counter plus S ticket state | S hardware observer owns the epoch; NS may keep a presentation copy or request revocation |
| USB classes, CTAPHID, CCID, OTP HID/keyboard framing and keepalive timers | NS | NS; framing and identifiers confer no S authorization |
| USB identity, interface mask and endpoint allocation | Hard-coded NS identity | S loads/validates persisted configuration; NS receives a bounded public snapshot; S admits only that endpoint layout |
| TIMER0 and security/authorization deadlines | S | S only |
| TIMER1 and NS executor timer queue | NS | NS TIMER1 only; shared TICKS, clock and reset controls stay S |
| TRNG, DRBGs, OTP secrets and fuse operations | S | S only; ordinary gateways expose no raw entropy, secret rows or fuse primitive |
| Presence button, its GPIO/QSPI path and trusted display/touch input | S decision logic; no-touch, no display | S hardware and decision; NS can query waiting status or cancel, never report a successful press/PIN |
| LED, PIO/PWM, SPI/I2C and display/presence GPIO | Disabled or unused by this experiment | S board layer; NS presentation requests cannot reconfigure trusted input/output |
| DMA channels, descriptors, IRQ/DREQ routing and DMA MPU | No explicit complete policy | S only initially; descriptors cannot be supplied by NS or target S state through an NS-controlled channel |
| SIO FIFO, spinlocks and cross-core reset/launch | S engine uses reserved resources; NS masks its own interrupts | S reserves cross-core resources; NS cannot seize S locks or impersonate a core1 handshake |
| SAU, S/NS MPU policy, security attribution and interrupt routing | Partial startup setup | S; NS banked controls must not alter S resources or bypass reset checks |
| Clocks, RESETS, watchdog, POWMAN, debug/security controls and ROM service access | No complete deny policy | S; NS requests are bounded commands, not register writes or arbitrary ROM calls |

S IRQ handling must observe USB lifecycle events during synchronous S crypto.
Its masks, target and acknowledgement path must be inaccessible to NS. The
priority design must also keep honest NS keepalives running; enabling `PRIS`
without checking the S worker/NS executor ordering is not an acceptable shortcut.
Hardware filters, MPU attributes and peripheral grants must be checked for both
cores and every bus master before USB attachment. This is pending implementation.

The inspected 4 MiB experiment uses the following linker/SAU bounds. These are
the current layout, not fixed production offsets for every board. Production
must derive the boundaries from the combined image and retain each board's
existing KV layout.

| Region | Current address range | Owner |
|---|---|---|
| S code | `0x10000000..0x101fefff` | S |
| NSC entry veneers | `0x101ff000..0x101fffff` | S, callable only through declared entries |
| NS code | `0x10200000..0x1027ffff` | NS execution; S update policy |
| KV main/counters | `0x10280000..0x103fffff` | S |
| S SRAM | `0x20000000..0x2006ffff` | S |
| NS SRAM | `0x20070000..0x2007ffff` | NS |

Boot RAM and other SRAM/XIP aliases are not additional shared buffers. Their
access policy must preserve the underlying region's owner.

## Gateway and data contract

The shared request/reply constants live in `rsk_usb::worker_abi`
(`crates/rsk-usb/src/worker_abi.rs`) and are imported by both images through Cargo.
The existing `submit`, `poll` and `control` entries in
`firmware/src/trustzone/gateway.c` illustrate the command boundary. Production
keeps fixed, bounded values and byte copies. S validates the operation, complete
buffer span, length and capacity, then parses the copied request and applies
the applet's authorization policy. Ordinary command buffers must be in designated
NS data memory, not MMIO, ROM or USB control memory that happens to pass an access
probe. It retains no NS pointer or callback across
a dispatch. CMSE return cleanup and exception/FPU state must not expose S data.
S binds any pending presence or trusted-display approval to its copied request
and bus epoch; an old approval cannot authorize a replacement request from NS.

Tickets identify a copied job, not a principal or permission. CTAPHID CID, CCID
sequence and an NS epoch cannot create or restore authorization. S mints job
identifiers in its own bus epoch, refuses old identifiers and never wraps into
a live identifier; exhaustion fails closed until a scrubbed S reboot. `poll`
only exports a result still valid in that epoch. Cancellation and reset requests
from NS can reduce rights or availability, never refill retry budgets or renew
an authorization. Card reset remains distinct from a USB-wide session reset.

The S USB front-end will need a separate bounded endpoint interface. It accepts
only allocated endpoints, checked spans and the current S bus epoch. It exposes
no general register-write, IRQ-mask, reset-flag-clear or peripheral-reset command.
S owns endpoint buffers/control words and captures the physical EP0 setup packet
before NS handles class requests. It observes configuration loss independently
of an NS claim that a setup request was received or accepted. Application payload
parsing and USB class policy stay outside this small hardware front-end.

## USB reset decision

**Keep the hardware observer in S and deny direct NS access to USBCTRL and its
control memory.** USB classes and transports remain NS; the low-level controller
driver and lifecycle observer become part of the S trusted computing base.
This is a deliberate change from putting the entire USB HAL in NS.

The RP2350's `SIE_STATUS.BUS_RESET` is software-clearable and the bus-reset IRQ
enable is writable. `ACCESSCTRL_USBCTRL` grants access to the register block by
master and security/privilege level. These facts come from Raspberry Pi's
[USB register definitions](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2350/hardware_regs/include/hardware/regs/usb.h)
and [ACCESSCTRL definitions](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2350/hardware_regs/include/hardware/regs/accessctrl.h).
Thus an S callback, periodic S polling or an S-targeted IRQ alone cannot prove
reset observation while NS can clear the latch, disable the source or reset the
controller. An NS MPU restriction imposed by NS has the same trust problem.
Expiring authorization on a timer only bounds exposure; it does not establish
revocation at reset and would change existing session behavior.

The production reset sequence is:

1. The S front-end observes the physical reset latch. At every authorization
   admission, job dispatch and result-release boundary, S also checks pending
   hardware lifecycle events before using the current epoch. This check does not
   depend on an NS callback, polling frequency or a masked interrupt-status view.
2. Under S-owned serialization, it revokes the epoch, fences new work and old
   results, and invalidates pre-reset endpoint transfers **before** acknowledging
   the reset latch. These actions precede any notification to NS. An event racing
   a boundary is ordered before or after that boundary, never lost in between.
3. A queued request is wiped without dispatch. Synchronous crypto already in
   progress may finish, but its old-epoch result cannot be newly exported. The
   worker then wipes request/reply storage and all affected session authorization.
   No acknowledgement or `poll` from NS is required to perform cleanup.
4. Only after cleanup and the S front-end's valid bus/configuration transition
   can a new job be admitted. Old tokens/tickets fail. A user can authenticate
   again through the existing protocol, without gaining a new retry budget.

Logical revocation is immediate when S observes the hardware event; physical
RAM scrubbing can wait for a non-interruptible operation to return. This decision
does not promise an instantaneous scrub or a hard real-time reset latency.
A command admitted before reset may finish its existing persistent effects;
revocation does not interrupt synchronous dispatch or turn it into a transaction.
No later command may inherit its cached authorization. Committed flash writes
are not rolled back. Bytes already exported to NS cannot
be recalled, and NS can replay its own saved response bytes; the guarantee is
that S grants no new use of revoked authorization and releases no pending reply
from the revoked epoch. The front-end must serialize final release/endpoint
arming with reset processing; a single check at `submit` is insufficient.

The cleanup scope covers PIV PIN/fresh-PIN and management authentication,
OpenPGP PW security status, OATH validation and OTP-PIN status, management/vendor
session state, FIDO PIN/UV tokens and pending operations, applet selection,
chaining/GET RESPONSE buffers, pending presence/PIN collection and OTP output.
Persistent keys, configuration, retry counters and FIDO's per-boot PIN failure
budget are preserved. Cleanup must enumerate applet state, not rely on NS's
account of which applet was selected. The current experiment has tests for PIV
and FIDO cleanup; those tests do not establish this entire scope.

S-observed suspend and configuration loss conservatively revoke the session too.
Resume does not restore authorization. A powered disconnect can only be claimed
where a real controller/board signal is observable by S; a software event injected
by the emulator is not a physical VBUS measurement. Full loss of MCU power
starts a fresh boot with no restored volatile authorization. Repeated hardware
events and NS-requested resets coalesce into revocation; none grant rights.

## What must falsify this decision

These are acceptance cases for later implementation, not new passing results.

| Case | Required observation |
|---|---|
| NS omits every reset callback during RSA/ML-DSA and while idle | A physical USB reset still revokes S authorization and rejects old pending replies |
| NS tries to clear BUS_RESET, mask/force USB IRQs, rewrite USB DPRAM, reset USB or use aliases/DMA | The attempt cannot suppress the S observer or counterfeit its epoch |
| NS starves its executor/notifications or never polls the abandoned reply | S admission/release remains fenced; cleanup needs no NS acknowledgement; USB service itself may be denied |
| Reset races dispatch, `poll`, EP0 setup or IN transfer arming | The defined S serialization decides the epoch; an old transfer/result cannot be newly admitted afterward |
| NS replays an old ticket, CID, sequence or token after reconfiguration | S does not restore the old session's rights or refill PIN retries |
| Reset follows authorization in each applet and interrupts PIN/presence/OTP output | Every affected volatile authorization/pending buffer is revoked and scrubbed; reset itself neither deletes persistent data nor rolls back an admitted command |
| Protection is deliberately relaxed for a reset-latch write or old-epoch release | The corresponding negative test observes suppressed revocation or an unauthorized release |
| Honest NS runs the same crypto/lifecycle matrix | Existing signatures, keepalives and protocol behavior still pass |

The current image backend can exercise scheduling, tickets and cooperative NS
callbacks. Its pinned picoem core does not enforce all ordinary CPU memory/MMIO
accesses, ACCESSCTRL and DMA security paths, and direct ELF boot does not prove
bootrom signature verification. The hostile-NS cases require those models first,
then confirmation on hardware. No hardware-isolation property is closed here.
See [testing](testing.md) for the current emulator paths.

## Prototype build and measurements

This experiment runs USB, CTAPHID, CCID and OTP HID framing in Non-secure
state. The existing worker, applets, storage, PIN/presence decisions and RSA
core1 remain Secure. It is a 4 MiB, no-display, no-touch test image, not a
production configuration. The ordinary firmware build does not enable it.

Build inside the pinned development shell:

```sh
nix develop -c bash firmware/trustzone/build.sh
```

The output is `target/trustzone/combined.elf` and `combined.uf2`. The ELF embeds
the Non-secure image so the existing image emulator loads both. The build
checks that embedding it did not change the gateway import library.

Secure code uses the existing thread executor for startup, then transfers the
worker to Secure SWI_IRQ_0 at P3. Non-secure USB tasks use SWI_IRQ_1 at P2;
USBCTRL and TIMER1 interrupts target Non-secure. Secure TIMER0 and core1 retain
their existing ownership. Non-secure critical sections use the core0 interrupt
mask and do not take Secure's hardware spinlock 31.

Three CMSE C wrappers provide submit, poll and limited status/cancellation
operations. They are compiled by the existing Arm GCC, with register cleanup
and BXNS generated by `-mcmse`; Rust stays on the pinned stable toolchain.
`TestTarget::check_range` validates every input/output span. Requests are copied
into the worker's Secure exchange; its mutex and request tickets serialize dispatch.
No Rust references or applet state cross the boundary.

Submit returns a positive ticket; poll and abandon name that same ticket.
USB reset, deconfiguration and suspend advance the NS session epoch and queue
Secure cleanup. An abandoned synchronous operation finishes before its response
is wiped; no new request is accepted until discard and authorization cleanup
complete. CTAPHID CANCEL answers the original CBOR request with `0x2D`.
CCID uses the EP0/bulk ABORT handshake for the single card slot. Cancellation
does not undo a key or counter write that has already committed.

| Region | Address | Size |
|---|---|---|
| Secure code | `10000000..101FEFFF` | 2044 KiB |
| NSC gateways | `101FF000..101FFFFF` | 4 KiB |
| Non-secure code | `10200000..1027FFFF` | 512 KiB |
| KV main / counters | Existing `10280000..103FFFFF` | 1536 KiB |
| Secure SRAM | `20000000..2006FFFF` | 448 KiB |
| Non-secure SRAM | `20070000..2007FFFF` | 64 KiB |

Non-secure boot probes invalid gateway pointers before attaching USB, including
a span crossing into Secure memory. It links without a global allocator;
the OTP frame codec reuses the existing `rsk-otp` implementation and dependency
versions, while only that codec is linked into the transport image. TIMER1 uses
the existing Embassy time-driver API and bounded timer queue in this separate
workspace; it does not share Secure TIMER0's queue or wakers.

The prototype makes `getInfo` execute synchronous SHA-256 work in Secure for
three seconds before calling the existing FIDO handler. The host-side test
requires PROCESSING keepalives throughout that interval and a successful,
properly framed getInfo reply:

```sh
nix develop -c cargo run --locked --release --manifest-path tools/emu/Cargo.toml --target aarch64-apple-darwin -- --image target/trustzone/combined.elf --fido-port 7899 --ccid-port 7900 --inspect-port 7901
nix develop -c python tests/94_trustzone_keepalive.py --port 7899 --inspect-port 7901
```

The test uses explicit loopback HID/inspection sockets and cannot select a hardware key.
Intervals are checked on the image clock; wall time is reported separately
because interpreter throughput changes under host build/test load.
For real RSA and ML-DSA, start a fresh emulator with the same combined ELF and
run the independent crypto/liveness test:

```sh
nix develop -c python tests/95_trustzone_crypto_keepalive.py --fido-port 7899 --ccid-port 7900 --inspect-port 7901
```

It generates a PIV RSA-2048 key and verifies three signatures, then registers
ML-DSA-44/65/87 credentials and verifies three assertions per set under both
OpenSSL and dilithium-py. Altered messages/signatures must be rejected; packed
ES256 attestation is verified too. None of these requests invokes getInfo's
synthetic workload. The emulator stamps keepalives at USB completion and freezes
the measurement at the first final HID report or complete CCID message.
The test compares the USB count to the received socket messages, bounds every
gap at 500 ms and requires a keepalive on assertions/RSA operations long enough
for the transport's timer (150/300 ms, allowing dispatch margin).

Start another fresh image instance for the session-boundary matrix:

```sh
nix develop -c python tests/96_trustzone_sessions.py --fido-port 7899 --ccid-port 7900 --inspect-port 7901
```

It injects events after the first PROCESSING keepalive or CCID time extension:
CANCEL, bus reset and disconnect/reconnect during ML-DSA-44/65/87 assertions;
ABORT, bus reset and disconnect/reconnect during RSA-2048 generation and signing;
card power-off/on queued during RSA generation; and bus reset during ML-DSA with
an active FIDO largeBlobWrite token. It verifies recovery with a new signature,
refuses late responses on the new channel/sequence, checks that PIN and management
authorization cleared, and rejects the old FIDO token without spending retries.
USB events preserve MCU power-up count. Disconnect models loss of the host link
with device RAM powered; it does not model removal of the board's power supply.

It is an image-level scheduling experiment, not evidence of complete hardware
isolation. ACCESSCTRL, DMA permissions, fault handling, production boot/update
packaging, display, other flash sizes, and preserved runtime USB identity still
need their own integration work. No signing key or fuse operation is part of
this build. Hardware flashing remains a maintainer action.

### Keepalive checks at bcdDevice 0x0AA4 (2026-10-13)

The combined ELF enumerated as three USB interfaces on the image backend built
from this worktree. Both prototype images passed clippy with `-D warnings`.
Three consecutive final-image getInfo runs produced:

| Run | Image seconds | Host seconds | Keepalives | Largest image-clock gap |
|---|---|---|---|---|
| 1 | 3.804 | 6.118 | 32 | 0.404 s |
| 2 | 3.645 | 5.859 | 32 | 0.394 s |
| 3 | 3.701 | 5.883 | 32 | 0.437 s |

The same test rejected a temporary `KEEPALIVE_MS = 10000` mutation with
`only 0 keepalives during Secure work`, after accepting the completed getInfo
response. The mutation was restored. A priority P1 mutation faulted during
exception return in the model; that run is not counted as a keepalive kill.
CCID power-on and SELECT PIV also completed through the Secure worker (`9000`).

The NS initialization frame initially needed 22920 bytes against about 17 KiB
of stack. Constructing CTAPHID/CCID directly with `StaticCell::init_with` reduced
it to 7408 bytes. TIMER1 also needed its own TICKS generator enabled by Secure
startup; Embassy's ordinary initialization enables only TIMER0 and watchdog.
These fixes were checked in the resulting image, not only in a host mock.
The final repeat on the same ELF produced these USB-completion measurements. Signing
rows cover three verified signatures each; times are image time, not board
latency estimates. ML-DSA signing varies with rejection sampling.

| Operation | Image seconds | Keepalives | Largest gap |
|---|---|---|---|
| RSA-2048 generate | 6.073 | 30 CCID time extensions | 0.200 s |
| RSA-2048 sign | 0.344–0.354 | 1 each | 0.200 s |
| ML-DSA-44 makeCredential | 0.324 | 3 | 0.106 s |
| ML-DSA-44 getAssertion | 0.184–0.222 | 1–2 | 0.110 s |
| ML-DSA-65 makeCredential | 0.346 | 3 | 0.108 s |
| ML-DSA-65 getAssertion | 0.289–0.562 | 2–5 | 0.107 s |
| ML-DSA-87 makeCredential | 0.384 | 3 | 0.106 s |
| ML-DSA-87 getAssertion | 0.306–0.957 | 2–9 | 0.109 s |

Both complete positive runs passed: two RSA key generations, six RSA signatures,
and six assertions for each ML-DSA parameter set. The first generation took
8.726 image seconds with 43 time extensions; the maximum gap was 200 ms in both.

Sampling `status` after receiving a short response initially included emulator
idle catch-up and falsely reported a 526 ms final gap. The USB-completion trace
avoids that observer delay; its unit tests cover other channels/sequences,
continuation packets, GET RESPONSE and reading the result after a host delay.
The real-operation test also rejected temporary transport mutations. With
`KEEPALIVE_MS = 10000`, a valid ML-DSA-44 assertion verified under both host
implementations but failed with zero keepalives. With `WTX_INTERVAL_MS = 1000`,
RSA-2048 generation returned its public key after 5.792 image seconds but failed
on a 1.000 s gap. A prior 10000 ms WTX trial exceeded the image backend's 5 s
silence deadline; that timeout is not counted as a directed liveness failure.
Both constants were restored, and that combined ELF has the same SHA-256
as the positive-test image (`e0e3ae9c61b6d6f0582dcec342abe89c31b6b3bd08c6f365745ff0c6cadfeed6`).
No board timing or full isolation test is recorded here.

At `0x0AA4`, the full ordinary quality gate was rerun after the real-operation checks and
returned `ALL CHECKS PASSED`. The final transport timing tests and all three
emulator lint profiles also pass. Root workspace discovery uses the manifest's
members and preserves the original first-party scope, so the nested Non-secure
manifest cannot shadow the Secure firmware. Its 70 owner binding tests pass;
restoring the old scan makes the namespace tests fail. Gate assertions and the
ordinary image's optional-crate expectation are unchanged.

The lifecycle changes at `0x0AA5` grew the NS startup frame to 16520 bytes.
Keeping that frame in `main` left about 500 bytes for transport calls and USB
interrupts; a sequential matrix exposed `STKOF` near `MSPLIM_NS`. Startup now
runs with NS interrupts masked in a returning `#[inline(never)] init`, so the
frame is released before the NS interrupt executor runs. The Secure/NS RAM split
and transport capacities are unchanged.

### Session checks at bcdDevice 0x0AA5 (2026-10-14)

The final combined ELF (`eb4c5b2b644f0f47e318e776297c4e86e84301ce633b08b2eddede91b068de76`)
passed all 17 session-boundary cases in sequence. A preceding full pass after
reclaiming the startup frame used a fixed seed; the final pass used a fresh
random seed and included the partial-read/idle-session fixes. Every recovery
signature verified. PIV PIN and management authorization cleared on bus/card
reset, and the old FIDO largeBlobWrite token returned `PIN_AUTH_INVALID` (`33`)
without spending PIN retries. Bus events kept the MCU power-up count at one.

The crypto keepalive regression passed on the same final ELF in a fresh image:
RSA-2048 generation took 7.412 image seconds with 37 time extensions, signing
took 0.342–0.352 seconds with one each, and the largest gap was 200 ms.
All nine ML-DSA assertions and three packed attestations verified; the largest
CTAPHID gap was 108 ms. A premature test start failed at the USB-ready barrier
before dispatch and is not counted as a crypto failure; the harness now waits
for readiness explicitly.

Both prototype halves passed clippy with `-D warnings`. The host USB suite has
115 passing tests, including default-handler compatibility and reset while an
endpoint read is pending. The Secure ticket state has two passing Kani proofs:
reset invalidates every dispatch stage, and a foreign ticket cannot consume or
abandon another reply. A directed baseline run before the fix returned a valid
ML-DSA signature after CANCEL and an old CBOR result to the new channel after
bus reset; both are refused by the session test.

The diff mutation sweep tested 116 mutants in the bounded container (4 GiB,
2 CPUs, 256 PIDs). The first pass caught 96, left 14 survivors and rejected six
uncompilable mutations. New tests closed eight survivors through two
`--iterate` repeats: old framing errors, new-session pending frames, packet
copy bounds and legacy handler compatibility. The composed result is 104
caught, six unviable and six equivalent survivors; the raw in-diff runner still
returns 2 for those survivors. No acceptance registry was changed.

| Remaining mutation | Count | Why the behavior is equivalent |
|---|---|---|
| Default `session_epoch()` returns 1 instead of 0 | 2 | Each default remains a constant; the transport compares epochs and never exposes their numeric value |
| CCID slot-status `status \| STATUS_FAILED` becomes XOR | 4 | The stored ICC status is only active/inactive (0/1), disjoint from the failed-command bit (`0x40`) |

The initial runner attempts hit another task's fixed container name and the
managed worktree's absolute `.git` link. They are apparatus failures. The measured
run used a temporary ordinary clone of the same base plus the uncommitted diff,
and a unique container name, with the original limits and read-only source mount.
Its failure assertions were read: the added tests rejected an extra stale reply,
an out-of-bounds copy, a lost new reply and unsolicited legacy cancellation.
Logs are retained in `target/trustzone/session-checks/`.

The ordinary quality gate is a composed pass on this change. The initial run
reached emulator conformance; its existing vendor-read wall-time test failed
at 7.563 s, then 3.008 s against its 3 s bound. That timer includes device boot;
the isolated case passed in 0.33 s. Repeating the complete conformance row with
`RUST_TEST_THREADS=4` passed all 213 cases, with the original assertions and
timing bound. The two new session proofs required the existing Kani floors and
current-count prose to rise by two; all 112 Kani gate tests passed after that
update. The remaining gate rows passed, including 419 CLI tests, 59 interop
tests and gitleaks. Extra final USB tests and host clippy passed after the
initial gate started; production code did not change during these repeats.
The full Kani tiers and `check-assurance.sh` were not rerun; no PR is being opened.

### ABI relocation at bcdDevice 0x0AA6 (2026-10-14)

The shared constants moved unchanged into `rsk_usb::worker_abi`; both images
import them through Cargo. Build commands and results now live on this page.
Both images built and passed clippy with `-D warnings`; mdBook and the offline
link check passed. The bounded in-diff mutation runner found no mutation sites
in the relocated declarations/imports, and a direct comparison confirmed every
constant declaration was unchanged.

The combined ELF (`d39e96941235b419280cd3b3886f78c31aceeeaec8199ff307050d411e316e18`)
passed one fresh-image getInfo smoke run: 3.561 image seconds, 6.511 host seconds,
32 PROCESSING keepalives and a maximum image-clock gap of 355 ms. The test
emulator was stopped afterward. The earlier RSA/ML-DSA and session matrices above
remain measurements of their named images, not new runs on this ELF. The S USB
hardware front-end chosen in this contract is not implemented in this image.

The ordinary quality gate is a composed pass for the ABI relocation. The full
run passed through the image, host and roster checks, then refused a CHANGELOG
entry that omitted the new build counter. After recording `bcdDevice 0x0AA6`,
the failing row and every remaining row passed without firmware changes.
The final documentation build and link check also passed. No new hardware or
full Kani/assurance result is claimed for this refactor.

## Emulator source and isolation checks

The image backend uses `third_party/picoem`, imported from
[TheMaxMur/picoem](https://github.com/TheMaxMur/picoem/tree/9513634a7ba2c8331f4f8b363196eb24bace96df)
at `9513634a7ba2c8331f4f8b363196eb24bace96df`. Upstream library code keeps
its MIT OR Apache-2.0 terms; local security changes are AGPL-3.0-only. The ROM
is BSD-3-Clause, with its licence beside the fixture. Only
`rp2350-emu` and `picoem-common` library sources and the pinned A4 ROM are
imported; integration-test firmware fixtures and unrelated binaries are omitted. Local changes implement
the isolation model needed to test this boundary. They add no firmware dependency.

The CPU model now checks SAU/IDAU attribution before every byte, halfword and
word data access and every instruction dispatch, including decode-cache hits.
NSC entry requires SG; ordinary NS data reads of NSC memory are refused. MPU
read/write and execute-never permissions apply to actual accesses, with fault
status in the corresponding SCS bank. SecureFault status/address are S-only.
ROM service hooks also pass fetch attribution before the host can service them.
These rules follow the [Cortex-M33 user guide](https://documentation-service.arm.com/static/5f16e93d20b7cf4bc524af1d)
and the [RP2350 bootrom attribution map](https://github.com/raspberrypi/pico-bootrom-rp2350/blob/master/src/main/arm/arm8_bootrom_rt0.S).

CPU checks on 2026-10-14: five reproducing tests failed on the imported core
because prohibited accesses succeeded; the permitted NS-memory control passed.
After the repair, all ten isolation tests and 3,741 library tests passed (27
upstream tests remain ignored), and both library crates passed clippy with
warnings denied. Existing bank-switch fixtures now explicitly configure SAU;
their assertions are unchanged. The current combined firmware also passed the
getInfo smoke: 32 keepalives, maximum image-time gap 187 ms. ACCESSCTRL, DMA,
malicious image probes and independent Secure USB revocation are still pending.

```sh
nix develop -c cargo test --locked --manifest-path third_party/picoem/Cargo.toml \
  -p rp2350-emu --target aarch64-apple-darwin --lib
```

The full `scripts/check.sh` passed for the CPU-memory step. Controller, DMA
and adversarial-image coverage are still needed before an isolation claim.


Special-register and exception-return checks now preserve the separation of
the S and NS register banks. MRS/MSR `_NS` aliases are RAZ/WI to NS code.
EXC_RETURN from thread mode cannot unstack a frame; NS returns with invalid ES
or DCRS fields raise INVER. Returning to a protected S frame checks its integrity
signature before restoring registers. Honest S-to-NS interrupt returns follow
the default DCRS rules, including callee-register preservation. The existing
quality gate now runs the vendored model's formatting, clippy and library tests,
so these tests participate in CI rather than only in manual emulator checks.


Transition checks on 2026-10-14: six reproductions failed on the previous model,
including S-bank reads/writes, forged returns and acceptance of a corrupted
stack signature. Both valid interrupt-return paths now pass; all 17 boundary
tests and 3,748 RP2350 library tests pass. Clippy is green and the combined-image
smoke reports 32 keepalives with a maximum image-time gap of 287 ms.
Disabling the NS data-attribution guard made the actual `test (RP2350 model)`
gate row fail at secret-exposure and protected-store assertions (not a compiler
failure). The guard was then restored byte-for-byte. These checks cover the
implemented transitions; ACCESSCTRL, SIO banking and DMA remain separate work.


The bus model now applies ACCESSCTRL master and security/privilege filters to
CPU reads, writes and instruction fetches in both serial and threaded views,
including host-mounted MMIO devices. It models reset values, password failures,
atomic aliases, locks, CFGRESET, FORCE_CORE_NS and the restricted NSP-to-NSU
write rule. Boot RAM remains S-only regardless of programmable grants. Source:
RP2350 datasheet sections 2.1.2 and 10.6 and pico-sdk 2.2.0 register definitions.
CPU access contexts are scoped to one operation; laboratory bus accesses use
an S debugger context. ROM hooks must pass the same bus and fetch checks.

ACCESSCTRL checks on 2026-10-14: nine controller tests and four additional CPU
cases pass; the RP2350 library total is 3,761 passing, 27 ignored. The previous
ROM hook bypass was reproduced by a prohibited NS ROM access before repair.
Disabling the CPU bus filter makes the actual model gate row fail at protected
peripheral and ROM-hook assertions. Clippy passes. The unchanged combined image
also passed smoke with 32 keepalives, maximum image-time gap 205 ms. SIO banking,
GPIO register filtering, DMA channel security and DMA MPU are still pending.


SIO now has separate S and NS FIFOs, spinlocks, doorbells and interrupt lines.
S can address the NS mirror; NS attempts to address that mirror fault. GPIO
input/output/OE accesses share the physical state with ACCESSCTRL masks, including
narrow writes and CP0. PERI_NONSEC controls each core's interpolator ownership;
NS cannot reassign it or access the S-only timer. The threaded view preserves
both banks and GPIO policy during promotion and polls their separate IRQ lines.
Per-pin IO_BANK/PADS filtering and TMDS encoding are not modelled; the production
policy must keep those peripherals S-only unless their model is extended.


SIO checks on 2026-10-14 reproduced eight prohibited accesses before repair.
Removing bank selection makes the actual model gate fail on S FIFO disclosure,
S GPIO reads and protected-state mutation. Both bank views have positive controls;
the new high-bank output path also has a reproducing pad-projection test. Smoke
on the unchanged combined image reports 32 keepalives and a maximum image-time
gap of 208 ms. The x86 Linux container needs at least six vCPUs for the upstream
threaded runtime. The imported pacer overrun test now uses a valid millisecond
quantum and an actual overrun; it no longer fails at construction on a coarse
virtual TSC. The runtime's minimum quantum is unchanged. The ordinary model test
row remains portable to smaller CI hosts; clippy compiles all features, and
threaded runtime tests run separately on a six-vCPU host. Container wall-clock
measurements are not a physical-device pacing oracle.


Final model runs for SIO: 3,776 RP2350 tests pass on macOS (27 ignored), and
3,868 pass on x86 Linux with threading and all features (28 ignored). The common
library also passes its Linux all-feature tests after the portable overrun
fixture repair. These measurements exercise the emulator model; they do not
prove the hardware policy in the current prototype, which still grants NS
direct USB access.
