<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# TrustZone boundary and resource ownership

This chapter owns the TrustZone design, build instructions, measurements and
remaining production work. The standard single-image build has no Secure/Non-secure
split. The experimental build at `bcdDevice 0x0ABB` runs USB classes and transports in
Non-secure (NS), with the controller, lifecycle observer, worker and applets in
Secure (S). Secure revocation no longer depends on NS reset callbacks. The
resource policy, Secure board services and combined offline build are implemented
below; physical validation remains required before release. Passing
software checks are not a claim of physical isolation.

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
| USBCTRL, USB DPRAM/control words, USBCTRL_IRQ, masks and event acknowledgement | S HAL driver and observer; bounded NS packet proxy | S bounded hardware front-end; NS gets endpoint operations and copied events, not raw MMIO/DPRAM access |
| USB bus epoch and reset latch | S epoch and raw lifecycle observation | S hardware observer owns the epoch; NS may keep a presentation copy or request revocation |
| USB classes, CTAPHID, CCID, OTP HID/keyboard framing and keepalive timers | NS | NS; framing and identifiers confer no S authorization |
| USB identity, interface mask and endpoint allocation | S-validated public snapshot and bounded endpoint allocation | S loads/validates persisted configuration; NS receives a bounded public snapshot; S admits only that endpoint layout |
| TIMER0 and security/authorization deadlines | S | S only |
| TIMER1 and NS executor timer queue | NS | NS TIMER1 only; shared TICKS, clock and reset controls stay S |
| TRNG, DRBGs, OTP secrets and fuse operations | S | S only; ordinary gateways expose no raw entropy, secret rows or fuse primitive |
| Presence button, its GPIO/QSPI path and trusted display/touch input | S hardware and decision; touch enabled by default; optional S display | S hardware and decision; NS can query waiting status or cancel, never report a successful press/PIN |
| LED, PIO/PWM, SPI/I2C and display/presence GPIO | S board layer; selected board LED and optional display | S board layer; NS presentation requests cannot reconfigure trusted input/output |
| DMA channels, descriptors, IRQ/DREQ routing and DMA MPU | Secure channels locked; registers/IRQs S-owned; no NS descriptors | S only initially; descriptors cannot be supplied by NS or target S state through an NS-controlled channel |
| SIO FIFO, spinlocks and cross-core reset/launch | S engine uses reserved resources; NS masks its own interrupts | S reserves cross-core resources; NS cannot seize S locks or impersonate a core1 handshake |
| SAU, S/NS MPU policy, security attribution and interrupt routing | SAU plus both S MPUs and NS MPU; generated 2/4/16 MiB map | S; NS banked controls must not alter S resources or bypass reset checks |
| Clocks, RESETS, watchdog, POWMAN, debug/security controls and ROM service access | Explicit S grants and ACCESSCTRL locks; silicon debug/update validation pending | S; NS requests are bounded commands, not register writes or arbitrary ROM calls |

S IRQ handling must observe USB lifecycle events during synchronous S crypto.
Its masks, target and acknowledgement path must be inaccessible to NS. The
priority design must also keep honest NS keepalives running; enabling `PRIS`
without checking the S worker/NS executor ordering is not an acceptable shortcut.
Hardware filters, MPU attributes and peripheral grants must be checked for both
cores and every bus master before USB attachment. The startup policy below
installs and reads back these grants before attachment; silicon checks remain.

The inspected 4 MiB experiment uses the following linker/SAU bounds. These are
the current layout, not fixed production offsets for every board. Production
must derive the boundaries from the combined image and retain each board's
existing KV layout.

| Region | Current address range | Owner |
|---|---|---|
| S code | `0x10000000..0x1026efff` | S |
| NSC entry veneers | `0x1026f000..0x1026ffff` | S, callable only through declared entries |
| NS code | `0x10270000..0x1027ffff` | NS execution; S update policy |
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

The S USB front-end implements a separate bounded endpoint interface. It accepts
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
account of which applet was selected. The shared transport reset now scrubs every applet, including unselected applets,
and clears held CCID output. Host tests cover the cleanup path; the image tests
exercise PIV and FIDO authorization. PIN-entry and physical OTP-output timing
still require the board integration and hardware checks below.

S-observed suspend and configuration loss conservatively revoke the session too.
Resume does not restore authorization. A powered disconnect can only be claimed
where a real controller/board signal is observable by S; a software event injected
by the emulator is not a physical VBUS measurement. Full loss of MCU power
starts a fresh boot with no restored volatile authorization. Repeated hardware
events and NS-requested resets coalesce into revocation; none grant rights.

## What must falsify this decision

These acceptance cases define the boundary. The measurements below identify
which software cases have passed and which still require hardware.

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

The image backend exercises scheduling, tickets and both normal and omitted NS
reset callbacks. The vendored core now enforces the tested SAU/MPU, ACCESSCTRL,
SIO and serial DMA paths described below. Further hostile NS images, remaining
instruction/FPU fidelity and hardware confirmation are still required. Direct
ELF boot does not prove bootrom signature verification. No hardware-isolation
property is closed here. XIP-cache latency requires physical timing; neither
backend models cache misses. See [testing](testing.md) for the emulator paths.

## Prototype build and measurements

This experiment runs USB classes, CTAPHID, CCID and OTP HID framing in
Non-secure state; Secure owns the controller and EP0 driver. The existing worker, applets, storage, PIN/presence decisions and RSA
core1 remain Secure. The default build enables real presence and the selected
board LED; test-only behavior requires explicit flags. The ordinary firmware
build does not enable the split.

Build inside the pinned development shell:

```sh
nix develop -c bash firmware/trustzone/build.sh
```

The output is `target/trustzone/combined.elf` and `combined.uf2`. The ELF embeds
the Non-secure image so the existing image emulator loads both. The build
checks that embedding it did not change the gateway import library.

Secure startup and worker tasks use Secure SWI_IRQ_0 at P3; the Secure LED
executor uses SWI_IRQ_3 at P2. Non-secure USB tasks use SWI_IRQ_1 at P2.
USBCTRL targets Secure at P0 and the EP0 executor uses Secure SWI_IRQ_2 at P1.
Secure signals public USB and worker progress through Non-secure SWI_IRQ_4 at P2;
its handler wakes NS-local waiters. Polling retains a 16-millisecond fallback,
and registering a waiter rechecks its observed generation to avoid lost wakes.
The worker publishes a reply or completed reset only after its command future
has returned and the Secure dead-stack sweep has finished. Epoch, ticket and
response checks still decide whether output may cross the gateway.
TIMER1 targets Non-secure. Secure TIMER0 and core1 retain
their existing ownership. Non-secure critical sections use the core0 interrupt
mask and do not take Secure's hardware spinlock 31.

Four CMSE C wrappers provide bounded USB packet operations plus submit, poll and limited status/cancellation
operations. They are compiled by the existing Arm GCC, with register cleanup
and BXNS generated by `-mcmse`; Rust stays on the pinned stable toolchain.
`TestTarget::check_range` validates every input/output span. Requests are copied
into the worker's Secure exchange; its mutex and request tickets serialize dispatch.
No Rust references or applet state cross the boundary.

Submit returns a positive ticket; poll and abandon name that same ticket.
Secure USB reset, deconfiguration and suspend observation advance the Secure bus
epoch and queue cleanup independently of NS callbacks. An abandoned synchronous operation finishes before its response
is wiped; no new request is accepted until discard and authorization cleanup
complete. CTAPHID CANCEL answers the original CBOR request with `0x2D`.
CCID uses the EP0/bulk ABORT handshake for the single card slot. Cancellation
does not undo a key or counter write that has already committed.

| Region | Address | Size |
|---|---|---|
| Secure code | `10000000..1026EFFF` | 2492 KiB |
| NSC gateways | `1026F000..1026FFFF` | 4 KiB |
| Non-secure code | `10270000..1027FFFF` | 64 KiB |
| KV main / counters | Existing `10280000..103FFFFF` | 1536 KiB |
| Secure SRAM | `20000000..2006FFFF` | 448 KiB |
| Non-secure SRAM | `20070000..2007FFFF` | 64 KiB |

With `RSK_TZ_GATEWAY_PROBES=1`, Non-secure boot probes invalid gateway pointers
before attaching USB, including a span crossing into Secure memory. It links without a global allocator;
the OTP frame codec reuses the existing `rsk-otp` implementation and dependency
versions, while only that codec is linked into the transport image. TIMER1 uses
the existing Embassy time-driver API and bounded timer queue for the NS image; it does not share Secure TIMER0's queue or wakers.

With `RSK_TZ_TEST_DELAY=1`, `getInfo` executes synchronous SHA-256 work in Secure
for three seconds before calling the existing FIDO handler. The host-side test
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
build with `RSK_TZ_NO_TOUCH=1` and run the independent crypto/liveness test:

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

These image-level scheduling checks do not establish complete hardware
isolation. Current startup, peripheral policy, identity, board integration and
packaging are described below; silicon and bootrom validation remain open. No signing key or fuse operation is part of
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


The DMA model now carries the channel's own security/privilege attributes and
DMA master identity through actual serial transfers. SECCFG reset values,
automatic/manual channel locks, restricted NS configuration writes, interrupt
visibility, timer/peripheral DREQ visibility and downward-only chaining are
modelled. The MPU checks logical addresses, including span ends and overflow;
the lowest matching region wins, otherwise MPU_CTRL defines the background.
Aliases are not normalised into a permitted region. MPU and bus denials stop
the channel, latch READ_ERROR/WRITE_ERROR and request its interrupt; errors
require W1C before restart. DMA self-access follows the same checks.

Serial and threaded CPU MMIO views enforce controller permissions for every
access width, including partial W1C writes. Threaded DMA transfer execution is
still absent upstream; use the serial image backend for DMA isolation tests.
The production policy will keep DMA registers and channels S-owned and protect
all SRAM/XIP aliases with a Secure background plus explicit NS data regions.
No current firmware DMA policy is claimed by these model changes.


DMA checks on 2026-10-14: six reproductions exposed a Secure channel pointer,
bypassed master filters or wrote protected control resources before repair.
The final model passes 3,795 RP2350 tests on macOS (27 ignored), and 3,887 on x86
Linux with threading/all features (28 ignored); both clippy runs pass. Removing
the transfer MPU guard makes the real model gate fail because NS DMA exports
Secure RAM. The guard is then restored byte-for-byte.

The unchanged combined ELF at bcdDevice 0x0AA6 again passes RSA-2048 generation
and signing, plus ML-DSA-44/65/87 credentials and assertions; every signature
and attestation is verified. Maximum image-clock keepalive gaps are 201 ms for
RSA and 108 ms for ML-DSA. All 17 cancellation/reset/disconnect cases pass,
including worker recovery, authorization clearing on reset and refusal of the
old FIDO token. These remain honest-NS lifecycle measurements; independent
Secure USB revocation is still the next firmware step.


At bcdDevice 0x0AA7, the worker's USB-wide reset uses the CCID full-session scrub,
which enumerates all eight applets, clears selection and chaining/GET RESPONSE
state, and wipes the reply buffer. The FIDO transport scrub keeps its per-boot
PIN lock; the OTP transport and typing queue are scrubbed as well. ICC reset
still follows its existing selected-applet semantics. This closes the software
cleanup scope when S receives revocation; the prototype still needs independent
Secure USB observation against an NS image that suppresses reset callbacks.

Queued OTP characters are fenced immediately when the S session is revoked,
including while synchronous crypto finishes or reset cleanup is pending. The
queue itself is wiped before admission reopens; a second reset during scrubbing
keeps both admission and auxiliary output closed until its cleanup completes.


The Secure USB front-end exercises a basic IRQ nested over an outstanding lazy
FPU reservation. The model previously rejected that valid return, preventing
USB enumeration. Arm DDI0553 E2.1.231 preserves the reservation on a basic
return; FPCAR does not authenticate a stack frame. The model now follows that
ordering, retains the Secure integrity-signature check (including FType), and
reports CFSR.INVPC at bit 18. UNDEFINSTR is set by the undefined decoders,
rather than by delivery of every UsageFault.

Two imported tests assumed that FPCAR/LSPACT must authenticate every return.
Their expectations were replaced with populated-frame and independent-lazy-state
cases from [Arm's exception return and PopStack specification](https://documentation-service.arm.com/static/5f8f00eaf86e16515cdbe632).
The new nested-IRQ test fails on the previous guard. Native all-feature tests
pass 3799 cases, with 27 existing ignores; clippy passes. This fixes that
scheduler path and does not claim complete banked-FPU or Arm instruction fidelity.


## Secure USB front-end at bcdDevice 0x0AA8

`rsk_usb::usb_abi` defines the packet interface used by both Cargo builds.
Secure retains the Embassy RP controller, endpoint buffers, interrupt masks,
acknowledgement and the persistent EP0 task. Non-secure uses an Embassy driver
proxy. It receives copied packets and bus events and can operate only allocated
endpoints. Each payload is at most 64 bytes; ordinary gateway buffers must be
inside the designated NS SRAM, in addition to passing the complete CMSE span
check. No entry exposes a raw register write or reset-latch acknowledgement.

Secure observes raw reset, suspend and configuration-loss state before worker
admission and result export, and around endpoint operations. Revocation advances
the Secure bus epoch, fences worker tickets, clears pending endpoint buffers and
wipes DPRAM payloads before the HAL acknowledges the event. Accepted physical
SET_CONFIGURATION opens admission after cleanup. Resume permits the new epoch
without restoring old authorization. Epoch exhaustion is terminal until a
scrubbed reboot. An already executing command can finish its persistent effects;
its abandoned response cannot be newly exported.

The EP0 driver runs as a persistent Secure future on SWI_IRQ_2. Its commands use
the same typed ticket/abandonment/reset state machine as the worker; replacement
setup and reset cancel the old control operation. Polling and final packet
copies are serialized with Secure lifecycle observation.

Non-secure reads the Secure epoch instead of incrementing a local counter. A
whole CTAPHID or CCID response, including keepalives and continuation packets,
retains the request epoch. Refreshing the epoch at each write reproduced a late
ML-DSA reply in the newly initialized channel; binding the complete response
removed that failure. A disabled endpoint ends CTAPHID transmission immediately.
OTP keyboard writes also retain the epoch captured before consuming a Secure
character. These hooks are no-ops for the ordinary driver.

The bcdDevice 0x0AA8 validation used `RSK_TZ_NS_IGNORE_RESET=1` to build an NS
image without Secure reset calls in its bus callbacks. Since 0x0AAE, that is the
normal policy and the switch has been removed. The real RSA
generation/signing and ML-DSA-44/65/87 reset, cancel and disconnect matrix passed
all 17 cases with that image. The test still lets NS run its transport tasks;
it does not establish the separate case where NS permanently stops execution.
The final normal callback image passed the same 17-case matrix and all eight
real-crypto operations, including independent signature and attestation checks.

This remains a no-touch, fixed 4 MiB image. The controller's VBUS override and
powered physical disconnect detection need board validation. The complete
ACCESSCTRL/MPU policy, RAM-executed RSA code permissions, production presence
and display tasks, Secure configuration snapshot and signed combined-image
coverage are the next production steps. No release signing, flashing or OTP write was
performed for these measurements.


The final software checks include five bus-state tests, reserved USB status/flag
and control-ticket boundary tests, and four passing Kani harnesses across the
worker-session and bus-epoch state machines. The bounded mutation run tested 53
changes: 48 were caught, five failed compilation, and none survived. The first
run exposed six missing boundary checks; the completed run includes their tests.
The full Kani tiers have not been rerun for this USB step.


## Explicit resource policy at bcdDevice 0x0AA9

Secure startup now writes and reads back the ACCESSCTRL grants before NS entry.
Unused peripherals remain Secure. Core0 NS receives TIMER1 and the canonical NS
memory through the CPU attribution boundary; controller/DPRAM, clocks, resets,
OTP, TRNG, flash controls, DMA and GPIO policy remain Secure. All GPIO NS masks
are cleared. SRAM banks containing both domains need a shared bus grant;
SAU and the locked Secure DMA channels enforce the finer address boundary.
The other SRAM banks stay Secure. ROM services remain S-only, and boot RAM is
hardwired S-only by RP2350. ACCESSCTRL is locked against both cores, DMA and
debugger configuration writes after setup. This does not configure OTP debug
latches or establish protection against a physical debug/fault attack.

Every DMA channel is Secure/privileged and locked; IRQs, timers and sniff control
are Secure. PIO and SPI admit Secure DMA for the board layer. NS has no channel
or descriptor API. This policy does not rely on an NS MPU remaining enabled.

Both cores configure Secure MPU permissions. SRAM data is execute-never; RSA
C/assembly, the small-prime sieve and Embassy RAM functions occupy an aligned,
read-only executable linker section. Its load image and ordinary data must be
contiguous; linker assertions and the runtime copy symbols enforce that.
The NS MPU permits NS flash, its data, TIMER1 and its banked PPB only. NS can
reprogram its own MPU, while SAU and the bus grants still protect S resources.
The validated host planner covers SRAM with disjoint regions and refuses bad
linker or stack bounds; its symbolic proof reaches stack windows on both sides
of the immutable code island.

The pinned HAL copies the trusted boot2 XIP-restoration code from boot RAM onto
the Secure stack for flash operations. Its actual instruction fetch faulted when
all stack RAM was XN. Secure therefore opens a bounded 4 KiB stack execution
window only around synchronous flash write/erase, with core0 interrupts masked
before the HAL pauses core1 and performs its existing DMA/XIP checks. An RAII
restore reinstates data-only permissions before NS interrupts are unmasked,
including on a returned flash error. This window is writable and executable
Secure memory; it is an explicit exception, not a permanently executable stack
or isolation between S components. Hardware timing/cache effects and abort/fault
recovery still require validation. Early storage setup leaves the bootrom policy
intact until core0 installs this policy.

A disposable `test-hostile-access` NS image disables its own MPU and reads
USBCTRL. The image reaches its pre-read NS marker, faults with PRECISERR and
BFARVALID at `0x50110000`, and never reaches its post-read marker. Relaxing the
USBCTRL grant in a throwaway image makes the same test fail specifically because
the read succeeds; restoring the grant restores the denial. This establishes
that software row on the model, not physical silicon behavior. The same runner refuses all 18 tested MMIO/boot-RAM reads: USBCTRL and its three
atomic aliases, DPRAM, DMA, clocks, resets, IO_BANK0, PADS_BANK0, BUSCTRL, TRNG,
OTP control/data/raw data, XIP_CTRL, QMI and boot RAM. ACCESSCTRL is world-readable
by design (RP2350 datasheet section 6.2.2); that read correctly succeeds.
Protected RAM/flash, writes, entry-register clearing and fault recovery remain
separate checks before the production policy is closed.

The resource/MPU image passes all eight real RSA and ML-DSA crypto operations.
Four host region tests and one Kani partition harness pass, with both source
covers reached. The full code gate and assurance gate pass on the integrated worktree. All 17
lifecycle cases pass with both ordinary NS callbacks and deliberately suppressed
Secure reset callbacks. The final bounded mutation run catches 24 defects; two
do not compile, and none survives. Its three initial survivors exposed incomplete
alignment tests, including a needless extra executable alignment block.


Run an address probe only with a disposable test image, never a release artifact:

```sh
RSK_TZ_PROBE_ADDRESS=0x50110000 nix develop -c bash firmware/trustzone/build.sh
nix develop -c python tests/97_trustzone_isolation.py \
  --image target/trustzone/combined.elf \
  --ns-image target/trustzone/nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns \
  --emulator tools/emu/target/aarch64-apple-darwin/release/rsk-emu \
  --address 0x50110000
nix develop -c bash firmware/trustzone/build.sh
```

The runner requires explicit image/backend paths, checks loopback ports, reads
only its NS progress marker and validates the fault address/status. It never
opens a physical authenticator. The final build command restores a normal NS
image; hostile probes remain an explicit feature.


## Public Secure boot identity at bcdDevice 0x0AAA

The boot path copies the effective VID/PID, PHY-overridden manufacturer/product,
serial, bcdDevice, interface mask and VID-selected ATR into a public snapshot.
NS reads it in bounded chunks through the packet gateway, then constructs only
the enabled interfaces in the existing keyboard/FIDO/CCID order. Disabled CCID
has no ABORT handler. This snapshot carries no PIN, key or authorization state;
compromised NS can still lie in its own descriptors. Applet capability checks
remain Secure.

The shared Cargo ABI owns the fixed 171-byte encoding; NS no longer reads a neighbouring
source file to discover bcdDevice. Descriptor strings are bounded and checked as
UTF-8. Three host tests cover descriptor capacity/padding and the scalar/string round trip, identity/ATR choice,
overlong strings and invalid lengths/UTF-8.

The artificial three-second getInfo busy loop is compiled only with
`RSK_TZ_TEST_DELAY=1`; gateway startup probes require
`RSK_TZ_GATEWAY_PROBES=1`. Use both for the original synthetic keepalive test.
Normal builds leave both disabled. The hostile-MMIO and suppressed-callback
features remain explicit disposable test builds. This identity step preceded the production presence/board and multi-board
integration recorded below.


The image ICC-reset harness now uses its existing 180-second recovery budget for
the socket as well as the command loop. A 60-second socket timeout interrupted
a healthy RSA case under concurrent host checks: it completed in 100 seconds
wall time and 14.8 seconds on the image clock, cleared authorization and verified
the next signature. This changes the test's inconsistent wait, not the firmware
wire deadline or the recovery budget.


The integrated snapshot image passes all eight real crypto operations and all 17
lifecycle cases with independent signature checks. The code and assurance gates
pass. The bounded mutation run catches 46 defects; six do not compile and none
survives. Its first two survivors were size mutations hidden by self-consistent
round trips; the completed tests also assert the exact public header and length.


## Production boot and artifacts at bcdDevice 0x0AAB

Secure boot, storage setup, worker and display tasks now share a cooperative
Secure interrupt executor. This preserves the RefCell ownership used by the
trusted UI. The Secure LED executor runs above the worker; Secure DMA/PIO IRQs
can complete display/LED operations during a synchronous presence wait.
NS runs only its classes, transport framing and packet proxy. Thread mode enters
NS after the Secure initialization frame has returned.

One build layout assigns the final 64 KiB of the existing code partition to NS
and the preceding 4 KiB to NSC. It emits both linker inputs and runtime bounds;
the old checked-in NS memory.x is removed because it overrode the generated
linker search path and left vectors pointing at the wrong address. Existing KV
bounds, partition sizes and the 16 MiB E10 exclusion stay unchanged. Tested code
profiles are 2 MiB/896 KiB KVMAIN, 4 MiB/1408 KiB and 16 MiB/1408 KiB. The display
configuration builds at 16 MiB and advertises the existing CCID PIN verification
capability from Secure; its actual panel/touch behavior still needs hardware.

Startup validates the NS vector/stack ranges, initializes NS execution masks,
keeps HardFault/NMI Secure and permits only FP coprocessors in NSACR. Secure owns
FP lazy/clear controls. The final entry clears shared GPRs, all FP registers and
status before BXNS. Complete banked-FP and exception fidelity is still beyond the
current model, so successful crypto here is not that missing architecture proof.

USB grants admit both Secure cores so terminal cleanup can also run on Core1;
normal controller ownership stays on Core0. The disposable
`tests/99_trustzone_core1_fault.py` regression verifies a pre-armed nonzero packet
is fenced from Core1, then detects incomplete cleanup when only its grant is
removed. Neither image can access a physical key.

A fatal S panic/fault latches every gateway closed, detaches USB and clears DPRAM
using only raw S-owned MMIO. It does not borrow interrupted locks or resume the
worker. A new boot constructs unauthenticated state; normal requested resets
still use Worker::reboot. The fault path deliberately does not claim SRAM
scrubbing. Emulator terminal-stop recognition must let the cleanup execute first;
its host test covers both cores and the complete terminal symbol range.

Default combined builds keep touch and the selected board LED. BOOTSEL sampling
uses the same bounded flash-code window as erase/write. The build applies the
partition table before producing ELF/UF2. These are unsigned artifacts:

```sh
nix develop -c bash firmware/trustzone/build.sh
nix build .#firmware-trustzone
```

For the no-touch crypto/lifecycle harnesses use an explicit disposable test build:

```sh
RSK_TZ_NO_TOUCH=1 LED_KIND=none nix develop -c bash firmware/trustzone/build.sh
```

`tests/98_trustzone_presence.py` requires explicit image/backend paths, starts its
own loopback emulator with --touch and presses emulated BOOTSEL only after
UPNEEDED. It waits for release between ceremonies and verifies six presence
requests plus all eight RSA/ML-DSA operations. The measured touch+LED and offline
Nix images pass that row, with independently verified attestations/signatures.
The measured maximum gaps are 204 ms for RSA and 114 ms for ML-DSA. No physical
key, release signing key or OTP write is part of these runs.

The combined-image hash load map includes S, RAM load images, NSC and NS.
Changing one NS byte in a disposable hash-only ELF makes picotool report an
incorrect hash. Real release signing and fused boot acceptance remain maintainer
operations; hash-only coverage does not establish either one.


### Integrated software verification

The combined no-touch image passes the eight RSA/ML-DSA operations and all 17
session-boundary cases. All 17 also pass with every NS reset callback suppressed.
The touch-enabled offline Nix ELF passes six real Secure presence waits and the
same eight cryptographic operations. The PR Kani tier proves 75 harnesses and
reaches all 60 required source covers.

The capability-codec mutation sweep catches 15 defects and rejects one mutant at
compilation. One equivalent mutant survives: replacing OR with XOR after masking
out PINPAD_VERIFY cannot change a bit, because the operands are disjoint. The
repeated-setter test also verifies idempotence; no acceptance registry is changed.

The fatal-path image first arms an IN endpoint with a nonzero packet, then tries
a denied USBCTRL read with its NS MPU disabled. Secure stops with the endpoint
unavailable and DPRAM zero. Omitting only clear_packets in a disposable clone
makes that same test fail for retained USB/DPRAM state; restoring it passes.
The fixture requires the default three-interface image and keyboard EP1 IN.

The ordinary applet shim's five-second replug wait and wall-clock reset-window
assertions are unsuitable for a slow full-image run. A separate image-clock case
accepts reset after a real emulated power cycle, rejects it after at least 13
image seconds and then checks worker liveness:

```sh
nix develop -c python tests/96_trustzone_sessions.py \
  --fido-port 7899 --ccid-port 7900 --inspect-port 7901 --case reset_window
```

It is explicit and destructive to the emulator's FIDO state. It is kept separate
from the 17-case cancellation matrix. Its measured late request at 13.09 image
seconds is refused; a wall-clock INCONCLUSIVE run is not counted as a pass.

### Checks still required before a hardware release

| Check | What must be observed |
|---|---|
| Bus grants on both cores and silicon aliases | Hostile NS cannot read/write S SRAM, flash, boot RAM, USB/DPRAM, security controls or SIO resources, including through DMA; policy cannot be unlocked |
| Powered cable removal and USB timing | The actual board exposes disconnect/reset to S; old authorization and IN packets are revoked during RSA/ML-DSA, with bounded keepalive gaps under real host controllers |
| BOOTSEL, GPIO presence, LED and trusted panel | Honest requests progress during crypto/flash pauses; NS cannot fabricate a press, PIN, trusted prompt or replacement approval |
| Exception/FP transitions and terminal faults | Register cleanup, lazy FP state, Secure fault routing and gateway closure hold on silicon; no stale packet is exported after a fatal fault |
| Bootrom and update coverage | The maintainer signs the complete PT-applied combined image; a changed S, NSC, NS or partition-table byte is rejected by the fused key/rollback policy |
| Recovery and provisioned storage | Existing devices retain their full KV layout and records through the maintainer's approved upgrade/recovery path, including the 16 MiB E10 exclusion |
| Board margins | Stack/SRAM and flash-operation timing remain safe with display, core1 RSA, interrupts and worst supported operations on the actual boards |

The emulator provides evidence only for the implemented instruction, peripheral
and bus paths. It is not a complete banked-FP/exception model or a fused bootrom
acceptance proof. Direct ELF boot and hash-only tampering cannot close those
hardware rows. The firmware policy is installed independently of these model
limitations. No software measurement here substitutes for signing, flashing or
fuse validation by the maintainer.


For a release candidate, repeat the immutable Nix derivation with `--rebuild`;
this compares both outputs, including ELF metadata. The NS data-object strips
unused objcopy binary symbols because their names otherwise contain the random
absolute build directory. Keep the combined image's code, veneers and partition
table when hashing or signing; signing S alone does not authenticate NS.


## Shared build at bcdDevice 0x0AAC

Both images now belong to the root workspace: `firmware` and `firmware-ns`.
Internal dependencies use workspace entries and one root Cargo.lock; the nested
lockfile and release profile are removed. External versions, sources and
checksums are unchanged. NS is excluded from host tests and coverage. The device
gate and commit hook build the combined image and lint each world separately.

The separate NS workspace had triggered Cargo [issue 7645](https://github.com/rust-lang/cargo/issues/7645):
paths to its out-of-workspace dependencies changed crate hashes between Nix build
directories. Symbol stripping alone did not fix the resulting NS code order.
The common workspace passes an independent immutable Nix `--rebuild`: both the
complete ELF and UF2 match byte for byte.

Use the combined build script or Nix package. The script compiles each package
separately in its own target directory, preserving the two worlds' dependency
features and link inputs. Bare Cargo builds retain the original default members;
NS needs the Secure-generated memory layout and CMSE import library.


## No-touch build checks at bcdDevice 0x0AAD

The timeout constant is used by Secure LED setup and the trusted display. Its
unused-import expectation now applies only to the headless, non-display
no-touch build. The LED-enabled hardware configuration exposed an unfulfilled
expectation under strict clippy; this build correction changes no runtime policy.


## Late Non-secure callbacks at bcdDevice 0x0AAE

A physical-board regression reproduced `6D00` on READ time immediately after a
successful SELECT of Rescue. Secure had already revoked the old USB epoch, but
a delayed NS bus callback could still issue a second, unscoped worker reset and
clear the selection established by the new session.

NS lifecycle callbacks no longer request Secure resets. The unused reset action
was removed from the worker gateway; hardware observation and accepted EP0
lifecycle operations remain the sources of USB-wide revocation. NS CCID ABORT
state carries the Secure USB epoch, so an old abort cannot attach to a new
session even when NS omits callbacks.

The test-only `test-gateway-probes` image exposes CTAPHID command `0xFE`: `epoch`
reads the Secure bus epoch and `reset` invokes the NS reset/configuration-loss/
suspend callbacks late. The normal image does not implement this command.
`tests/100_trustzone_usb_regressions.py --case late-callback` checks that a new
Rescue selection survives that callback at an unchanged Secure USB epoch.

On the RP2350 A2 test key, all 20 delayed-callback repetitions preserved the
selection and refused the removed gateway action. Sixteen physical USB resets
also advanced the Secure epoch, invalidated an armed old ABORT and preserved
the RAM-only clock. A subsequent reset stress run lost the macOS CCID reader
while HID and the Secure gateway still answered; reader recovery and the
3072-byte CCID response remain separate investigations.


## Full CCID responses at bcdDevice 0x0AAF

The physical macOS regression reads a 3056-byte PIV object in a single 3072-byte
CCID response and immediately sends another APDU. The object and status word
were correct, but the next transaction failed with PC/SC `0x80100016`. The same
sequence reproduced on the ordinary no-touch firmware, independently of the
TrustZone split.

A full-size host read can finish before consuming the response's terminating
zero-length USB packet. The Secure controller still queues that ZLP normally.
If a new bulk OUT command arrives first, it retires the unconsumed terminator
before the next response. RP2350's EP_ABORT/EP_ABORT_DONE handshake makes the
buffer safe to modify; an unconsumed packet also restores the previous data
toggle. Revocation clears the retirement state. CCID capacity and mandatory ZLP
termination remain unchanged for hosts that consume the complete transfer.

`tests/100_trustzone_usb_regressions.py --case ccid` uses the existing PIV
frame-boundary assertions, including the following APDU. `--case bus-reset`
uses the normal image: it verifies PIV PIN and management authority before a
physical USB reset, then checks that both have been revoked, that CCID answers
and that the RAM-only clock survived. The two-second wait after reset allows
macOS to recreate its driver; APDU errors are never retried.

The first corrected normal no-touch image passed 20 consecutive repetitions of
the original 3072-byte case and its following APDU. The before-image failed at
that following APDU after returning the complete object; the corrected image
keeps the original frame-size and content assertions.

The authorization test uses `SCARD_LEAVE_CARD` and first closes/reopens the
connection without a USB reset: a PIN query and a privileged PIV write must
still succeed. It then resets USB while that connection remains open. The
initial test used pyscard's default `SCARD_UNPOWER_CARD` before reset; those
runs establish reader recovery and clock continuity only, not USB-triggered
authorization revocation.


## Shared OTP status at bcdDevice 0x0AB0

A physical YubiKit regression exposed a second NS cache: OTP feature reports
returned an old program sequence and slot flags after CCID SELECT changed the
Secure applet's status. YubiKit rejected the next write as `No data` even when
the slot had been programmed. The before-image failed the direct comparison
between the public CCID SELECT result and the next OTP feature report.

Secure now publishes those public status bytes atomically at worker startup and
after APDU/OTP dispatch, before releasing the reply. NS reads that snapshot
through a numeric, read-only control action; its frame codec retains ownership
of processing, response framing and touch-wait signalling. The getter performs
no flash access and changes no applet selection or authorization.

Run this on an explicitly selected test key:

```sh
nix develop -c python tests/101_trustzone_otp_status.py --serial rs-key-0001 --reader "RS-Key RS-Key Security Key" --runs 3
```

It compares both status views, configures OTP slot 2, verifies HMAC-SHA1 against
the host, reselects over CCID and removes the scratch slot. GET/SET_FEATURE use
EP0 without capturing keyboard input; macOS refuses direct keyboard-HID access
in the current host environment.


## Physical validation on 2026-10-15

The RP2350 A2 reference key (4 MiB flash) finished on the normal TrustZone
**no-touch 0x0AB0** image. The host was macOS 27.0.1. The final combined image
has a partition table, no gateway probes and no injected getInfo delay.

| Final 0x0AB0 check | Observed result |
|---|---|
| CCID frame boundaries | 20 repetitions of the 3072-byte IN/OUT case and following APDU; each repetition also checked 64, 128, 192, 256 and 320-byte IN transfers |
| Physical USB reset | 50 repetitions, both PIV authorities active before each reset and revoked afterwards; the RAM-only clock survived |
| Reset oracle | Removing the USB reset failed specifically at `PIN authority survived reset`; the control connection retained authority under `SCARD_LEAVE_CARD` |
| Complete PIV suite | `80_piv.py --rsa` passed, including ECDSA, ECDH, attestation, object boundaries, RSA, PIN changes and factory reset |
| Physical crypto | RSA-2048 generation plus five verified signatures; ML-DSA-44/65/87 registration and five independently verified assertions per set |
| Physical CANCEL | All three ML-DSA sets cancelled after a real PROCESSING report, followed by a new verified signature |
| Physical card reset | PIN and management authority revoked; a new RSA signature verified under the existing public key, without rebooting the MCU |
| OTP over EP0 | Three YubiKit configuration/HMAC/delete cycles with matching CCID/HID status; scratch slot 2 removed |
| OTP across warm reboot | The first feature report, before CCID SELECT, exposed the persisted slot; HMAC verified and the scratch slot was deleted |
| HID and routing | PING through 7609 bytes, invalid command/length/sequence, competing channel and timeout recovery; U2F/vendor isolation and CCID smoke passed |
| Normal-image boundary | Test-only CTAPHID `0xFE` was refused |

Physical ML-DSA keepalive gaps peaked at 119.703 ms on the host monotonic clock.
During RSA generation/signing, 572 USB PINGs completed inside the operations;
the largest PING latency was 7.580 ms. PC/SC does not expose CCID time-extension
counts, so those physical measurements do not claim to count WTX packets.

The same final ELF passed the real-crypto image test and all 17 image-emulator
CANCEL/reset/disconnect/authorization scenarios. Both full repository gates
passed. The host-test row was repeated after adding the emulator-scope checks:
944 passed; the assurance row had 2708 passed. In-diff Rust mutation enumeration
found no applicable operators: the host-crate changes add/remove ABI constants,
while the runtime fixes are embedded glue. The shared mutation container was
already occupied by a separate checkout and was left untouched.

The report/APDU shim refuses suites 100/101 before loading their raw USB
backend. The host tests execute that CLI path and remove each refusal in a
negative control, where a blocked import detects entry into the physical suite.
This does not restrict direct USB/IP testing of an emulated USB device.

### Limits and retained failure

These were automatic checks. The reset script gives macOS two seconds to
recreate its CCID driver and then waits at most 30 seconds for the reader; it
never retries a failed APDU. Earlier resets without that settling interval
lost the macOS reader while HID and Secure still answered. That immediate-reset
stress case is not counted as a passing hardware case. PC/SC also refused a
one-byte XfrBlock before sending it, so that malformed physical transfer remains
unchecked through this host API. Real removal of power, physical touch and
fused secure-boot acceptance were not tested.

An earlier 0x0AAF full PIV run returned `6581` at factory RESET. Its defaults
were recovered through the normal applet protocol; a complete rerun, a clean
image-emulator run and the final 0x0AB0 hardware run passed. The original failure
is retained as an unexplained hardware finding, not reclassified as a pass or
claimed fixed by the OTP change. No full-flash export was taken for it.

The follow-up no-touch diagnostic image (0x0AB1) reproduced the RESET failure
on cycle 13 of `tests/102_piv_factory_reset.py --runs 20 --churn 8 --rsa`, after
12 complete cycles. Its stage code `6F04` identifies the failed `Fs::put` of
`EF_RETRIES` while provisioning the factory PIN/PUK retry counters. The public
FLASH INFO command then reported 52 files and 3822 payload bytes. This localizes
the failure to that write; it does not yet identify the failing storage operation.

A later 20-cycle attempt completed ten cycles, then lost PC/SC during PUT DATA
on cycle 11, before RESET. The Mac entered idle sleep four seconds after that
transport error. That interrupted run is not a 20-cycle pass or another `6581`
reproduction. The two earlier RESET failures had no nearby host sleep events.

The no-touch 0x0AB7 diagnostic retained the 0x0AB1 load addresses and completed
all 20 cycles of the same `--runs 20 --churn 8 --rsa` command. Both retry pairs
were `3/3` before VERIFY, the slot keys and object were removed, and every new
F9 certificate verified independently. This run did not reproduce the earlier
write failure; it does not resolve that finding.

The following no-touch 0x0AB8 diagnostic completed 100 authenticated
`EF_RETRIES` delete/recreate cycles, then three full RESET cycles with RSA.
The 0x0AB9 diagnostic kept the 0x0AB1 load addresses and one-byte SDK errors.
After initialization at boot, its additional diagnostic instructions ran only
on error paths. It passed `tests/80_piv.py --rsa` and another 20 cycles of
`--runs 20 --churn 8 --rsa`. Image-emulator controls checked SDK errors 0, 1 and
7, storage phases, and stopping at the first error before SELECT or a RESET
retry. These passes did not identify the cause of the earlier write refusal;
no production firmware fix resulted.

The later no-touch 0x0ABA diagnostic froze counter and main write errors
before filesystem recovery. Key-source acquisition and filesystem prechecks
were outside this trace. It completed
20 more full RESET cycles with RSA and eight object rewrites per cycle. Three
additional complete PIV suites passed under 60,242 concurrent HID PINGs; the
longest PING took 0.190 seconds. All diagnostic error records remained empty.
These runs did not reproduce `6581` or identify why `EF_RETRIES` was refused.

The temporary no-touch 0x0ABC diagnostic also covers `Fs::put` prechecks and
storage-key acquisition. It freezes the SDK error, enclosing operation and FID,
error sites and sequential-storage error class before filesystem recovery can
overwrite them. The enclosing FID identifies the requested operation; validation
may fail on another retained payload. Driver errors and readback mismatches also
retain the flash operation, offset, length and error kind. Root diagnostics contain the root arm,
blank/fused/unreadable row state and latch flag. `EF_RETRIES` is routed to
the authenticated Main store; the separate counter bank serves the declared
`COUNTER_FIDS` set.

Three image-emulator controls checked this capture through the actual RESET
command. An injected `NoMemory` at retry-file recreation returned `6581` and
froze the filesystem precheck. A separately skipped flash program made the real
readback check fail; RESET returned `6581`, with `MemoryFatal`, write context
`D1FE` and the journal flash offset retained before recovery. A one-shot
`RootRead::Unreadable` also returned `6581`, preserving the root row state and
write context without reporting a flash IO error. These deliberate faults
validate the diagnostic; the original hardware failure remains unexplained. An
uninjected image completed RESET after all 34 varied object lengths.

The earlier direct-call RAM probes synthesized retry bytes at the wrong offsets
and bypassed the command-level RESET gate. Their final `[3,3,0,0]` tuple leaves
the PIN unblocked; the real RESET rejects it with `6A80` and no flash changes.
Those runs cover storage operations rather than the complete APDU workload.

A replacement RAM NOR probe drives `PivApplet` through SELECT, management
authentication, real EC/RSA generation and signing, eight varied object writes,
PIN change, exact wrong-reference statuses and RESET. Each of 100 admitted
resets starts with `[3,0,3,0]`, restores `[3,3,3,3]` and checks factory metadata,
slot-key and object removal. Erase events measured 58 resets with neither journal
rollover nor payload erase, 13 with journal rollover only, 23 with payload erase
only and 6 with both. Foreign records and the routed counter survived, and all
registry dependencies match the firmware lockfile. This model does not exercise
USB or RP2350 flash timing and did not reproduce the original `6581`.

The 0x0ABC physical series then completed 40 full RESET cycles with RSA and
eight object writes per cycle, covering all 34 lengths. Each cycle checked
factory retry pairs before VERIFY, removal of the generated keys and scratch
object, and the new F9 self-signature. All diagnostic error records remained empty.

The saved 0x0AB1 ELF matches the load bytes of its original UF2. It completed 20
image-emulator RESET/RSA cycles with eight 3046-byte writes per cycle; 0x0ABC
completed another 20. A separate image run used synthetic legacy KV with
48 foreign public records, 1,055 writes of a 3046-byte value and a routed `C000`
counter. That full RESET/RSA cycle also passed with no frozen error. The existing
firmware load segments were unchanged; no data from the physical key was used
for the fixture.

The key was restored to the normal TrustZone no-touch 0x0ABB image, clearing
prior diagnostic code outside KV. A fresh no-touch build matched the previously
verified UF2 byte for byte. CCID started without a recovery USB reset. The private
EP0 request stalled; standard EP0 and HID remained live. The full `80_piv.py --rsa`
suite and one strict RESET/RSA cycle with varied object lengths passed on that
image.

No production PIV fix resulted from these runs. The internal cause of the
original `EF_RETRIES` refusal remains unknown.

While returning to the ordinary no-touch 0x0AB0 image, programming and
verification passed, but PC/SC reported `NoCard` and HID INIT did not answer.
Live EP0 GET_STATUS still answered. One host USB bus reset recovered HID
without reflashing. The cause of this stall after flashing has not been
identified; that first start is retained as a failed hardware case.

The RESET runner also accepts `--vary-churn`, which cycles object lengths from
one byte through 3046 bytes, with lengths around common packet and page sizes.
For a disposable no-touch key, run
`python tests/102_piv_factory_reset.py --runs 40 --churn 8 --rsa --vary-churn`
with the reader and serial selection described in [testing](testing.md).
Each cycle still checks the exact PIN/PUK countdown and factory retry counts,
key and object removal, and the replacement F9 certificate. Varying the lengths
changes payload page packing; it is another reproduction workload, not a fix.

A RAM NOR model separately completed 6000 direct `reset_files` calls after
fragmented legacy import, across three storage roots and epochs. It checked all
four retry bytes and preserved the imported foreign records and routed counters.
This model does not exercise the RP2350 flash driver or USB.

Controlled image-emulator failures after payload append and at candidate
verification returned an error while both PIN/PUK retry pairs already read
`3/3`: the post-error scan published the prepared counter value, but provisioning
had stopped before the management key and F9. Correct retry counts after an
error do not establish a complete RESET or identify its storage failure.

`tests/102_piv_factory_reset.py` exercises this boundary repeatedly. Each cycle
changes the PIN, creates and verifies a P-256 key (also RSA with `--rsa`), and
rewrites a 3046-byte object `--churn` times. RESET must then restore the default
PIN and management key, remove the slot keys and object, and publish a different
F9 key whose certificate verifies independently. On a failed RESET it records the
PIN-query and public slot-metadata statuses, including both PIN and PUK retry
counts when readable, before any SELECT can repair files. A successful RESET
must restore both retry maxima and remaining counts to three before VERIFY can
update them. Every preceding wrong PIN/PUK response must show the expected
countdown or blocked status; a transient write failure cannot disappear behind
a later blocked response. The script stops after a failed RESET without
retrying it. It destroys the selected key's PIV data.

```sh
RSK_TEST_READER='RS-Key RS-Key Security Key' nix develop -c \
    python tests/102_piv_factory_reset.py --runs 10 --churn 4 --rsa
```

Keep the host awake throughout a physical run. On macOS, put `caffeinate -i`
before `nix develop` in this command; the sleep assertion ends with the test.

The same script runs through `tests/emu.py`, including the firmware image
backend. An omitted-RESET negative control must fail at default-PIN verification
after a simulated `9000`, before any F9 comparison can hide the missing reset.

The first same-process libusb open immediately after the additional warm reboot
found no device despite HID enumeration. A fresh USB context then verified the
first OTP status and HMAC before any CCID selection and removed the scratch
slot. This host handover failure is separate from the firmware status mismatch
that suite 101 reproduces.

The tested UF2 SHA-256 is
`30846b4672e705c92f10d23e63d2152be7fd283bab4f082401d6d84eca4630bb`;
the combined ELF SHA-256 is
`0ba9fca891f549978f99ffcf04577a673961e4798db93480c3341769efd08919`.

## Configuration status completion at bcdDevice 0x0ABB

An image replay reproduces a configured host with live EP0 and silent HID when
Secure IRQ handling is delayed after the SET_CONFIGURATION status packet is
armed. The host ACKs that packet and sends another SETUP before Secure handles
the completion. Cancelling the old control task first used to lose the Secure
configuration transition. The same delay without another SETUP completes normally.

Secure now binds the configuration status to its control ticket, clears a previous
EP0 IN completion before arming it, and consumes the hardware completion before
invalidating the old request. A completed configuration survives suspend in the
new epoch; a bus reset takes precedence over an old ACK. Revocation still clears
authorization and fences old responses. No persistent record format changes.

`tests/103_trustzone_configuration.py` builds disposable images with a bounded
IRQ delay and a public admission marker. It uses only loopback emulator sockets.
Its ordering control moves ACK handling below SETUP invalidation: the neutral
case must still answer HID INIT while the overlapping SETUP must lose admission.
Neither the delay nor the marker is part of an ordinary build.

This replay identifies a real configuration race. It does not establish the
cause of the earlier physical post-flash incident.
Before this change, five code-only reflashes and 500 SET_CONFIGURATION /
GET_CONFIGURATION pairs passed on the reference key, including 50 HID checks.
The separate PIV RESET write refusal remains under investigation.

The observer also accounts for events first seen by HAL after the initial raw
register snapshot. HAL acknowledgement cannot swallow a reset or suspend without
Secure revocation. The final snapshot retains only observations already handled;
it cannot mark a newly arriving event as handled. Suspend tracks the read-only
bus level separately from the acknowledged IRQ, following the
[pico-sdk register definitions](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2350/hardware_regs/include/hardware/regs/usb.h).

`tests/104_trustzone_late_reset.py` pauses the image after its raw snapshot,
authorizes PIV first, then injects a USB reset through the emulated host. The
corrected image advances epoch 2 to 3 and refuses the old PIN authority before
SELECT. Removing only the HAL reset fallback retains epoch 2 and answers `9000`
to that same PIN query. Both runs reconfigure USB without a power cycle.

## Software recheck on 2026-10-16

The recheck used branch revision `9b9ce0c4` and fresh partitioned combined
images. PIV RESET `6581` investigation was excluded. No firmware behavior,
build counter, dependency pin or hardware state was changed by this recheck.

| Check | Observed result |
|---|---|
| Real cryptography | RSA-2048 generation and two independently verified signatures; ML-DSA-44/65/87 registration and two independently verified assertions each |
| Lifecycle | All 17 CANCEL/reset/disconnect/session cases and the separate image-clock reset-window case passed |
| Hostile NS | Three allowed controls and 52 denied read/write/execute cases passed with the NS MPU disabled; denied writes preserved synthetic Secure data and terminal faults fenced USB/DPRAM |
| Isolation controls | Relaxing only the USB grant or only the synthetic Secure-data SAU region let the forbidden access reach its post-read marker |
| Profiles | 2 MiB and 16 MiB no-touch images built and answered getInfo after cold boot; the 16 MiB trusted-display profile built with `LED_KIND=none`; its KV end retained the E10 exclusion |
| Reproducibility | The immutable `firmware-trustzone` Nix derivation and independent `--rebuild` completed with identical ELF and UF2 outputs |
| Upgrade | The saved v0.4.11 image's OATH key, resident FIDO signing key and changed OpenPGP PIN survived automatic migration into the new image |
| Artifact coverage | Hash-only sealing verified the combined ELF; a changed byte in each of `.text`, `.rsk_exec`, `.gnu.sgstubs`, `.nonsecure` and `.pt` produced `hash: incorrect` |
| Symbolic checks | All 12 `rsk-device` Kani harnesses passed using the runner's soft-backend flags, including both MPU-layout branches |

The hostile-image matrix also covers XIP/SRAM aliases, NSC data and mid-veneer
execution, USB atomic aliases, DPRAM, DMA, clocks, resets, OTP, TRNG, QMI and
boot RAM. Its fault hook exposes only synthetic test state in a disposable
image. These results describe the emulator's enforced paths, not silicon.

The image laboratory previously treated core0's active SP as its Secure stack
even while NS ran. Measurements now select each security bank explicitly,
derive the NS top from the embedded ELF vector and its floor from Secure SAU,
and report `ns0_*` alongside the existing Secure fields. Invalid, overlapping
or ambiguously attributed ranges are refused before painting. The regressions
use real BXNS/SG transitions, preserve live frames in both banks and expose an
NS underflow independently of a healthy Secure stack. Ordinary images retain
their two-stack report; PSP and Non-secure core1 are refused explicitly.

In the final 4 MiB no-touch replay, ML-DSA-87 creation used 84,940 bytes of the
Secure core0 allocation and signing used 94,288 bytes. Core1 used 520 bytes and NS
core0 used 744 bytes. These are sampled minima, not the paint extent: deliberate
RAM scrubbing can overwrite the whole painted range. They do not establish
physical interrupt, cache or FP-state margins.

The software assurance gate also exposed a release-citation false positive:
the hex fragment inside the word `header` was mistaken for a commit ID. The
existing `develop` fix was ported with its regression; hexadecimal commit
citations remain rejected while fragments inside words are accepted.

The read-only reference-key check answered getInfo and reported diagnostic
`bcdDevice 0x0ABC`, superseding the earlier recorded restore as a statement of
current board state. No flashing, signing or fuse operation was performed.
The hardware-release rows above remain open, including powered removal,
physical presence/panel checks, exception/FP behavior and fused boot acceptance.

The additional 16 MiB display cold-boot smoke timed out before USB enumeration.
Core0 waited at `PioDisplayTx::flush` for PIO0 `FDEBUG.TXSTALL0` while the
model reported neither a fault nor a reboot. The PIO model records an empty
TX pull as `StallKind::Pull` but never latches that event into `FDEBUG`; its
only writes to the register are reset and explicit register writes. This is
a model limitation, not evidence of a firmware failure. The display profile
is build-verified only; its runtime remains unchecked.

The ordinary full-operation runner stopped at populated FIDO RESET because its
120-second wall-clock client deadline expired while keepalives continued. An
image-only replay retained the original operation order and assertions, with
a RESET bound of 120 image seconds, a 1200-second host backstop and a maximum
USB keepalive gap of 0.5 seconds. RESET completed, removed the PIN and refused
the deleted credential. The shared device helper retains its original deadline;
this replay does not establish a physical reset latency.

## Image-laboratory follow-up on 2026-10-16

The canonical image runner now bounds CTAP requests to 120 seconds on the image
clock, with a separate 1,200-second host watchdog. Both bounds cover the final
HID report and continuation reads. A terminal fault, a changed power-up count or
a backwards clock refuses the result. Native runs retain their 120-second
keepalive wait. Each measured operation retains every CTAP transport sample and
refuses an image-clock USB gap over 500 ms. Regression tests and isolated
negative controls check the callback wiring, both clocks, final reads, USB gaps
and preservation of the original error if stack inspection also fails.

The same touch-enabled 16 MiB display ELF now cold-boots through the pinned A4
ROM, enumerates with three USB interfaces and answers getInfo at bcdDevice
`0x0ABC`. Three model corrections were required:

- PIO `FDEBUG.TXSTALL` latches on an actual empty blocking PULL or autopull,
  including forced instructions and elapsed ticks in the idle batch path.
  W1C clears the latch; no-tick and ordinary disabled stepping do not recreate it.
  A waveform test checks that TXEMPTY precedes transmission of the last bit.
- I2C NACK completes TX and preserves its abort cause through STOP until the
  explicit interrupt-clear read. This lets Embassy observe the refusal and
  continue without an attached CST328. The first 10-bit address NACK uses bit 1.
- UART1, SPI1 and I2C1 use their RP2350 bases at `0x40078000`, `0x40088000`
  and `0x40098000`. Independent SDK-address tests exercise real peripheral
  reset values, both instances, reset gates and the XOR/SET/CLR aliases.

The pre-fix display waits and failing register assertions are retained in the
verification report. Removing each PIO latch path or its completion ordering,
and reverting the I2C completion/cause fixes, fails the matching assertions.
The image backend uses the serial emulator; these changes do not implement
the threaded runtime's missing secondary-peripheral routes. The panel and
CST328 contacts are still not modelled, so boot/getInfo is not physical display
or touch-approval validation.

Three filesystem contract tests also close the six non-equivalent mutation
survivors from the develop integration. The repeated set has 65 caught,
three unviable and one equivalent mutation: at equal lengths, Torn's `>` to
`>=` replacement only appends an empty suffix. These are test/model/tooling
changes; firmware behavior and bcdDevice are unchanged.
