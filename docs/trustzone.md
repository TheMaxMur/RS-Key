<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# TrustZone boundary and resource ownership

TrustZone is mandatory from bcdDevice 0x0BDA. USB classes and
transports run Non-secure (NS); the controller, lifecycle observer, worker,
applets, cryptography, storage, OTP and trusted board input/output stay Secure
(S). The firmware is delivered as one combined ELF/UF2, including the storage
partition table. Secure revocation observes the hardware USB lifecycle and
does not depend on NS reset callbacks.

TrustZone does not enable Secure Boot or burn provisioning fuses. Enforced
Secure Boot authenticates the combined image; page-58 provisioning protects
the storage roots. [Production setup](production.md) describes that process.
The [engineering history](trustzone-history.md) records dated measurements and
their limits. Passing an image test does not establish silicon resistance to
physical attacks.

## Build and update

```sh
nix build .#firmware
# result/firmware.elf and result/firmware.uf2

nix develop -c env BOARD=waveshare-one \
  bash firmware/trustzone/build.sh --features strong-pin,advertise-pqc
# target/trustzone/combined.elf and combined.uf2
```

The builder links S to export its CMSE entry points, links NS against that
import library and the generated NS memory map, then embeds NS in the final S
link. The import library must remain identical across the two S links. All
documented board and identity knobs reach those links; firmware features apply
to S, with shared transport policy forwarded to NS. See [build options](build.md)
for pure Nix configuration, ENV overrides and test-only features.

Sign the combined ELF after the partition table has been added. Flash only
the resulting combined image. Building or signing either half separately is
not an update procedure. Keep the same flash geometry and KV layout when
upgrading a provisioned device. There is no non-TrustZone authenticator build,
feature switch or legacy Nix package. `--no-default-features` cannot remove the
boundary. Bare Cargo refuses to build outside the S/NS link stages.

The first Secure link exists only to export the import library. It halts before
initialization if it has no embedded NS payload, even over old NS flash contents.
The final link requires the payload. `rsk-wipe` remains a separate Secure SRAM
recovery utility; it has no authenticator applets or Non-secure transport.

After OTP keys are provisioned, S validates the key rows, migrates records and
scrubs old copies before automatically closing page 58. If a PIN-bound record
needs its PIN, sealing waits; present the PIN and reboot. A completed latch
causes a scrubbed reboot before NS starts. `rsk otp status` reports the outcome.

## Verification scope

The ordinary gate builds the combined image. The image suite runs the actual
TrustZone ELF through RP2350 ROM, exercises command stacks and interrupted
writes, and checks automatic OTP sealing. CI runs these on `develop`, `main`
and pull requests. ELF, constant-time and owner-binding readers inspect the
combined Secure image; the NS ELF is audited separately and compared with its
embedded payload. Old formal evidence does not automatically become evidence
for the changed Secure/NS execution boundary.

Before a hardware release, verify debug denial after cold power-up, signed
combined-image update/rejection, page-58 read denial and the remaining physical
isolation cases. Neither emulation nor a successful build substitutes for those
board measurements. Both `DEBUG_DISABLE` and `SECURE_DEBUG_DISABLE` are required
by the production provisioning policy.

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
boundary. The existing [threat model](threat-model.md) also applies to Secure code.

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

| Resource | Implementation | Owner and permitted NS use |
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

The 4 MiB reference build uses the following linker/SAU bounds. These are
the current layout, not fixed production offsets for every board. The builder
derives the boundaries from the combined image and retains each board's
existing KV layout.

| Region | Current address range | Owner |
|---|---|---|
| S code | `0x10000000..0x1026efff` | S |
| NSC entry veneers | `0x1026f000..0x1026ffff` | S, callable only through declared entries |
| NS code | `0x10270000..0x1027ffff` | NS execution; S update policy |
| KV main/counters | `0x10280000..0x103fffff` | S |
| S SRAM | `0x20000000..0x2006ffff` | S |
| NS SRAM | `0x20070000..0x2007ffff` | NS |
| Scratch SRAM data | `0x20080000..0x200800ff` | S, unallocated |
| Scratch SRAM code | `0x20080100..0x20081fff` | S, read-only executable |

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
