<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# TrustZone verification record

## Verification scope

The ordinary gate builds the combined image. The image suite runs the actual
TrustZone ELF through RP2350 ROM, exercises command stacks and interrupted
writes, and checks automatic OTP sealing. CI runs these on `develop`, `main`
and pull requests. ELF, constant-time and owner-binding readers inspect the
combined Secure image; the NS ELF is audited separately and compared with its
embedded payload. Old formal evidence does not automatically become evidence
for the changed Secure/NS execution boundary.

The image suite also builds a separate `test-gateway-probes` image. Startup
checks reject Secure RAM, NS code/MMIO, crossing and wrapping worker buffers,
zero-capacity replies and malformed request tags. Valid NS RAM and empty-input
controls must reach the worker; abandoned replies must preserve their buffer.
The runner requires the completion diagnostic and a subsequent getInfo. The
ordinary image is rebuilt with probes disabled. These checks exercise the
worker gateways in the emulator. Physical RP2350 A2 measurements are recorded below.

The suite separately builds hostile NS images that disable their MPU and read
or write USBCTRL at `0x50110000`, or write DMA's interrupt register at
`0x50000400`, after arming a nonzero IN packet. The runner requires the selected
LDR/STR instruction in the matching NS ELF, the pre-access marker, no post-access
marker, that exact BFAR and CFSR `0x8200`, and the terminal USB/DPRAM fence. A
completion barrier precedes the post-access marker.
`RSK_TZ_PROBE_ACCESS=read|write` selects the test access; reading remains the default.
Inherited probe settings cannot enable a test feature in the ordinary image.

The resource matrix reuses zero-address read/write images. After arming its IN
packet, NS yields until the laboratory selects the target in NS RAM. Each case
boots a fresh emulator, checks the instruction and pre-access marker, and compares
the fault address and status before checking the USB/DPRAM fence. NS RAM controls
must complete first. At most two denied cases run together, with separate ports
and logs. Peripheral denials use BFAR/CFSR; SAU memory denials use
SFAR/SFSR (`AUVIOL | SFARVALID`). The matrix includes peripheral grants, all DMA
channel address/count/control and security registers, critical atomic aliases,
Secure flash/RAM and scratch code. These are model checks, not silicon measurements.

The suite also synchronizes RSA ABORT/reset/disconnect at a private-operation
barrier in a disposable source copy, avoiding a race against the first WTX.
A separate authorized-fault image checks terminal USB fencing and refusal of
further CCID traffic. It cold boots the same store without ICC power-on, checks
PIN refusal before PIV SELECT, then PIN and management refusal after SELECT.
New authorization must succeed. The normal image runner compares the complete
scratch code and padding with the exact ELF on entry and exit from each scenario.

| Negative control | Observed failure |
|---|---|
| Omit the NS startup probe call | `scripts/image-suites.sh` refuses the incomplete completion diagnostic |
| Remove `--gateway-image` from the image-suite command | The row regression detects that incomplete probes were accepted |
| Grant NS access to USBCTRL in disposable images | `scripts/image-suites.sh` fails because the protected read or write succeeds; the store changes the logged USB address to 127 |
| Grant NS access to DMA in disposable images | `scripts/image-suites.sh` fails because the protected DMA write succeeds; the post-probe marker is reached |
| Substitute LDR for the hostile store | The ELF instruction check refuses the mislabeled write probe |
| Omit the hostile write case | The row regression detects that the write image was never checked |
| Corrupt one SRAM8/9 padding byte | The real basic row refuses scratch bytes that differ from the ELF |
| Jump to terminal stop without fatal cleanup | The authorized-fault row fails with `authorized fault left USB/DPRAM live` |
| Omit the fatal fence in the physical diagnostic | The actual USBCTRL store faults, but retained flags 193 instead of 223 expose missing cleanup |

On 2026-11-03, suite `108_trustzone_hardware.py` passed 184 read and 179 write
cases on `rs-key-0001`, RP2350 A2, ROM `312e22fa`, secure boot disabled. Both
matrices included nine allowed controls. They checked the launch registers,
all sixteen DMA channel locks, protected peripheral/memory accesses, fatal USB
cleanup and fresh PIV authorization. Both cores retained scratch RX permissions
during normal execution and the observed flash MPU window. The complete
7936-byte code/padding image matched its ELF through every reset.

The BOOTSEL arm verified actual SRAM write/read service, submitted one original
UF2 block and observed the overlapping ROM erase bitmap while the old application
remained absent. A complete reload passed all twenty baseline cases again.
The ordinary touch-enabled image was restored; getInfo passed, the private
diagnostic command was refused, and PIV authority was absent. The precommitted
criteria and raw captures are linked from
[`PLAT-TZ-001`, `PLAT-TZ-008` and `PLAT-TZ-009`](platform-assumptions.md).

Before a hardware release, verify debug denial after cold power-up, signed
combined-image update/rejection, page-58 read denial and the remaining physical
isolation cases. Neither emulation nor a successful build substitutes for those
board measurements. Both `DEBUG_DISABLE` and `SECURE_DEBUG_DISABLE` are required
by the production provisioning policy.

The maintainer archived the PIV RESET `6581` investigation on 2026-11-04
after follow-up hardware and emulator attempts did not reproduce it. The latest
physical series completed 200 RESET/RSA cycles. It is no longer an active task
or release blocker; no firmware fix is claimed. Reopen only with fresh failure
data or a reproducible case. The [investigation history](trustzone-evidence.md#piv-reset-recheck-on-2026-11-04) is retained.
