# Production setup — signed boot + OTP master key

> ⚠️ OTP writes are permanent. A wrong boot key, image or lock can leave
> the board unable to boot or recover enrolled credentials. Keep the
> signing key and the recovery artifacts before enabling enforcement.

RS-Key always runs a combined TrustZone image. The Secure half owns OTP,
storage and the applets. Enforced Secure Boot authenticates the combined
image before either half runs. The OTP master key protects device-sealed
records at rest. The rollback floor lets the ROM reject older signed
images.

## Before you start

- Match the board, flash size and KV layout of the device you are updating.
  Use the production build with its partition table. Use disposable storage
  with diagnostic builds and builds with `no-touch`, `FAKE_MKEK` or `FAKE_DEVK`.
  See [Build options](build.md).
- Back up existing credentials before provisioning. A
  [FIDO seed backup](guides/seed-backup.md) restores non-resident credentials.
  Plan separate recovery or re-enrolment for resident passkeys, OpenPGP, PIV,
  OATH and OTP slots.
- Check `rsk secure-boot status` in BOOTSEL and `rsk otp status` in the
  running firmware before working on an existing board. Use the update path
  for a board that already enforces Secure Boot. Current firmware can
  finish a pending page-58 seal automatically at startup.
- Disconnect other RP2350 boards before using the provisioning commands.
  The commands that explicitly write fuses offer `--dry-run` and ask for
  confirmation. Page-58 sealing and a ROM rollback advance happen during
  boot. See [OTP fuses](otp-fuses.md).

## Every command on this page, in order

![Production provisioning order. Sign the combined TrustZone ELF and the recovery image, then load and test the signed firmware. Provision the fingerprint with load-key, run harden, and run enable. Check the first enforced boot and read back the rollback policy. Run lock for a fixed key or skip it to retain rotation. Then provision page 58 with rsk otp burn.](images/secure-boot-chain.svg)


This order establishes which firmware the board trusts before it
provisions the device secrets on page 58.

| Step | Where | Action |
|---|---|---|
| Prepare | Host | Generate and back up the signing key. Build the combined ELF and `rsk-wipe` for this board. Seal both ELFs, convert them to UF2 and inspect the files. |
| Check the image | BOOTSEL, then running firmware | Load the signed firmware and check that the application starts before changing the boot policy. |
| Stage A | BOOTSEL | `rsk secure-boot load-key` writes the signing-key fingerprint and sets `KEY_VALID`. Reboot and check the signed image again. |
| Stage B | BOOTSEL | `rsk secure-boot harden` sets both debug disables and configures glitch detection. Cold-boot and verify debug denial. |
| Stage C | BOOTSEL, then normal flash boot | `rsk secure-boot enable` sets `SECURE_BOOT_ENABLE`. Boot the signed firmware. With `--rollback 1` on a fresh board, the ROM can also set floor 1 and `ROLLBACK_REQUIRED` on this boot. Verify enforcement. |
| Stage D | BOOTSEL | `rsk secure-boot lock` revokes the other slots and makes the boot-policy and key pages read-only from BOOTSEL. Decide about rotation before this step. |
| Provision storage | BOOTSEL, then running firmware | `rsk otp burn` writes DEVK and MKEK. Secure startup migrates storage, scrubs flash and seals page 58. Check `rsk otp status`. |
| Change rollback policy | Host, then device | For later activation or an increase, follow [Stage 3](#stage-3--anti-rollback-optional). Prepare both signed images at the intended version before booting a higher one. |

<a id="stage-2--secure-boot"></a>

## Stage 1 — Secure Boot

### 1a. Generate and back up the signing key

Generate a separate secp256k1 signing key for this board. The example
paths are for one board. Keep another board's files in a separate directory.

```sh
mkdir -p ~/.rs-key-secrets
cd ~/.rs-key-secrets
openssl ecparam -genkey -name secp256k1 -noout -out secure_boot_key.pem
openssl ec -in secure_boot_key.pem -pubout -out secure_boot_pub.pem
```

Back up the private PEM off the build machine and check that you can
restore it before Stage C. The private key stays on the signing host.
The board receives its public-key fingerprint. See [Signing keys](signing-keys.md)
for storage, passphrases and rotation.

<a id="2b-sign-and-prove-a-signed-image-boots-before-any-fuse"></a>

### 1b. Sign and check both images

Run these commands from the repository root in `nix develop`. The example
uses the 4 MiB Waveshare RP2350-One.

```sh
BOARD=waveshare-one bash scripts/build.sh
```

The [TrustZone builder](architecture.md#trustzone-build-and-boot) links the
Secure firmware and CMSE gateways, embeds the linked Non-secure image and
adds the partition table to `target/trustzone/combined.elf`. Sign that
finished ELF as a single image. For a Nix build use `result/firmware.elf`
from `nix build .#firmware` or the ELF for the matching
[board or feature variant](build.md#nix-build-hermetic-no-dev-shell).
For the Waveshare display board use
`BOARD=waveshare-touch-lcd bash scripts/build.sh --features display`
or the `firmware-display` package.

Seal the ELF before converting to UF2. With rollback metadata, the ELF
sealing path marks the original unsigned image definition as ignored.
Sealing a combined UF2 can leave the original block active. A signature
reported as verified on the host is insufficient if the ROM rejects that
block first.

The example chooses rollback version 1 on a fresh board. The first
normal boot after enabling Secure Boot can then permanently commit
floor 1 and require rollback metadata. To start with Secure Boot alone
and leave a fresh board at floor 0, omit `--rollback 1` from **both**
signing commands below. `--major` and `--minor` are separate image
version fields.

```sh
picotool seal --sign --hash target/trustzone/combined.elf -t elf firmware-signed.elf -t elf \
    ~/.rs-key-secrets/secure_boot_key.pem ~/.rs-key-secrets/otp_secureboot.json \
    --major 1 --minor 0 --rollback 1
picotool uf2 convert firmware-signed.elf -t elf firmware-signed.uf2
picotool info -a firmware-signed.uf2
```

Check `hash: verified`, `signature: verified` and the intended rollback
version in the signed block. For a versioned combined image, check that
metadata block 1 is `ignored`. The firmware partition should show
`NSBOOT(rw)`; the `RS-Key Store` partition should show
`S(rw) NSBOOT(-) NS(-)`. The signature covers both firmware halves, the
gateways and the partition table. File inspection verifies the artifact
against its embedded key. The board boot after Stage C tests whether its
OTP trusts that key.

Build `rsk-wipe` for the same hardware and physical flash size, including
any explicit `FLASH_SIZE` override. It is a separate SRAM program for
erasing flash. Sign it with the same key and intended rollback version.

```sh
BOARD=waveshare-one cargo build --locked --release -p rsk-wipe
picotool seal --sign --hash target/thumbv8m.main-none-eabihf/release/rsk-wipe -t elf \
    rsk-wipe-signed.elf -t elf ~/.rs-key-secrets/secure_boot_key.pem \
    --major 1 --minor 0 --rollback 1
picotool uf2 convert rsk-wipe-signed.elf -t elf rsk-wipe-signed.uf2
picotool info -a rsk-wipe-signed.uf2
```

Check the signature, hash and intended rollback version. The wipe UF2
should report family `rp2350-arm-s` and a signed Arm Secure image
definition in SRAM (`0x2000_0000`–`0x2007_FFFF`). Keep both signed UF2s.
Launching the wipe image erases flash, so test it only on a board whose
contents you can lose.

Enter BOOTSEL using the board button or `rsk reboot bootsel` from a
running RS-Key. Load **the signed firmware**, then confirm that it
enumerates and responds. At this point you are checking the image can
run on this hardware. Stage C checks signature enforcement.

```sh
picotool load -v firmware-signed.uf2 && picotool reboot
```

Wait for RS-Key to enumerate, then run `rsk status` and check that the
expected device responds over FIDO or CCID before moving on.

#### What `otp_secureboot.json` is for

`picotool seal` writes `bootkey0`, the SHA-256 fingerprint of the
public key it embedded in the image, to this host-side file. It also
emits provisioning flags. `rsk secure-boot load-key` takes the
fingerprint, writes it to the selected slot and sets that slot's
`KEY_VALID` bit. It reads both back. The separate `enable` command sets
enforcement. Use the JSON produced by the same seal as the firmware
you just checked. You can regenerate the fingerprint by sealing with
the same private key.

<a id="2c-burn-staged"></a>

### 1c. Program the boot policy in stages

Run each block separately and check its result before continuing.
Every `rsk secure-boot` command below runs in BOOTSEL. From the app,
use `rsk reboot bootsel` and approve on the device, or hold the board's
BOOTSEL button while reconnecting it. Wait for BOOTSEL to enumerate.
To preview a fuse write, run its command with `--dry-run` first.

#### A. Load the boot-key fingerprint

After the signed firmware has booted in Stage 1b, enter BOOTSEL.

```sh
rsk secure-boot load-key ~/.rs-key-secrets/otp_secureboot.json &&
    rsk secure-boot status
```

Slot 0 should show `[0]KV.` and `SECURE_BOOT_ENABLE` should still be
`False`. Run `picotool reboot`, wait for USB and check that the signed
firmware responds. Verify that your debug probe can access the board
before you harden it.

#### B. Harden debug and enable glitch detection

Return to BOOTSEL for hardening.

```sh
rsk secure-boot harden && rsk secure-boot status
```

Check that `DEBUG_DISABLE`, `SECURE_DEBUG_DISABLE` and
`hardening copies complete` are `True`, and `GLITCH enable/sens` is
`True / 3`. Unplug and reconnect the board normally. Verify that the
debug probe is denied and the firmware still runs. Return to BOOTSEL.

#### C. Enable Secure Boot and verify the first boot

Keep `firmware-signed.uf2` and `rsk-wipe-signed.uf2` ready. The checked
signed firmware should already be in flash. Enable enforcement from BOOTSEL.

```sh
rsk secure-boot enable && rsk secure-boot status
```

Check `SECURE_BOOT_ENABLE: True`, then run `picotool reboot`. Wait for
USB and run `rsk status`. Confirm that the expected applets work. On the
first normal flash boot the ROM can also advance the rollback floor.
Return to BOOTSEL and read the resulting fuse state.

```sh
rsk secure-boot status
```

With the version-1 recipe on a fresh board expect `SECURE_BOOT_ENABLE`
and `ROLLBACK_REQUIRED` to be `True` and `boot version 1/48`. With the
versionless recipe expect Secure Boot enabled, `ROLLBACK_REQUIRED`
clear and `boot version 0/48`. Investigate a mismatch before writing
more fuses.

On a disposable test board in BOOTSEL, use the unsigned UF2 from the
same build and layout to check rejection. The example uses the local
builder's output path.

```sh
picotool load -v target/trustzone/combined.uf2 && picotool reboot
```

Confirm that the unsigned firmware fails to start after a successful
transfer and reboot. Enter BOOTSEL with the board button if needed.
Restore the signed image and verify that it starts.

```sh
picotool load -v firmware-signed.uf2 && picotool reboot
```

#### D. Lock the boot-key policy (optional)

To retain [key rotation](signing-keys.md#5-rotate-a-key), leave a free
slot and skip this step. For a fixed key, enter BOOTSEL after proving
enforcement.

```sh
rsk secure-boot lock && rsk secure-boot status
```

The command requires one trusted slot and completed hardening. It revokes
the other slots and makes pages 1 and 2 read-only from BOOTSEL. Secure
writes remain available for later rollback advances. Check `LOCKED`, then
run `picotool reboot` and verify another normal signed boot before Stage 2.

<a id="stage-1--otp-master-key"></a>

## Stage 2 — OTP master key

Provision page 58 before enrolling new credentials. On an existing
device, the first boot with the new MKEK migrates eligible records,
including the FIDO seed, attestation key, persistent grant, and
key-base-sealed PIV, OATH and OTP records. Secure startup waits for
the required migration and a fresh flash scrub before it locks page 58.
The scrub can delay USB enumeration and successful sealing requests a
restart. Leave the device powered through that boot.

Enter BOOTSEL from the running signed firmware with `rsk reboot bootsel`
and approve on the device. Wait for BOOTSEL to enumerate, then check
that page 58 is ready for provisioning.

```sh
rsk otp burn --dry-run
```

If preflight succeeds, run the burn in BOOTSEL.

```sh
rsk otp burn
```

The command reboots the device. Wait for RS-Key to enumerate again,
then read the result from the running app.

```sh
rsk otp status
```

The burn command generates DEVK (device attestation) and MKEK (storage
sealing), programs the keys and chaff, verifies the rows and reboots.
The fused keys stay on the chip. DEVK changes the rescue attestation
public key. Re-record that identity if you use
[fleet verification](guides/fleet.md).

`rsk otp status` reports whether sealing finished. If it reports
pending migration, follow the listed actions and restart. A legacy
FIDO seed wrapped by a PIN or a legacy OATH OTP PIN can delay the latch.
Until the access lock takes effect, BOOTSEL can still read page 58.
An already-fused device can finish sealing automatically on an upgrade.
For an incomplete burn, a foreign lock or a torn latch, use the status
and recovery cases in [OTP fuses](otp-fuses.md) before attempting any
further fuse writes. The normal path completes the latch during startup.

### Existing PINs and recovery references

Present each configured reference so its verifier can migrate to the
fused root. OpenPGP also rewraps the DEK copy associated with that
reference. A successful migration of one reference leaves the others
to be migrated separately.

- **FIDO PIN.** Use a PIN operation such as `rsk fido list-passkeys`, or
  enter the PIN on the device display to unlock it.
- **PIV PIN and PUK.** Perform a PIN VERIFY. To migrate the PUK, use
  `ykman piv access change-puk` or the panel's Change PUK and supply
  the current PUK as both values.
- **OpenPGP.** In `gpg --card-edit`, `verify` presents PW1. For PW3, use
  `admin` and `passwd` option 3 with the current Admin PIN as both
  values. If you set a resetting code, set it again with option 4.
- **Legacy OATH OTP PIN.** Present it using the client that set it.
  The rewrite is best-effort. Recheck the migration status after restart.

Replug after these operations to let startup scrub superseded copies
from flash. The page-58 latch closes the pre-OTP path for the
device-sealed records it covers. Legacy PIN verifier and OpenPGP DEK
compatibility have their own limits. See [Seals and PINs](limitations.md#seals-and-pins).

## Stage 3 — anti-rollback (optional)

On a secured board the ROM compares an image's signed rollback version
with the board's OTP floor even when `ROLLBACK_REQUIRED` is clear.
The flag closes the path for versionless images. On normal Secure Boot
from flash, the ROM sets it when it advances the floor. With the
version-1 recipe in Stage 1, this typically already happened at the
first boot after `enable`. See the
[RP2350 datasheet, §5.1.11](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf).

<a id="turning-it-on"></a>

### Turning it on or raising the floor

Read the current floor and flag in BOOTSEL.

```sh
rsk secure-boot status
```

For floor 0, choose a positive version to start. To block a vulnerable
build, choose a version strictly above all affected images still eligible
under the board's trusted keys. Prepare and inspect **both** signed images
at that version using the [ELF workflow](#1b-sign-and-check-both-images).
In BOOTSEL load the firmware and boot normally. This boot can spend OTP bits.

```sh
picotool load -v firmware-signed.uf2 && picotool reboot
```

Confirm the app starts, then return to BOOTSEL and run
`rsk secure-boot status` again. If the floor differs from the intended
version, stop and investigate the image and boot path. If the floor is
correct and `ROLLBACK_REQUIRED` is already set, the policy is active.

If the floor is correct and the flag is still clear, verify that both
image files carry the intended rollback version. Use `picotool reboot`
from BOOTSEL and wait for the app. Preview the explicit fuse write.

```sh
rsk otp rollback-require --dry-run
```

If it reports the expected floor with the flag still clear, run the
write and confirm on the device.

```sh
rsk otp rollback-require
```

Read back the flag with `rsk status` or return to BOOTSEL and run
`rsk secure-boot status`. On a test board, check that trusted signed
images without a rollback version or below the floor are refused.
Restore the known-good image and check that it boots.

### After it's on

Reuse the floor for routine updates. Raising it from 3 to 5 spends two
logical bits and excludes signed versioned images below 5. The two
standard OTP words hold 48 logical bits, which is the denominator in
`rsk secure-boot status`. **47 is the highest version supported by the
pinned `picotool` with those two words.** Version 48 requires a third
row. Updates at 47 can still use 47. To exclude vulnerable images also
signed at 47, use [key rotation or a replacement board](anti-rollback.md#when-the-rollback-floor-reaches-47)
as applicable. See [Anti-rollback](anti-rollback.md) for version selection.

## Updating a provisioned board

Use the existing trusted key and preserve the device's flash geometry
and KV layout. Follow the combined ELF sealing sequence in
[Stage 1b](#1b-sign-and-check-both-images), using the current positive
floor for both firmware and the recovery utility. For an intentionally
versionless setup, check that the floor is zero and
`ROLLBACK_REQUIRED` is clear, then omit the rollback argument.

```sh
picotool load -v firmware-signed.uf2 && picotool reboot
```

This assumes the board is in BOOTSEL. After reboot, confirm the
expected USB identity, applets and access to existing credentials.
`nix run .#flash` signs and flashes in one step. It uses the configured
signing key and stamps `RSK_ROLLBACK`, which defaults to 1. Set it
explicitly for the target board or use the manual flow above.

## Recovery and failure cases

| Situation | Action |
|---|---|
| The new firmware fails to start | Enter BOOTSEL with the board button. Load a signed combined UF2 with the correct layout, a trusted key and a rollback version allowed by the board. |
| The only trusted signing key is lost | Keep the accepted signed artifacts. Creating new images requires that private key, or an available rotation path on a board provisioned for it. See [Signing keys](signing-keys.md). |
| The rollback floor advanced unexpectedly | Read the new floor in BOOTSEL and prepare both signed images at it. OTP keeps the higher floor. |
| The signed wipe image fails to start | Check its SRAM layout, board geometry, trusted signing key and rollback version against [Stage 1b](#1b-sign-and-check-both-images). |
| BOOTSEL refuses a read of page 58 | This is expected after the page is sealed. Read `rsk otp status` from the running firmware for the sealing result. |
| BOOTSEL denies access to the KV partition | This is the [partition table](build.md#the-partition-table) protecting the store. Use the running applets for data management. Use `rsk-wipe` only when you intend to erase all flash. |
| Replacing the board | Provision a fresh signing key and restore each credential type through its recovery path. See [Moving to a new board](anti-rollback.md#moving-to-a-new-board). |

> ⚠️ To **erase all flash**, enter BOOTSEL and run
> `picotool load -v -x rsk-wipe-signed.uf2`. The `-x` selects the
> downloaded SRAM image for execution. Reinstall the eligible signed
> firmware through BOOTSEL after the wipe. The signing fuses, page-58
> keys and rollback floor survive the erase.

## Residual risks

The production policy leaves USB BOOTSEL available for recovery. Its
flash transfers are separate from the ROM's boot checks. A trusted
old image that lacks the partition fence can expose the KV store over
BOOTSEL again, so account for such artifacts in your rollback policy.
See [Flash snapshot rollback](threat-model.md#flash-snapshot-rollback-the-pin-counter-reset).

The firmware executes from QSPI flash. Secure Boot verifies it before
execution, leaving a window for lab hardware that can substitute flash
contents between check and use. RP2350 encrypted boot uses RAM-loaded
images. See the [RP2350 datasheet, §10.1](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
and the [threat model](threat-model.md).

### Completing older debug hardening

`rsk secure-boot status` shows both effective debug-disable flags and
whether all eight hardening copies are complete. If page 1 remains
BOOTSEL-writable, `rsk secure-boot harden` can fill in missing bits and
preserves the bits already set. Stop if readback fails. If page 1 is
already bootloader-read-only and hardening is incomplete, the CLI
cannot finish the write through BOOTSEL. Verify debug denial after a
cold power cycle before accepting a production device.
