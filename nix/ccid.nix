# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# The ccid driver carrying the default RS-Key identity in its reader list. libccid
# binds only the USB ids in readers/supported_readers.txt (generated into the
# bundle's Info.plist at build time), so on the default identity the CCID
# interface is skipped *silently*: FIDO keeps working while OpenPGP, PIV, OATH and
# Yubico-OTP look absent rather than broken
# (docs/linux.md → "The CCID driver's reader list").
#
# This is a local overlay rather than an upstream submission because
# 0x1209:0x0001 is pid.codes' shared *prototype* id, not an allocation to this
# project: listing it in the ccid driver itself would bind every unrelated
# prototype that uses the same id.
{ pkgs }:
let
  # The identity the default build presents (`config.device_release`'s neighbours
  # in firmware/src/main.rs), and the one the udev rules in docs/linux.md match.
  # The Yubico interop build (VIDPID=Yubikey5) needs none of this — 0x1050:0x0407
  # is in the list already.
  vendorId = "0x1209";
  productId = "0x0001";

  # pcsc-lite names a reader from the USB product string, falling back to the
  # driver's friendly name; both spellings have to keep matching the host tools'
  # reader test (`RSK_READER_TOKENS` in tools/rsk/ccid.py).
  friendlyName = "RS-Key";

  # Anchor on pid.codes 0x1209's other tenant so the entry lands with the ids it
  # shares a vendor with, inside the section the generator reads. --replace-fail
  # then turns an upstream restructure into a build failure instead of a driver
  # that silently drops the id again.
  anchor = "# F-Secure Foundry";
  entry = "# ${friendlyName}\n${vendorId}:${productId}:${friendlyName}\n\n${anchor}";
in
pkgs.ccid.overrideAttrs (old: {
  pname = "ccid-rs-key";

  postPatch = (old.postPatch or "") + ''
    substituteInPlace readers/supported_readers.txt --replace-fail '${anchor}' '${entry}'
  '';

  # --replace-fail proves the line reached the source; this proves create_Info_plist.pl
  # picked it up. It reads the whole file and skips comments, so an entry parked in
  # a commented-out section would edit cleanly and still never bind.
  postInstallCheck = ''
    grep -q '<string>${friendlyName}</string>' \
      "$out/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
  '';
})
