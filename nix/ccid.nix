# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# libccid binds only listed USB ids. Keep the allocated identity and the former
# shared test PID in this opt-in overlay until upstream covers the allocation;
# the test PID stays local because it also matches unrelated prototypes.
{ pkgs }:
let
  vendorId = "0x1209";
  productId = "0xF1D2";
  legacyProductId = "0x0001";

  # PC/SC may fall back to this name; keep the host tools' RS-Key reader token.
  friendlyName = "RS-Key";
  legacyFriendlyName = "RS-Key (legacy test PID)";

  # Keep both rows in the section create_Info_plist.pl reads; fail on upstream drift.
  anchor = "# F-Secure Foundry";
  entry = "# ${friendlyName}\n${vendorId}:${productId}:${friendlyName}\n${vendorId}:${legacyProductId}:${legacyFriendlyName}\n\n${anchor}";
in
pkgs.ccid.overrideAttrs (old: {
  pname = "ccid-rs-key";

  postPatch = (old.postPatch or "") + ''
    substituteInPlace readers/supported_readers.txt --replace-fail '${anchor}' '${entry}'
  '';

  # Check the generated parallel arrays, not just whether the source patch landed.
  postInstallCheck = (old.postInstallCheck or "") + ''
    ${pkgs.python3}/bin/python3 - "$out/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist" <<'PY'
    import plistlib
    import sys

    with open(sys.argv[1], "rb") as source:
        info = plistlib.load(source)
    arrays = [info[key] for key in ("ifdVendorID", "ifdProductID", "ifdFriendlyName")]
    assert len({len(a) for a in arrays}) == 1, "ccid reader arrays differ in length"
    readers = set(zip(*arrays))
    for product, name in (("${productId}", "${friendlyName}"),
                          ("${legacyProductId}", "${legacyFriendlyName}")):
        assert ("${vendorId}", product, name) in readers, f"ccid omits {product}: {name}"
    PY
  '';
})
