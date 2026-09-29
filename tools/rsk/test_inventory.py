# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk inventory list` — the org-attestation record and how it renders.

Run from tools/:  python -m pytest rsk/test_inventory.py
ATT_STATE leaves the chain hash out for a chain the device cannot read back
whole, and `list` showed that key as a healthy "installed", with nothing in the
`--json` record but a missing field to tell it apart.
"""
import sys
import types

# rsk.inventory reaches rsk.fido, which tries python-fido2; loading the real
# extension aborts the nix interpreter on macOS 27 (libffi).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk import inventory  # noqa: E402

HASH = bytes(range(32))


class _Dev:
    def open_path(self, path):
        pass

    def close(self):
        pass


def test_list_records_a_key_whose_chain_the_device_cannot_use(monkeypatch):
    hid = inventory.ctaphid.hid
    monkeypatch.setattr(hid, "enumerate", lambda: [
        {"usage_page": inventory.ctaphid.FIDO_USAGE_PAGE, "path": b"/key"}], raising=False)
    monkeypatch.setattr(hid, "device", _Dev, raising=False)
    monkeypatch.setattr(inventory.ctaphid, "ctaphid_init", lambda dev: 1)
    monkeypatch.setattr(inventory.ctaphid, "send_cbor", lambda dev, cid, req: b"\x01")
    monkeypatch.setattr(inventory, "_vendor", lambda dev, cid, fields: (
        (0, {1: True}) if fields == {1: inventory.ATT_STATE} else (1, None)))
    [rec] = inventory._hid_records()
    assert rec["org_attestation"] == {"installed": True, "chain_unusable": True}, rec


@pytest.mark.parametrize("att, line", [
    ({"installed": True, "chain_unusable": False, "chain_sha256": HASH.hex()},
     f"  org attest : installed  chain sha256 {HASH.hex()[:16]}…"),
    ({"installed": True, "chain_unusable": True},
     "  org attest : installed  chain UNUSABLE (see `rsk fido attestation status`)"),
    ({"installed": False, "chain_unusable": False}, "  org attest : not installed"),
])
def test_list_renders_each_org_attestation_state(capsys, att, line):
    inventory._print_record({"transport": "hid", "org_attestation": att})
    assert capsys.readouterr().out.splitlines()[-1] == line
