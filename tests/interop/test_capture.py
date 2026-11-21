# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the capture helpers that name a device — no hardware.

`gpg` and `pkcs11-tool` take no device selector, so with both keys plugged they
answer for whichever card scdaemon and OpenSC picked. Two pure helpers pin them to
the labelled device, and `_fw_from` labels the snapshot with its firmware. Run:

    nix develop -c python -m pytest tests/interop/test_capture.py -q
"""
import json
import os

import capture

SLOTS = """\
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID
  token label        : yk-9a-rsa2048
  serial num         : beb916b643441efd
Slot 1 (0x4): Yubico YubiKey RSK OTP+FIDO+CCID
  token label        : PIV_II
  serial num         : 033de4f1a775b555
"""

CARDS = """\
0* D2760001240100000006475377740000
1  D2760001240100000006373650930000
"""


# ── _opensc_slot_block ───────────────────────────────────────────────────────

def test_slot_block_keeps_only_the_named_reader():
    block = capture._opensc_slot_block(SLOTS, "Yubico YubiKey OTP+FIDO+CCID")
    assert "yk-9a-rsa2048" in block
    assert "PIV_II" not in block, "the other key's token metadata must not leak in"


def test_slot_block_picks_the_rsk_reader_by_its_marker():
    block = capture._opensc_slot_block(SLOTS, "Yubico YubiKey RSK OTP+FIDO+CCID")
    assert "033de4f1a775b555" in block
    assert "beb916b643441efd" not in block


def test_slot_block_header_drops_the_enumeration_index():
    # `Slot 1 (0x4)` would slug to a key naming the host's probe order, so the two
    # snapshots would compare fields that don't exist on each other.
    block = capture._opensc_slot_block(SLOTS, "Yubico YubiKey RSK OTP+FIDO+CCID")
    assert block.splitlines()[0] == "Slot description: Yubico YubiKey RSK OTP+FIDO+CCID"


def test_slot_block_is_empty_for_an_absent_reader():
    assert capture._opensc_slot_block(SLOTS, "Some Other Reader") == ""


# ── _openpgp_aid ─────────────────────────────────────────────────────────────

def _fake_run(monkeypatch, rc, out):
    monkeypatch.setattr(capture, "run", lambda *a, **k: (rc, out))


def test_aid_matches_the_serial_in_the_aid_body(monkeypatch):
    _fake_run(monkeypatch, 0, CARDS)
    assert capture._openpgp_aid("gpg-card", "37365093") == "D2760001240100000006373650930000"
    assert capture._openpgp_aid("gpg-card", "47537774") == "D2760001240100000006475377740000"


def test_aid_is_none_when_that_card_is_not_inserted(monkeypatch):
    _fake_run(monkeypatch, 0, CARDS)
    assert capture._openpgp_aid("gpg-card", "12345678") is None


def test_aid_ignores_a_serial_that_only_appears_outside_the_serial_field(monkeypatch):
    # The manufacturer and trailing bytes must not be read as part of the serial.
    _fake_run(monkeypatch, 0, "0* D2760001240100000006373650930000\n")
    assert capture._openpgp_aid("gpg-card", "00000006") is None


def test_aid_is_none_when_gpg_card_fails(monkeypatch):
    _fake_run(monkeypatch, 2, "gpg-card: no card")
    assert capture._openpgp_aid("gpg-card", "37365093") is None


# ── _fw_from ─────────────────────────────────────────────────────────────────

def test_fw_label_reads_the_version_ykman_info_prints():
    # The ykman cell keeps its own namespace; `mgmt.*` is the raw TLV's.
    parsed = capture.nz.kv_lines("Firmware version: 5.8.0\n", "ykman.info")
    assert capture._fw_from({"ykman_info": {"parsed": parsed}}) == "5.8.0"


def test_is_rsk_knows_both_identities_and_never_a_yubikey():
    # The default identity and the emulator are named `RS-Key …`; only the
    # VIDPID=Yubikey5 build carries `RSK`. Knowing the one marker left both of
    # them unrecognised, so a capture labelled `rsk` found no device at all.
    assert capture._is_rsk("RS-Key Security Key (emulator) 00 00")
    assert capture._is_rsk("YubiKey RSK OTP+FIDO+CCID")
    assert not capture._is_rsk("Yubico YubiKey OTP+FIDO+CCID")


# ── the frozen baseline ──────────────────────────────────────────────────────

def test_baseline_strips_serials_and_keeps_only_presence_of_encrypted_members():
    cells = {
        "mgmt_tlv": capture.cell(parsed={"mgmt.serial": 12345678, "mgmt.version": "5.8.0"},
                                 raw="0302023b"),
        "fido_getinfo": capture.cell(parsed={"fido.getinfo.key_0x19": "f06c25ef",
                                             "fido.getinfo.minPINLength": 4}),
        "usb_descriptors": capture.cell(parsed={"usb.serialNumber": "abc",
                                                "usb.idVendor": "0x1050"}),
    }
    flat = {k: v for c in capture.strip_for_baseline(cells).values()
            for k, v in c["parsed"].items()}
    assert "mgmt.serial" not in flat and "usb.serialNumber" not in flat
    assert flat["fido.getinfo.key_0x19"] == "<present>"
    assert "fido.getinfo.key_0x1e" not in flat, "presence must not be invented"
    assert flat["mgmt.version"] == "5.8.0" and flat["fido.getinfo.minPINLength"] == 4
    assert all(c["raw"] == "" for c in cells.values())


def test_the_frozen_baseline_holds_only_what_a_baseline_may():
    # A re-freeze without `--baseline` would commit the serial, OATH account names
    # and the PKCS#11 dump, and gitleaks knows none of them as a secret.
    path = os.path.join(os.path.dirname(__file__), "baseline", "yubikey-5.8.0.json")
    with open(path) as f:
        snap = json.load(f)
    assert snap["meta"]["baseline"] is True
    assert set(snap["cells"]) == {"usb_descriptors", "fido_getinfo", "ccid_atr", "mgmt_tlv"}
    for name, c in snap["cells"].items():
        assert c["status"] == "ok" and c["raw"] == "", name
        for key in capture.BASELINE_DROP:
            assert key not in c["parsed"], f"{name} keeps {key}"
        for key in capture.BASELINE_PRESENCE:
            assert c["parsed"].get(key, "<present>") == "<present>", f"{name} keeps {key}'s bytes"
