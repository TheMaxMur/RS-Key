# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the capture cells that have to name their own device — no hardware.

`gpg` and `pkcs11-tool` take no device selector, so with both keys plugged they
answer for whichever card scdaemon and OpenSC picked. These are the two pure
helpers that pin them to the labelled device. Run:

    nix develop -c python -m pytest tests/interop/test_capture.py -q
"""
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
