# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for rsk.audit (no device).

Run from tools/:  python -m pytest rsk/test_audit.py
The device coalesces a run of config writes into one ring entry, so its detail
carries the run (`repeats(2 LE) ‖ targets(1)`) rather than eight zero bytes.
Decoding that is the only place the host interprets an entry's detail — pin it.

The second half drives `rsk audit verify`. Its two verdict-changing branches —
the signed head disagreeing with the exported window (TAMPER) and `--expect-key`
disagreeing with the signer (MISMATCH) — could both be deleted with the suite
green, while their `offboard --verify` twins were covered (audit run-34 #9).
"""
import sys
import types

# rsk.ctaphid sys.exits at import without hidapi; nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (Encoding,  # noqa: E402
                                                          PublicFormat)

from rsk import audit  # noqa: E402


def _entry(event, aux=0, detail=b"", folded=0):
    e = bytearray(audit.ENTRY_LEN)
    e[8] = event
    e[9] = aux
    e[10:10 + len(detail)] = detail
    e[audit.RUN_REPEATS_AT:] = folded.to_bytes(2, "little")
    return bytes(e)


def test_detail_of_a_single_config_write():
    e = _entry(audit.EVT_CONFIG_WRITE, aux=2, detail=bytes([0, 0, 0b100]))
    assert audit._detail(e) == "1× write (led)"


def test_detail_counts_a_coalesced_run_over_several_targets():
    # 299 further writes folded in, touching both the phy and the LED record.
    e = _entry(audit.EVT_CONFIG_WRITE, aux=1, detail=bytes([0x2B, 0x01, 0b110]))
    assert audit._detail(e) == "300× write (phy+led)"


def test_detail_of_other_events_stays_raw_hex():
    e = _entry(audit.EVT_RESET, detail=bytes([0xAA, 0xBB]))
    assert audit._detail(e) == "aabb000000000000"


def test_detail_shows_a_coalesced_run_of_a_non_config_event():
    # The silent (`up:false`) assertion and the don't-enforce U2F authenticate are
    # ungated, so the device folds a run of either into one entry — keeping the FIRST
    # occurrence's rpIdHash and counting the rest in bytes 18-19. Rendering only the
    # detail showed 4000 silent probes as one.
    e = _entry(0x03, detail=bytes([0xAA] * 8), folded=3999)
    assert audit._detail(e) == "aaaaaaaaaaaaaaaa ×4000"


def test_a_zero_repeat_field_is_a_single_occurrence():
    # Bytes 18-19 were reserved and always zero before the device coalesced these,
    # so an older build's entries must still read as one event, not "×1".
    assert audit._detail(_entry(0x03, detail=bytes([0xAA] * 8))) == "aaaaaaaaaaaaaaaa"


# --- `rsk audit verify`: the chain and the identity ---------------------------

EPOCH = bytes(32)
ENTRIES = _entry(audit.EVT_RESET) + _entry(0x01)
DEVK = ec.generate_private_key(ec.SECP256R1())
PUBKEY = DEVK.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _drive(monkeypatch, *, signs_head=None):
    """Stub the device side of `cmd_verify`. The checkpoint is signed for real, so
    a `signs_head` other than the window's own fold is a genuine signature over the
    wrong head — which is the shape a swapped-in journal has."""
    head = signs_head if signs_head is not None else audit._fold(EPOCH, ENTRIES)
    seq = len(ENTRIES) // audit.ENTRY_LEN

    def vendor(dev, cid, fields):
        challenge = fields[2][1]
        sig = DEVK.sign(audit.CKPT_TAG + head + seq.to_bytes(4, "little") + challenge,
                        ec.ECDSA(hashes.SHA256()))
        return 0, {1: head, 2: seq, 3: sig, 4: PUBKEY}

    monkeypatch.setattr(audit, "connect_fido", lambda exclusive=False: (object(), b"cid"))
    monkeypatch.setattr(audit, "device_has_pin", lambda dev, cid: False)
    monkeypatch.setattr(audit, "read_journal", lambda dev, cid, pin: (0, seq, EPOCH, ENTRIES))
    monkeypatch.setattr(audit, "_gated", lambda sc, para, dev, cid, pin: {1: sc, 2: para})
    monkeypatch.setattr(audit, "_vendor", vendor)


def _args(expect_key=None):
    return types.SimpleNamespace(pin=None, expect_key=expect_key)


def test_verify_accepts_a_consistent_journal(monkeypatch, capsys):
    _drive(monkeypatch)
    audit.cmd_verify(_args())
    out = capsys.readouterr().out
    assert "chain   : OK" in out and "NOT pinned" in out


def test_verify_reports_tamper_when_the_signed_head_is_not_the_window(monkeypatch, capsys):
    # Every cryptographic check passes; only the fold disagrees. That is the whole
    # point of the chain, so it must be fatal rather than a printed footnote.
    _drive(monkeypatch, signs_head=bytes(32))
    with pytest.raises(SystemExit):
        audit.cmd_verify(_args())
    assert "TAMPER" in capsys.readouterr().err


def test_verify_refuses_a_key_that_is_not_the_pinned_one(monkeypatch, capsys):
    _drive(monkeypatch)
    with pytest.raises(SystemExit):
        audit.cmd_verify(_args(expect_key="0" * 16))
    assert "MISMATCH" in capsys.readouterr().err


@pytest.mark.parametrize("form", ["fingerprint", "pubkey", "padded-uppercase"])
def test_verify_accepts_the_pinned_key_in_either_form(monkeypatch, capsys, form):
    fp = audit._fingerprint(PUBKEY)
    expect = {"fingerprint": fp, "pubkey": PUBKEY.hex(),
              "padded-uppercase": f"  {fp.upper()}  "}[form]
    _drive(monkeypatch)
    audit.cmd_verify(_args(expect_key=expect))
    assert "journal authentic" in capsys.readouterr().out
