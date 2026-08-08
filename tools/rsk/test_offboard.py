# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Offline receipt tests for rsk.offboard (no device, no hidapi).

Run from tools/:  python -m pytest rsk/test_offboard.py

The receipt is the whole point of `rsk offboard`, and the two checks that give it
meaning — the signed head folds from the recorded window, and that window holds
RESET — used to run only in memory and were then thrown away. Pin that --verify
redoes both offline, and that a hand-edited window fails however genuine the
signature block is (the forgery: a checkpoint captured from an INTACT device).

The second half stubs every device call and pins the wipe *order*: the FIDO reset
reaches the CTAP 2.1 §6.6 power-up window (replug), and a failure there still
leaves a receipt naming the applets that were already destroyed.
"""
import json
import sys
import types

# The offline verifier touches no device, but rsk.ctaphid sys.exits at import
# without hidapi and rsk.fido pulls in python-fido2; stub both away first (the
# `from fido2.… import …` lines then raise ImportError, which rsk.fido handles).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rsk import offboard
from rsk.audit import (AUDIT_CHECKPOINT, CKPT_TAG, ENTRY_LEN, EVT_RESET,
                       _fingerprint, _fold)

EVT_BOOT = 0x01
EPOCH = bytes(range(32))
CHALLENGE = bytes(range(16))
SEQ = 414


def _entry(seq, event):
    """One 20-byte journal entry as the firmware lays it out."""
    return (seq.to_bytes(4, "little") + (1234).to_bytes(4, "little")
            + bytes([event, 0]) + bytes(ENTRY_LEN - 10))


def _receipt(entries, *, key=None, head=None, epoch=EPOCH):
    """A receipt signed for real over `head` (default: the honest fold)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    head = _fold(epoch, entries) if head is None else head
    sig = key.sign(CKPT_TAG + head + SEQ.to_bytes(4, "little") + CHALLENGE,
                   ec.ECDSA(hashes.SHA256()))
    pubkey = key.public_key().public_bytes(Encoding.X962,
                                           PublicFormat.UncompressedPoint)
    return {"receipt_version": offboard.RECEIPT_VERSION, "signed": True,
            "reset_attested": True, "notes": [],
            "attested": {"signed_head": head.hex(), "seq": SEQ,
                         "signature": sig.hex(),
                         "attestation_pubkey": pubkey.hex(),
                         "fingerprint": _fingerprint(pubkey),
                         "challenge": CHALLENGE.hex(),
                         "epoch": epoch.hex(), "entries": entries.hex()},
            "host_observations": {"device": "37bebfdca282523b",
                                  "timestamp": "2026-06-13T14:22:09-04:00",
                                  "steps": {"otp": "ok", "fido_reset": "ok"},
                                  "journal_window": offboard._journal_entries(entries)}}


def _wiped():
    """What a real post-wipe window looks like. `authenticatorReset` calls
    `journal::fold_and_scrub` — collapsing the whole window, boot entry included,
    into the epoch — and only THEN appends the RESET, so a completed wipe leaves
    RESET as entry 0. Modelling a leading BOOT here is what made the stale-RESET
    hole invisible: it implied a RESET anywhere in the window was normal."""
    return _entry(413, EVT_RESET)


def _verify(tmp_path, rep, expect_key=None):
    """Through `run`, so the --verify dispatch is pinned with the checks."""
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(rep))
    offboard.run(types.SimpleNamespace(verify=str(path), expect_key=expect_key,
                                       report=None, no_receipt=False))


def test_genuine_receipt_verifies(tmp_path, capsys):
    _verify(tmp_path, _receipt(_wiped()))
    assert "signature and RESET event OK" in capsys.readouterr().out


def test_pinning_accepts_fingerprint_or_full_key(tmp_path, capsys):
    rep = _receipt(_wiped())
    for pin in (rep["attested"]["fingerprint"], rep["attested"]["attestation_pubkey"]):
        _verify(tmp_path, rep, expect_key=pin)
        assert "signed by the enrolled key" in capsys.readouterr().out


def test_pinning_rejects_another_device(tmp_path, capsys):
    with pytest.raises(SystemExit):
        _verify(tmp_path, _receipt(_wiped()), expect_key="0" * 16)
    assert "MISMATCH" in capsys.readouterr().err


def test_fabricated_reset_entry_is_rejected(tmp_path, capsys):
    # The forgery: a genuine signature block captured from an intact device
    # (window with no RESET), with a RESET hand-written into the window.
    rep = _receipt(_entry(412, EVT_BOOT))
    forged = _entry(412, EVT_BOOT) + _entry(413, EVT_RESET)
    rep["attested"]["entries"] = forged.hex()
    rep["host_observations"]["journal_window"] = offboard._journal_entries(forged)
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "TAMPER" in capsys.readouterr().err


def test_decoded_window_alone_cannot_claim_a_reset(tmp_path, capsys):
    # Only `attested.entries` is bound to the signature; a RESET pasted into the
    # human-readable host_observations window must not carry the claim.
    rep = _receipt(_entry(412, EVT_BOOT))
    rep["host_observations"]["journal_window"].append(
        {"seq": 413, "uptime_ms": 0, "event": "RESET", "aux": 0, "detail": ""})
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "does not OPEN with the RESET event" in capsys.readouterr().err


def test_failed_reset_cannot_certify_off_a_previous_runs_event(tmp_path, capsys):
    # Audit run-33. A FIDO reset that fails with the session alive (any status but
    # ERR_NOT_ALLOWED — a missed touch, a timeout) leaves the PREVIOUS window and its
    # RESET untouched, because the firmware folds and appends only on success. The
    # receipt is still written and signed for real, so every cryptographic check
    # passes; only the host's own observation contradicts it. Both the live run and
    # `--verify` must refuse rather than bless a device whose seed is still there.
    rep = _receipt(_wiped())
    rep["host_observations"]["steps"]["fido_reset"] = "failed: 0x27"
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "did not succeed in this run" in capsys.readouterr().err

    # And a receipt that never claimed the wipe cannot be verified into one.
    rep = _receipt(_wiped())
    rep["reset_attested"] = False
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "does not claim reset_attested" in capsys.readouterr().err


def test_signature_over_another_head_is_rejected(tmp_path, capsys):
    entries = _wiped()
    rep = _receipt(entries, head=bytes(32))  # signed, but not over this window
    rep["attested"]["signed_head"] = _fold(EPOCH, entries).hex()
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "SIGNATURE INVALID" in capsys.readouterr().err


def test_v1_receipt_is_refused(tmp_path, capsys):
    # v1 dropped the epoch, so its window can never be bound to the signature.
    rep = _receipt(_wiped())
    rep = {"device": "37bebfdca282523b", "signed": True,
           "journal_window": rep["host_observations"]["journal_window"],
           **{k: v for k, v in rep["attested"].items() if k != "epoch"}}
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    # Assert the version guard's own message. `"receipt" in stderr` also matched the
    # unrelated KeyError this file used to raise with the guard deleted, so the test
    # passed either way (audit run-34 #9).
    assert f"not a v{offboard.RECEIPT_VERSION} receipt" in capsys.readouterr().err


@pytest.mark.parametrize("version", [None, 1, offboard.RECEIPT_VERSION + 1, "2"])
def test_only_the_current_receipt_version_is_accepted(tmp_path, capsys, version):
    # A future version may bind fields this build does not check, so refuse both
    # directions rather than verifying a document under the wrong rules.
    rep = _receipt(_wiped())
    if version is None:
        del rep["receipt_version"]
    else:
        rep["receipt_version"] = version
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert f"not a v{offboard.RECEIPT_VERSION} receipt" in capsys.readouterr().err


def test_unsigned_receipt_is_refused(tmp_path, capsys):
    rep = _receipt(_wiped())
    rep["signed"], rep["notes"] = False, [{"code": offboard.NOTE_NO_DEVK, "detail": "x"}]
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "UNSIGNED" in capsys.readouterr().err


def test_truncated_window_is_refused_not_crashed(tmp_path, capsys):
    rep = _receipt(_wiped())
    rep["attested"]["entries"] = rep["attested"]["entries"][:-4]
    with pytest.raises(SystemExit):
        _verify(tmp_path, rep)
    assert "malformed receipt" in capsys.readouterr().err


def test_empty_window_does_not_certify():
    # Journalling is opt-in and OFF by default, so the post-wipe window is empty
    # and _fold returns the epoch verbatim — the fold check passes vacuously.
    assert _fold(EPOCH, b"") == EPOCH
    assert offboard._window_defect(EPOCH, b"", EPOCH)[0] == offboard.NOTE_NO_RESET_EVENT


def test_window_defect_is_none_on_a_real_wipe():
    entries = _wiped()
    assert offboard._window_defect(EPOCH, entries, _fold(EPOCH, entries)) is None


# --- the wipe run: the reset window, and the receipt on the failure paths ------

class _Handle:
    """A FIDO HID handle: openable, closable, and it remembers which path."""

    def __init__(self):
        self.path = None

    def open_path(self, path):
        self.path = path

    def close(self):
        pass


class _Conn:
    def disconnect(self):
        pass


def _args(tmp_path, **kw):
    base = {"verify": None, "expect_key": None, "no_receipt": False,
            "report": str(tmp_path / "receipt.json")}
    return types.SimpleNamespace(**{**base, **kw})


def _stub_run(monkeypatch, statuses=(0x00,), entries=None):
    """Stub every device call `run` makes. `statuses` is the CTAP status per
    authenticatorReset attempt (the last one repeats). Returns the call log."""
    log = {"vendor": [], "journal": 0, "resets": 0, "binds": []}
    entries = _wiped() if entries is None else entries
    key = ec.generate_private_key(ec.SECP256R1())

    monkeypatch.setattr(offboard, "_serial", lambda: ("cafebabe12345678", _Conn()))
    monkeypatch.setattr(offboard.ctaphid, "find", lambda: {"path": b"hid"})
    monkeypatch.setattr(offboard.ctaphid, "find_all", lambda: [{"path": b"hid"}])
    monkeypatch.setattr(offboard, "_require_journalling", lambda: None)
    monkeypatch.setattr(offboard, "confirm", lambda token: None)
    for step in ("_wipe_otp", "_wipe_oath", "_wipe_piv"):
        monkeypatch.setattr(offboard, step, lambda conn: (True, "ok"))
    monkeypatch.setattr(offboard, "_wipe_openpgp", lambda: (True, "ok"))
    # Record `exclusive` instead of swallowing it into **kw. The old stub absorbed
    # the argument, so the wipe could have bound whichever key answered first and
    # these tests would still have passed (audit run-34 #9).
    def connect_fido(exclusive=False):
        log["binds"].append(exclusive)
        return _Handle(), b"cid0"

    monkeypatch.setattr(offboard, "connect_fido", connect_fido)

    def send_cbor(dev, cid, payload):
        assert payload == bytes([offboard.CTAP_RESET])
        log["resets"] += 1
        return bytes([statuses[min(log["resets"], len(statuses)) - 1]])

    def read_journal(dev, cid, pin):
        log["journal"] += 1
        return 0, len(entries) // ENTRY_LEN, EPOCH, entries

    def vendor(dev, cid, fields):
        log["vendor"].append(fields[1])
        if fields[1] == offboard.ATT_STATE:
            return 0, {}
        if fields[1] == AUDIT_CHECKPOINT:
            head = _fold(EPOCH, entries)
            sig = key.sign(CKPT_TAG + head + SEQ.to_bytes(4, "little") + fields[2][1],
                           ec.ECDSA(hashes.SHA256()))
            pub = key.public_key().public_bytes(Encoding.X962,
                                                PublicFormat.UncompressedPoint)
            return 0, {1: head, 2: SEQ, 3: sig, 4: pub}
        raise AssertionError(f"unexpected vendor subcommand {fields[1]}")

    monkeypatch.setattr(offboard.ctaphid, "send_cbor", send_cbor)
    monkeypatch.setattr(offboard, "read_journal", read_journal)
    monkeypatch.setattr(offboard, "_vendor", vendor)
    return log


def test_reset_accepted_first_try_needs_no_replug(tmp_path, monkeypatch, capsys):
    # A key that shows what the touch approves is exempt from the §6.6 window.
    log = _stub_run(monkeypatch)
    monkeypatch.setattr(offboard, "_await_replug",
                        lambda: pytest.fail("replugged a key that took the reset"))
    offboard.run(_args(tmp_path))
    rep = json.loads((tmp_path / "receipt.json").read_text())
    assert log["resets"] == 1
    # The wipe is irreversible, so every bind it makes must refuse to guess.
    assert log["binds"] == [True]
    assert rep["signed"] and rep["reset_attested"]
    assert "device offboarded" in capsys.readouterr().out


def test_reset_refused_replugs_into_the_power_up_window(tmp_path, monkeypatch, capsys):
    # The blocker: minutes of CCID wipes put the reset outside the §6.6 window, so
    # the key answers 0x30 and only a real power cycle reopens it.
    log = _stub_run(monkeypatch, statuses=(0x30, 0x00))
    replugged = []

    def await_replug():
        replugged.append(True)
        return _Handle(), b"cid1"

    monkeypatch.setattr(offboard, "_await_replug", await_replug)
    offboard.run(_args(tmp_path))
    rep = json.loads((tmp_path / "receipt.json").read_text())
    assert (log["resets"], replugged) == (2, [True])
    assert rep["signed"] and rep["reset_attested"]
    assert rep["host_observations"]["steps"]["fido_reset"] == "ok"
    assert "UNPLUG" in capsys.readouterr().err


def test_abandoned_replug_still_writes_a_receipt(tmp_path, monkeypatch, capsys):
    # Nothing irreversible may end without an artifact: the CCID applets are gone
    # by now, so an operator who walks away still gets the record of that.
    log = _stub_run(monkeypatch, statuses=(0x30,))
    monkeypatch.setattr(offboard, "_await_replug", lambda: (None, None))
    with pytest.raises(SystemExit):
        offboard.run(_args(tmp_path))
    rep = json.loads((tmp_path / "receipt.json").read_text())
    steps = rep["host_observations"]["steps"]
    assert steps["piv"] == "ok" and steps["otp"] == "ok"
    assert "not replugged" in steps["fido_reset"]
    assert rep["signed"] is False and rep["reset_attested"] is False
    assert [n["code"] for n in rep["notes"]] == [offboard.NOTE_NO_SESSION]
    assert log["journal"] == 0 and AUDIT_CHECKPOINT not in log["vendor"]
    assert "re-run rsk offboard" in capsys.readouterr().err


def test_no_receipt_skips_the_journal_the_touch_and_the_file(tmp_path, monkeypatch):
    log = _stub_run(monkeypatch)
    offboard.run(_args(tmp_path, no_receipt=True))
    assert not (tmp_path / "receipt.json").exists()
    assert log["journal"] == 0 and AUDIT_CHECKPOINT not in log["vendor"]


def test_recheck_hint_does_not_pin_the_receipt_against_itself(tmp_path, monkeypatch,
                                                              capsys):
    _stub_run(monkeypatch)
    offboard.run(_args(tmp_path))
    rep = json.loads((tmp_path / "receipt.json").read_text())
    out = capsys.readouterr().out
    assert "--expect-key <ENROLLED-FP>" in out
    assert f"--expect-key {rep['attested']['fingerprint']}" not in out


def _handles(monkeypatch):
    """Record every HID handle `_await_replug` opens — an empty list is the proof
    that it bound nothing."""
    opened = []

    def device():
        opened.append(_Handle())
        return opened[-1]

    monkeypatch.setattr(offboard.ctaphid.hid, "device", device, raising=False)
    monkeypatch.setattr(offboard.ctaphid, "ctaphid_init", lambda dev: b"cid9",
                        raising=False)
    return opened


def _enumerations(monkeypatch, *rounds):
    """Feed `find_all` one result per poll, holding the last one once exhausted."""
    left = list(rounds)
    monkeypatch.setattr(offboard.ctaphid, "find_all",
                        lambda: left.pop(0) if len(left) > 1 else left[0])


def _clock(monkeypatch, step=10.0):
    """A monotonic clock that only moves when the code sleeps, so a timeout path
    resolves in a few polls instead of wall-clock minutes."""
    now = [0.0]

    def sleep(_s):
        now[0] += step

    monkeypatch.setattr(offboard.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(offboard.time, "sleep", sleep)


def test_await_replug_opens_only_the_key_that_came_back(monkeypatch):
    monkeypatch.setattr(offboard.time, "sleep", lambda s: None)
    opened = _handles(monkeypatch)
    _enumerations(monkeypatch, [{"path": b"old"}], [], [{"path": b"new"}])
    dev, cid = offboard._await_replug()
    assert (dev.path, cid) == (b"new", b"cid9")
    assert len(opened) == 1  # the pre-replug handle was never opened


def test_await_replug_will_not_bind_one_of_two_keys(monkeypatch, capsys):
    """Audit run-34 #29. The replug window is the one moment the bus is deliberately
    changing, so a first-match here lands the factory reset on the wrong key. The AST
    inventory in test_refuse_to_guess.py is byte-identical with and without this
    guard — deleting it left all 280 tests green, so the refusal has to be driven
    (audit run-37)."""
    _clock(monkeypatch)
    opened = _handles(monkeypatch)
    _enumerations(monkeypatch, [{"path": b"old"}], [],
                  [{"path": b"a"}, {"path": b"b"}])
    assert offboard._await_replug() == (None, None)
    assert opened == [], "bound a device while two were attached"
    assert "unplug all but the one" in capsys.readouterr().err


def test_await_replug_waits_out_the_second_key_and_binds_the_survivor(monkeypatch):
    # The refusal is a wait, not an abort: the operator unplugs the stray key and
    # the reset still lands, on the one device left.
    _clock(monkeypatch)
    opened = _handles(monkeypatch)
    _enumerations(monkeypatch, [{"path": b"old"}], [],
                  [{"path": b"a"}, {"path": b"b"}], [{"path": b"b"}])
    dev, cid = offboard._await_replug()
    assert (dev.path, cid) == (b"b", b"cid9")
    assert len(opened) == 1


def test_await_replug_aborts_when_the_key_stays_put(monkeypatch):
    monkeypatch.setattr(offboard, "REPLUG_TIMEOUT_S", -1)
    monkeypatch.setattr(offboard.ctaphid, "find_all", lambda: [{"path": b"old"}])
    monkeypatch.setattr(offboard.time, "sleep", lambda s: None)
    assert offboard._await_replug() == (None, None)


def test_await_replug_aborts_when_the_key_never_returns(monkeypatch):
    monkeypatch.setattr(offboard, "REPLUG_TIMEOUT_S", -1)
    monkeypatch.setattr(offboard.ctaphid, "find_all", lambda: [])
    monkeypatch.setattr(offboard.time, "sleep", lambda s: None)
    assert offboard._await_replug() == (None, None)
