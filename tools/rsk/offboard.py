# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk offboard — guided decommission of a returned (or lost-and-found) key.

Wipes every applet — OTP slots, OATH, PIV, OpenPGP, FIDO (seed, passkeys, PIN,
soft lock), org attestation — then signs a final audit checkpoint with the
DEVK-derived P-256 attestation key over the post-wipe journal window. The
saved JSON report is a cryptographic receipt: THIS device (fingerprint) was
factory-reset (the signed window contains the RESET event).

The receipt is split along the trust boundary. `attested` holds what the device
signed plus the inputs needed to redo the two checks that give it meaning (the
head folds from the recorded window, and that window holds RESET);
`host_observations` holds the steps, serial and timestamp, which the device
never attests — the journal has no event type for PIV, OATH, OpenPGP or OTP.
`rsk offboard --verify <receipt.json>` redoes all of it offline, no device.

Deliberately PIN-free: every wipe path is reachable without knowing any
credential (block-then-reset for PIV/OpenPGP, the spec's resetting paths for
OATH/OTP, touch-gated reset for FIDO), so a key that comes back with unknown
PINs can still be offboarded. Needs the CCID interface, a typed confirmation,
a replug (CTAP 2.1 §6.6, see `_fido_reset`), and up to three touches.
"""
import json
import os
import sys
import time
from datetime import datetime

from . import ccid, ctaphid, openpgp
from .audit import (AUDIT_CHECKPOINT, EVENTS, ENTRY_LEN, EVT_RESET, _audit_state,
                    _fingerprint, _fold, read_journal, verify_checkpoint,
                    verify_signature)
from .backup import ERR_NOT_ALLOWED, _gated, _vendor, mse_handshake
from .common import confirm, connect_fido, die
from .fido import ATT_CLEAR, ATT_STATE
from .status import RESCUE_AID, rescue_serial

OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
PIV_AID = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]

OTP_CONFIG_SIZE, OTP_ACC_CODE_SIZE = 52, 6
PIV_INS_VERIFY, PIV_INS_RESET_RETRY, PIV_INS_RESET = 0x20, 0x2C, 0xFB
CTAP_RESET = 0x07

# CTAP 2.1 §6.6: a screenless key honors authenticatorReset only this soon after
# power-up (mirrors RESET_WINDOW_MS in crates/rsk-fido/src/consts.rs). How long
# the operator gets for each half of the replug, and the enumeration poll rate.
RESET_WINDOW_S = 10
REPLUG_TIMEOUT_S = 60
REPLUG_POLL_S = 0.2

# v1 was flat and dropped the epoch, so its window could not be re-folded against
# the signed head; --verify refuses it rather than pretend to check it.
RECEIPT_VERSION = 2

# `notes` reason codes — a consumer branches on these, never on the wording.
NOTE_NO_DEVK = "no-devk"
NOTE_CHECKPOINT_FAILED = "checkpoint-failed"
NOTE_HEAD_MISMATCH = "head-mismatch"
NOTE_NO_RESET_EVENT = "no-reset-event"
NOTE_NO_SESSION = "no-session"
NOTE_JOURNAL_UNREAD = "journal-unread"
NOTE_RESET_NOT_THIS_RUN = "reset-not-this-run"


def register(sub):
    p = sub.add_parser("offboard", help="guided full wipe + signed receipt (DESTRUCTIVE)")
    p.add_argument("--report", help="receipt path (default offboard-<serial>-<time>.json)")
    p.add_argument("--verify", metavar="RECEIPT",
                   help="re-check a saved receipt offline (no device) instead of wiping")
    p.add_argument("--expect-key",
                   help="with --verify: 16-hex fingerprint or full hex SEC1 pubkey")
    p.add_argument("--no-receipt", action="store_true",
                   help="wipe only: no journal preflight, no checkpoint touch, no receipt file")
    p.set_defaults(func=run)


def _serial():
    """The device serial (RP2350 OTP chip id) from the rescue applet."""
    conn = ccid.connect(exclusive=True)
    serial = rescue_serial(*ccid.select(conn, RESCUE_AID))
    if serial is None:
        die("rescue applet did not answer — cannot identify the device")
    return serial, conn


def _wipe_otp(conn):
    """Delete slots 1-4 (an all-zero config is the protocol's delete).
    Returns (ok, detail) — detail is the receipt's step string."""
    _, s1, s2 = ccid.select(conn, OTP_AID)
    if (s1, s2) != ccid.SW_OK:
        return True, "applet absent"
    blocked = []
    for slot in range(1, 5):
        body = [0] * (OTP_CONFIG_SIZE + OTP_ACC_CODE_SIZE)
        _, s1, s2 = ccid.transmit(
            conn, [0x00, 0x01, 0x01, slot - 1, len(body)] + body)
        if (s1, s2) == (0x69, 0x82):
            blocked.append(slot)  # protected by an access code we don't have
        elif (s1, s2) != ccid.SW_OK:
            return False, f"slot {slot}: SW {s1:02X}{s2:02X}"
    if blocked:
        return False, f"slots {blocked} protected by access codes — NOT wiped"
    return True, "ok"


def _wipe_oath(conn):
    _, s1, s2 = ccid.select(conn, OATH_AID)
    if (s1, s2) != ccid.SW_OK:
        return True, "applet absent"
    _, s1, s2 = ccid.transmit(conn, [0x00, 0x04, 0xDE, 0xAD])
    ok = (s1, s2) == ccid.SW_OK
    return ok, "ok" if ok else f"RESET: SW {s1:02X}{s2:02X}"


def _wipe_piv(conn):
    """Block PIN and PUK (two distinct wrong values, so even a matching first
    guess cannot keep the retry counter alive), then factory RESET."""
    _, s1, s2 = ccid.select(conn, PIV_AID)
    if (s1, s2) != ccid.SW_OK:
        return True, "applet absent"
    for bad in (b"00000000", b"11111111"):
        for _ in range(8):
            ccid.transmit(conn, [0x00, PIV_INS_VERIFY, 0x00, 0x80, 8] + list(bad))
    for bad in (b"00000000" * 2, b"11111111" * 2):
        for _ in range(8):
            ccid.transmit(conn, [0x00, PIV_INS_RESET_RETRY, 0x00, 0x80, 16] + list(bad))
    _, s1, s2 = ccid.transmit(conn, [0x00, PIV_INS_RESET, 0x00, 0x00])
    ok = (s1, s2) == ccid.SW_OK
    return ok, "ok" if ok else f"RESET: SW {s1:02X}{s2:02X}"


def _wipe_openpgp():
    try:
        openpgp.reset(None)
        return True, "ok"
    except SystemExit as e:
        return False, f"failed: {e}"


def _await_replug():
    """Block until the FIDO device disappears and comes back, then open a fresh
    CTAPHID session on it. Returns (dev, cid), or (None, None) if either half
    times out — the operator walked away, and the caller still owes a receipt."""
    deadline = time.monotonic() + REPLUG_TIMEOUT_S
    while ctaphid.find_all():
        if time.monotonic() > deadline:
            return None, None
        time.sleep(REPLUG_POLL_S)
    print("unplugged — plug it back in…", file=sys.stderr)
    deadline = time.monotonic() + REPLUG_TIMEOUT_S
    warned = False
    while time.monotonic() < deadline:
        found = ctaphid.find_all()
        # The operator was told this must be the only key attached; enforce it
        # rather than binding the first match. This is the one moment the bus is
        # deliberately changing, so a second key appearing here is exactly when a
        # first-match would land the reset on the wrong device (run-34 #29).
        if len(found) > 1:
            if not warned:
                print(f"{len(found)} FIDO devices attached — unplug all but the one "
                      "being offboarded; waiting…", file=sys.stderr)
                warned = True
        elif found:
            dev = ctaphid.hid.device()
            try:
                dev.open_path(found[0]["path"])
                return dev, ctaphid.ctaphid_init(dev)
            except OSError:
                dev.close()  # enumerated, HID interface not ready yet
        time.sleep(REPLUG_POLL_S)
    return None, None


def _fido_reset(dev, cid):
    """authenticatorReset, replugging into the power-up window when the device
    refuses: CTAP 2.1 §6.6 accepts a reset only within RESET_WINDOW_S of power-up
    on a key with no screen, and a warm reboot does not reopen it. A key that
    shows what the touch approves is exempt, so it never reaches the prompt.

    Returns (dev, cid, ok, detail) — dev is None when the key never came back."""
    print("\nFIDO factory reset — touch the device (BOOTSEL)…", file=sys.stderr)
    st = ctaphid.send_cbor(dev, cid, bytes([CTAP_RESET]))[0]
    if st == ERR_NOT_ALLOWED:
        dev.close()
        print(f"\nthe key refuses a reset this long after power-up (CTAP 2.1 §6.6):"
              f"\nUNPLUG it now and plug it straight back in — it must be the only"
              f"\nFIDO key attached, and the reset lands within {RESET_WINDOW_S}s of"
              f"\npower-up. Waiting up to {REPLUG_TIMEOUT_S}s…", file=sys.stderr)
        dev, cid = _await_replug()
        if dev is None:
            return None, None, False, "aborted: the key was not replugged in time"
        print("FIDO factory reset — touch the device (BOOTSEL)…", file=sys.stderr)
        st = ctaphid.send_cbor(dev, cid, bytes([CTAP_RESET]))[0]
    return dev, cid, st == 0, "ok" if st == 0 else f"failed: {st:#x}"


def _journal_entries(entries):
    out = []
    for off in range(0, len(entries), ENTRY_LEN):
        e = entries[off:off + ENTRY_LEN]
        out.append({"seq": int.from_bytes(e[0:4], "little"),
                    "uptime_ms": int.from_bytes(e[4:8], "little"),
                    "event": EVENTS.get(e[8], f"0x{e[8]:02x}"),
                    "aux": e[9], "detail": e[10:18].hex()})
    return out


def _window_defect(epoch, entries, head, steps=None):
    """Why a signed window fails to certify a wipe, as (code, detail), or None
    when it certifies: the signed head must fold from the recorded window, that
    window must OPEN with the RESET event, and — when the host's own observations
    are available — this run must be the one that produced it.

    The position matters. A successful authenticatorReset folds the window away and
    *then* appends RESET, so a genuine one is always entry 0. Accepting a RESET
    anywhere let a run whose reset FAILED certify itself off a previous run's event:
    the failed reset leaves the old window (and its RESET) untouched, so every
    cryptographic check passed over a device whose seed and passkeys were still
    there. Neither test binds the event to *this* invocation on its own, so the
    host's `fido_reset` step is cross-checked too (audit run-33)."""
    if head != _fold(epoch, entries):
        return NOTE_HEAD_MISMATCH, "signed head differs from the recorded window — TAMPER"
    if len(entries) < ENTRY_LEN or entries[8] != EVT_RESET:
        return NOTE_NO_RESET_EVENT, ("signed window does not OPEN with the RESET event — "
                                     "it does not record a reset completed in this window")
    if steps is not None and steps.get("fido_reset") != "ok":
        return NOTE_RESET_NOT_THIS_RUN, (
            f"the FIDO reset did not succeed in this run (fido_reset="
            f"{steps.get('fido_reset')!r}) — the RESET in the window is a previous one")
    return None


def _require_journalling():
    """Refuse before the wipe when the journal is not recording: journalling is
    opt-in and OFF by default, and after the wipe there is no way to produce the
    RESET event the receipt certifies — and nothing to retry."""
    dev, cid = connect_fido(exclusive=True)
    try:
        on = _audit_state(dev, cid)
    finally:
        dev.close()
    if not on:
        die("audit journalling is OFF on this device, so the wipe cannot be "
            "attested — enable it first (rsk audit enable), or re-run with "
            "--no-receipt to wipe without a signed receipt")


def _receipt(dev, cid, serial, steps):
    """Build the receipt: the journal window (which holds the RESET event), then a
    checkpoint signing that window's head against a fresh challenge. Returns
    (report, defect) — the defect is why it fails to certify the wipe, or None.

    A dead session still yields a report: the CCID applets are already wiped, and
    an irreversible step must never end without an artifact."""
    epoch = entries = challenge = b""
    st, m = None, None
    session_defect = None
    if dev is not None:
        # The wipe already happened; a touch timeout or a malformed AUDIT_READ /
        # checkpoint must degrade to a note in a written receipt, never abort before
        # open() below (audit run-30). read_journal die()s on a missed touch — exactly
        # the post-reset state (no PIN → touch-gated) — and _vendor can raise on a
        # dying device.
        try:
            _, _, epoch, entries = read_journal(dev, cid, None)
            challenge = os.urandom(16)
            print("signing the wipe receipt — touch the device (BOOTSEL)…", file=sys.stderr)
            st, m = _vendor(dev, cid,
                            _gated(AUDIT_CHECKPOINT, {1: challenge}, dev, cid, None))
        except SystemExit as e:
            session_defect = (NOTE_JOURNAL_UNREAD,
                              f"could not read the journal to certify the wipe: {e}")
        except Exception as e:  # noqa: BLE001 — a hostile/dying device must not lose the receipt
            session_defect = (NOTE_JOURNAL_UNREAD,
                              f"malformed device response while certifying the wipe: {e!r}")
    report = {"receipt_version": RECEIPT_VERSION, "signed": False,
              "reset_attested": False, "notes": [],
              "host_observations": {
                  "device": serial,
                  "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                  "steps": steps,
                  "journal_window": _journal_entries(entries)}}
    if dev is None:
        defect = (NOTE_NO_SESSION,
                  "no FIDO session to sign with — receipt is UNSIGNED")
    elif session_defect is not None:
        defect = session_defect
    elif st == ERR_NOT_ALLOWED:
        defect = (NOTE_NO_DEVK, "no OTP DEVK provisioned — receipt is UNSIGNED")
    elif st != 0:
        defect = (NOTE_CHECKPOINT_FAILED,
                  f"checkpoint failed ({st:#x}) — receipt is UNSIGNED")
    else:
        # The device is untrusted: validate every field before use so a malformed
        # checkpoint fails closed with a note instead of aborting the whole receipt.
        try:
            head, seq, sig, pubkey = verify_checkpoint(
                m, challenge, "do not trust this device",
                "receipt SIGNATURE INVALID — do not trust this device")
        except SystemExit as e:
            defect = (NOTE_CHECKPOINT_FAILED,
                      f"checkpoint rejected ({e}) — receipt is UNSIGNED")
        except Exception as e:  # noqa: BLE001 — a None/malformed checkpoint must not lose the receipt
            # verify_checkpoint indexes the response map (`1 in m` etc.) and calls
            # vk.verify(sig): a device answering st=0 with an empty/malformed body
            # (m is None, or a non-bytes sig) raises TypeError, not SystemExit, which
            # would otherwise abort before the receipt is written.
            defect = (NOTE_CHECKPOINT_FAILED,
                      f"malformed checkpoint response ({e!r}) — receipt is UNSIGNED")
        else:
            # epoch and entries are what bind the signature to the window shown
            # above; persist them or no later --verify can redo the fold and the
            # RESET scan, and the receipt asserts a wipe nothing can re-check.
            report["signed"] = True
            report["attested"] = {"signed_head": head.hex(), "seq": seq,
                                  "signature": sig.hex(),
                                  "attestation_pubkey": pubkey.hex(),
                                  "fingerprint": _fingerprint(pubkey),
                                  "challenge": challenge.hex(),
                                  "epoch": epoch.hex(), "entries": entries.hex()}
            defect = _window_defect(epoch, entries, head, steps)
            report["reset_attested"] = defect is None
    if defect:
        # Recorded, never fatal: the wipe already happened, so losing the file
        # would leave the operator with nothing at all.
        report["notes"].append({"code": defect[0], "detail": defect[1]})
        print(f"warning: {defect[1]}", file=sys.stderr)
    return report, defect


def run(args):
    if args.verify:
        return verify(args)

    serial, conn = _serial()
    # Resolve the FIDO half exclusively HERE, before anything is destroyed. The
    # only other exclusive bind is inside `_require_journalling`, which
    # `--no-receipt` skips — so that flavour used to wipe OTP, OATH, PIV and
    # OpenPGP and only then discover it could not tell the keys apart (run-34 #29).
    hid_found = ctaphid.find_all()
    if not hid_found:
        die("no FIDO HID device — offboard needs both interfaces")
    if len(hid_found) > 1:
        die(f"{len(hid_found)} FIDO HID devices attached — offboard destroys a "
            "specific key, so it must not guess; unplug the others and retry")
    hid_info = hid_found[0]
    if not args.no_receipt:
        _require_journalling()

    print(f"device serial : {serial}")
    print("\nThis wipes EVERYTHING on the key: OTP slots, OATH credentials, PIV")
    print("keys, OpenPGP keys, the FIDO seed and all passkeys, PINs, the org")
    print("attestation — and finishes with a signed wipe receipt.")
    print("A screenless key will ask to be replugged before the FIDO reset.")
    confirm(f"OFFBOARD {serial}")

    steps, failed = {}, {}

    def record(name, ok, detail):
        steps[name] = detail
        if not ok:
            failed[name] = detail

    print("\nwiping OTP slots…", end=" ")
    record("otp", *_wipe_otp(conn))
    print(steps["otp"])
    print("wiping OATH…", end=" ")
    record("oath", *_wipe_oath(conn))
    print(steps["oath"])
    print("wiping PIV (block PIN+PUK, then factory reset)…", end=" ")
    record("piv", *_wipe_piv(conn))
    print(steps["piv"])
    conn.disconnect()  # openpgp.reset opens its own connection
    print("wiping OpenPGP…")
    record("openpgp", *_wipe_openpgp())

    # A failure here is recorded, not fatal: the CCID applets are already wiped,
    # so the run must still reach the receipt that says what was destroyed.
    dev, cid = connect_fido(exclusive=True)
    dev, cid, ok, detail = _fido_reset(dev, cid)
    record("fido_reset", ok, detail)

    if dev is None:
        record("org_attestation", False, "not attempted — no FIDO session")
    else:
        st, m = _vendor(dev, cid, {1: ATT_STATE})
        if st == 0 and m.get(1):
            mse_handshake(dev, cid)
            print("removing the org attestation — touch the device (BOOTSEL)…", file=sys.stderr)
            st, _ = _vendor(dev, cid, _gated(ATT_CLEAR, None, dev, cid, None))
            record("org_attestation", st == 0,
                   "cleared" if st == 0 else f"clear failed: {st:#x}")
        else:
            steps["org_attestation"] = "none"

    report, defect, path = None, None, None
    if args.no_receipt:
        print("\nno receipt (--no-receipt) — this wipe leaves no signed record")
    else:
        report, defect = _receipt(dev, cid, serial, steps)
        path = args.report or f"offboard-{serial}-{datetime.now():%Y%m%d-%H%M%S}.json"
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nreceipt : {path}")
    if report and report["signed"]:
        fp = report["attested"]["fingerprint"]
        print(f"identity: fingerprint {fp} — match it against your inventory record")
        print(f"re-check: rsk offboard --verify {path} --expect-key <ENROLLED-FP>")
        print("          <ENROLLED-FP> is the fingerprint recorded when the key was "
              "enrolled;\n          pinning the one above checks the receipt against "
              "itself and proves nothing")
    if failed:
        die(f"offboard finished WITH FAILURES: {failed} — "
            f"{'receipt saved; ' if path else ''}re-run rsk offboard "
            "(every wipe step is idempotent)")
    if report and report["signed"] and not report["reset_attested"]:
        die(f"wipe NOT attested ({defect[0]}) — receipt saved")
    print("device offboarded ✓ — all applets at factory state")


def verify(args):
    """Offline re-check of a saved receipt: redo the fold binding and the RESET
    scan `run` did in memory, then the signature. No device, no network."""
    try:
        with open(args.verify) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        die(f"cannot read the receipt: {e}")
    if not isinstance(rep, dict) or rep.get("receipt_version") != RECEIPT_VERSION:
        die(f"not a v{RECEIPT_VERSION} receipt — earlier receipts do not record the "
            "epoch, so their window cannot be bound to the signature")
    if not rep.get("signed"):
        # Never echo the file's own strings back: a receipt is untrusted input,
        # and `notes` would carry a forger's terminal escapes to the auditor.
        die("receipt is UNSIGNED — nothing to verify; read its `notes` for why")
    a = rep.get("attested") or {}
    try:
        head = bytes.fromhex(a["signed_head"])
        epoch = bytes.fromhex(a["epoch"])
        entries = bytes.fromhex(a["entries"])
        challenge = bytes.fromhex(a["challenge"])
        sig = bytes.fromhex(a["signature"])
        pubkey = bytes.fromhex(a["attestation_pubkey"])
        seq = int(a["seq"])
    except (KeyError, TypeError, ValueError) as e:
        die(f"malformed receipt: {e}")
    if len(entries) % ENTRY_LEN:
        die("malformed receipt: the recorded window is not whole journal entries")

    verify_signature(head, seq, sig, pubkey, challenge,
                     "do not trust this receipt",
                     "receipt SIGNATURE INVALID — do not trust this receipt")
    # Cross-check the receipt's own host observations. `verify` used to read only
    # the `attested` block, so a receipt whose recorded `fido_reset` said "failed"
    # still printed the clean verdict — every cryptographic check passing over a
    # contradiction sitting in the same file (audit run-33).
    steps = rep.get("host_observations", {}).get("steps")
    # A legitimate v2 receipt ALWAYS writes this (see `_receipt`), so its absence
    # means the file was edited or truncated — which is exactly what the freshness
    # cross-check exists to catch. Passing None here would skip that check instead,
    # letting a `del host_observations.steps` launder a failed reset into a clean
    # verdict against the genuine enrolled key, signature untouched (run-34).
    if not isinstance(steps, dict):
        die("malformed receipt: host_observations.steps is missing — "
            "this receipt cannot be checked against the run that produced it")
    defect = _window_defect(epoch, entries, head, steps)
    if defect:
        die(f"{defect[1]} — this receipt does not certify a wipe")
    if not rep.get("reset_attested"):
        die("the receipt does not claim reset_attested — it does not certify a wipe")

    fp = _fingerprint(pubkey)
    print(f"fingerprint : {fp}")
    print(f"att key     : {pubkey.hex()}")
    if args.expect_key:
        if args.expect_key.lower().strip() not in (fp, pubkey.hex()):
            die("attestation key MISMATCH — this is NOT the enrolled device")
        print("verdict     : FIDO applet reset, signed by the enrolled key ✓")
    else:
        print("verdict     : signature and RESET event OK — the key is NOT "
              "pinned, so this does not prove which device it was")
    print("note        : the OTP/OATH/PIV/OpenPGP steps are host observations, "
          "never attested by the device")
