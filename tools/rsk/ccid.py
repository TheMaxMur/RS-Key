# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PC/SC (CCID) transport helpers shared by the rsk subcommands."""
import sys

try:
    from smartcard.System import readers
except ImportError:
    readers = None

VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]

# ISO 7816-4 status words, as the (sw1, sw2) tuple transmit() returns.
SW_OK = (0x90, 0x00)
SW_COND_NOT_SATISFIED = (0x69, 0x85)


def _require():
    if readers is None:
        sys.exit("missing dependency: pyscard (run `rsk` from `nix develop`)")


# Reader-name tokens that mark our device: the default build's product string
# carries "RS-Key"; the opt-in Yubico interop flavor carries "RSK". Neither
# appears in a genuine YubiKey's reader name, so we never grab the wrong device.
RSK_READER_TOKENS = ("RS-Key", "RSK")


def _is_rsk(name):
    return any(tok in name for tok in RSK_READER_TOKENS)


def find_reader(substr=None):
    _require()
    rs = readers()
    if not rs:
        sys.exit("no PC/SC readers — is the device flashed and the CCID driver bound?")
    if substr is not None:
        return next((r for r in rs if substr in str(r)), rs[0])
    # No rs[0] fallback: a destructive command (e.g. `rsk openpgp reset`) must never
    # land on someone else's card just because the RS-Key's CCID interface is
    # unplugged, disabled, or rebranded via `rsk hw --product` (audit run-30).
    hit = next((r for r in rs if _is_rsk(str(r))), None)
    if hit is None:
        sys.exit(
            "no RS-Key PC/SC reader found — check the device is plugged in, CCID is "
            f"enabled, and the product string still matches. Readers seen: {[str(r) for r in rs]}"
        )
    return hit


def connect(substr=None):
    conn = find_reader(substr).createConnection()
    conn.connect()
    return conn


def transmit(conn, data):
    d, sw1, sw2 = conn.transmit(list(data))
    return bytes(d), sw1, sw2


def select(conn, aid):
    return transmit(conn, [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00])


def reboot(conn=None, bootsel=True):
    """SELECT the vendor AID then the reboot command (P1=1 BOOTSEL, P1=0 app).

    Reboot-to-BOOTSEL now requires an on-device confirmation (the firmware gates
    it against a hostile host); a plain app restart (P1=0) stays ungated. Returns
    the (sw1, sw2) status word, or None when the device dropped off the bus before
    replying (the reboot is already under way). On a confirmed reboot the device
    resets after flushing SW_OK; on a decline it returns 6985 and stays put."""
    if conn is None:
        conn = connect()
    select(conn, VENDOR_AID)
    try:
        _, s1, s2 = transmit(conn, [0x00, 0x1F, 0x01 if bootsel else 0x00, 0x00, 0x00])
        return (s1, s2)
    except Exception:
        return None
