# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk fido — ykman-free FIDO2 management over the HID interface (needs python-fido2).

set-pin:       set or change the FIDO2 clientPIN (no touch).
list-passkeys: list discoverable credentials via credentialManagement (needs PIN).
attestation:   org attestation key/chain, and who gets vendor-facilitated EA.
"""
import sys
from getpass import getpass

from .common import add_pin_arg, device_has_pin, die, die_ctap_pin_error, resolve_pin, sanitize

#: Largest attestation chain the device stores — `rsk_fido::cert::ATT_CHAIN_MAX`,
#: i.e. `rsk_fs::MAX_VALUE_BYTES - 1 - 2 * ATT_CHAIN_MAX_CERTS` = 4078 − 1 − 8. It
#: used to be a flat 2048; when the ceiling moved to what a flash record actually
#: holds, this pre-flight check kept the old number, so a chain in the 11-byte gap
#: passed here and was refused by the device as a bare CTAP error.
ATT_CHAIN_MAX = 4069

#: authenticatorConfig vendorPrototype id for the vendor-facilitated (type 1)
#: enterprise-attestation RP list — `rsk_fido::consts::CONFIG_EA_RPIDS`.
CONFIG_EA_RPIDS = 0x0E6841934E719BE7
#: `rsk_fido::consts::MAX_EA_RPIDS`. Checked here so an over-long list is named
#: as such instead of coming back as a bare CTAP2_ERR_KEY_STORE_FULL.
MAX_EA_RPIDS = 8

try:
    from fido2.ctap import CtapError
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.ctap2.credman import CredentialManagement as CM
except ImportError:
    CtapHidDevice = None


def register(sub):
    p = sub.add_parser("fido", help="FIDO2 management (set PIN, list passkeys, attestation)")
    g = p.add_subparsers(dest="cmd", required=True)
    sp = g.add_parser("set-pin", help="set or change the FIDO2 clientPIN")
    add_pin_arg(sp, help="current FIDO2 PIN, when changing (prompted if omitted)")
    sp.add_argument("--new-pin", help="new FIDO2 PIN (prompted, with confirmation, if omitted)")
    sp.set_defaults(func=set_pin)
    lp = g.add_parser("list-passkeys", help="list discoverable credentials")
    add_pin_arg(lp)
    lp.set_defaults(func=list_passkeys)

    a = g.add_parser("attestation", help="org attestation key/chain (enterprise)")
    ga = a.add_subparsers(dest="acmd", required=True)
    i = ga.add_parser("import", help="install an org attestation key + cert chain")
    i.add_argument("--key", required=True, help="P-256 private key (PEM)")
    i.add_argument("--chain", required=True, help="cert chain, leaf first (PEM or concatenated DER)")
    add_pin_arg(i)
    i.set_defaults(func=att_import)
    c = ga.add_parser("clear", help="remove the org attestation")
    add_pin_arg(c)
    c.set_defaults(func=att_clear)
    ga.add_parser("status", help="show whether an org attestation is installed").set_defaults(
        func=att_status)
    r = ga.add_parser("set-rpids",
                      help="set the RPs that get vendor-facilitated (type 1) EA")
    r.add_argument("rp_id", nargs="*", help=f"relying-party ids (max {MAX_EA_RPIDS})")
    r.add_argument("--clear", action="store_true", help="remove every listed RP")
    add_pin_arg(r, help="FIDO2 PIN (authenticatorConfig requires one; prompted if omitted)")
    r.set_defaults(func=att_set_rpids)


def _ctap(exclusive=False):
    """Open the device through python-fido2's own enumeration.

    `exclusive` refuses to guess between two attached authenticators, the same
    rule `common.connect_fido` applies. It matters more here, not less: this is a
    *third* selector — on macOS the order comes from `IOHIDManagerCopyDevices`, a
    CFSet whose order Apple leaves unspecified — so a PIN write could land on one
    key while the confirmation is read back from the other (audit run-34 #13)."""
    if CtapHidDevice is None:
        die("missing dependency: python-fido2 (run `rsk` from `nix develop`)")
    found = list(CtapHidDevice.list_devices())
    if not found:
        die("no FIDO HID device found")
    if exclusive and len(found) > 1:
        die(
            f"{len(found)} FIDO HID devices attached — this command needs exactly one, "
            "so it cannot act on the wrong device; unplug the others and retry"
        )
    ctap = Ctap2(found[0])
    if "FIDO_2_0" not in ctap.info.versions:
        die("device does not advertise FIDO2")
    return ctap


def set_pin(args):
    ctap = _ctap(exclusive=True)
    has_pin = ctap.info.options.get("clientPin")
    if has_pin is None:
        die("device does not support clientPin")
    cp = ClientPin(ctap)
    new = args.new_pin
    if new is None:  # interactive: enter twice; a --new-pin is trusted as typed
        new = getpass("New FIDO2 PIN (4-63 chars): ")
        if getpass("Repeat new PIN: ") != new:
            die("PINs do not match")
    if len(new) < 4:
        die("PIN too short (min 4)")
    if has_pin:
        current = resolve_pin(args, has_pin=True, prompt="Current PIN: ", required=True)
        try:
            cp.change_pin(current, new)
        except CtapError as e:
            die_ctap_pin_error(e, cp)
        print("FIDO2 PIN changed.")
    else:
        try:
            cp.set_pin(new)
        except CtapError as e:
            die_ctap_pin_error(e, cp)
        print("FIDO2 PIN set.")
    # Re-read from the device just written, not from a fresh enumeration: the
    # second one could answer from the other key and print its state as this one's.
    print("clientPin now:", ctap.get_info().options.get("clientPin"))


def _count(meta, key):
    """A device-reported count, or "?" when the device did not send an integer.
    Never interpolate the raw CBOR value: a counterfeit authenticator returning a
    text string would put terminal escapes straight into the operator's terminal
    (the class fixed for rpId/user name in run-12, unswept here until run-33)."""
    v = meta.get(key)
    return v if isinstance(v, int) else "?"


def list_passkeys(args):
    ctap = _ctap()
    print("credMgmt:", ctap.info.options.get("credMgmt"),
          "| clientPin:", ctap.info.options.get("clientPin"))
    if not ctap.info.options.get("clientPin"):
        die("no FIDO2 PIN set — set one first (rsk fido set-pin)")
    cp = ClientPin(ctap)
    pin = resolve_pin(args, has_pin=True, required=True)
    try:
        token = cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    except CtapError as e:
        die_ctap_pin_error(e, cp)
    cm = CM(ctap, cp.protocol, token)
    meta = cm.get_metadata()
    # Coerce: `get_metadata` hands back whatever CBOR the device sent, and a
    # counterfeit one returning a text string here reached the terminal verbatim —
    # six lines above the sanitize() the rpId and user name already get. An
    # `== 0` guard also never fires for a str, so the walk below ran regardless.
    existing = _count(meta, CM.RESULT.EXISTING_CRED_COUNT)
    remaining = _count(meta, CM.RESULT.MAX_REMAINING_COUNT)
    print(f"\ndiscoverable credentials: {existing}  (free slots: {remaining})")
    if existing == 0:
        print("  → none. An SSH `-O resident` key would show here.")
        return
    for rp in cm.enumerate_rps():
        rp_id = rp[CM.RESULT.RP].get("id")
        print(f"\nRP: {sanitize(rp_id)}")
        for cred in cm.enumerate_creds(rp[CM.RESULT.RP_ID_HASH]):
            user = cred[CM.RESULT.USER]
            cid = cred[CM.RESULT.CREDENTIAL_ID]["id"]
            name = user.get("name") or user.get("displayName") or user.get("id")
            print(f"   user={sanitize(name)}  credId={cid.hex()[:24]}…")


# --- org attestation (vendor 0x41 subcommands 0x09-0x0B) ---------------------
# Provisions the enterprise-attestation key + chain: makeCredential with
# enterpriseAttestation 1/2 and U2F register then attest under the org chain
# instead of the per-device self-signed cert. The private key crosses the wire
# ChaCha20-Poly1305-wrapped on the same MSE channel the seed backup uses.

ATT_IMPORT, ATT_CLEAR, ATT_STATE = 9, 10, 11


def _att_scalar(path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(open(path, "rb").read(), None)
    if not isinstance(key.curve, ec.SECP256R1):
        die(f"attestation key must be P-256 (got {key.curve.name})")
    return key.private_numbers().private_value.to_bytes(32, "big")


def _att_chain(path):
    data = open(path, "rb").read()
    if b"-----BEGIN" in data:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        certs = x509.load_pem_x509_certificates(data)
        return b"".join(c.public_bytes(Encoding.DER) for c in certs)
    return data  # already concatenated DER


def att_import(args):
    import os

    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from .backup import _die_pin_required, _gated, _vendor, mse_handshake
    from .common import connect_fido

    scalar, chain = _att_scalar(args.key), _att_chain(args.chain)
    if len(chain) > ATT_CHAIN_MAX:
        die(f"chain too large ({len(chain)} B, max {ATT_CHAIN_MAX})")
    dev, cid = connect_fido(exclusive=True)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    key, aad = mse_handshake(dev, cid)
    nonce = os.urandom(12)
    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, scalar, aad)
    print("touch the device (BOOTSEL) to authorise the import…", file=sys.stderr)
    st, _ = _vendor(dev, cid, _gated(ATT_IMPORT, {1: blob, 2: chain}, dev, cid, pin))
    _die_pin_required(st)
    if st != 0:
        die(f"import failed: {st:#x}")
    print("org attestation installed ✓ — EA makeCredential and U2F now use the org chain")


def att_clear(args):
    from .backup import _die_pin_required, _gated, _vendor, mse_handshake
    from .common import connect_fido

    dev, cid = connect_fido(exclusive=True)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    mse_handshake(dev, cid)
    print("touch the device (BOOTSEL) to remove the attestation…", file=sys.stderr)
    st, _ = _vendor(dev, cid, _gated(ATT_CLEAR, None, dev, cid, pin))
    _die_pin_required(st)
    if st != 0:
        die(f"clear failed: {st:#x}")
    print("org attestation removed ✓ (back to the self-signed device cert)")


def att_set_rpids(args):
    from .common import connect_fido
    from .lock import _config_vendor

    # The device has no read path for this list, so an accidental empty argv would
    # clear it with nothing to compare against afterwards: make the clear explicit.
    if bool(args.rp_id) == args.clear:
        die("give the rp ids to allow, or --clear to remove them all")
    if len(args.rp_id) > MAX_EA_RPIDS:
        die(f"{len(args.rp_id)} rp ids, max {MAX_EA_RPIDS} (the device refuses the whole list)")
    dev, cid = connect_fido(exclusive=True)
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid), required=True)
    st = _config_vendor(dev, cid, pin, CONFIG_EA_RPIDS, rp_ids=list(args.rp_id))
    if st == 0x28:
        die("device refused the list as too long (CTAP2_ERR_KEY_STORE_FULL)")
    if st != 0:
        die(f"set-rpids failed: {st:#x}")
    if args.clear:
        print("enterprise rp list cleared ✓ — type-1 EA now qualifies no RP")
    else:
        print(f"enterprise rp list set ✓ — {len(args.rp_id)} RP(s) get type-1 EA")
        print("(enterpriseAttestation must also be enabled by the managed platform)")


def att_status(args):
    from .backup import _vendor
    from .common import connect_fido

    dev, cid = connect_fido()
    st, m = _vendor(dev, cid, {1: ATT_STATE})
    if st != 0:
        die(f"status failed: {st:#x}")
    if m[1]:
        print(f"org attestation : installed\nchain hash      : {m[2].hex()}")
    else:
        print("org attestation : not installed (self-signed device cert in use)")
