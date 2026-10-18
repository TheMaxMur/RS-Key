# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native USB reset and CPU warm boot have different global and applet lifetimes."""
import hmac
from itertools import product

from . import codec
from .cards import selected_cleanup
from .fido import cm, info, pin_token
from .fido_fixtures import credential
from .fido_lifecycle import decrypt_member
from .info_matrix import agreement, stable
from .native_lifetimes import preflight, cross as native_cross
from .oath_access import known_record, lock, unlock
from .oath_gates import Grant, reset
from .oath_pin_matrix import NAME, PIN, private_record, setup
from .openpgp_references import REFS, fixture as pgp_fixture, authenticate, grants
from .pcsc_grants import piv_grants, oath_grants
from .piv_matrix import key_fixture
from .vendor_boot import Boundary

BOUNDARIES = (Boundary.SELF, Boundary.OTHER, Boundary.INVALID, Boundary.WARM, Boundary.USB_RESET)
RETAINS_GRANTS = (Boundary.SELF, Boundary.INVALID)


def eligible(session, boundary):
    if boundary in (Boundary.WARM, Boundary.USB_RESET):
        preflight(session, boundary)
    else:
        from .binding import require_pair
        session.require(session.profile == "rsk", "selection grant contracts require RS-Key", "excluded_by_profile")
        require_pair(session)
    current = info(session)
    session.require(current.get(4, {}).get("clientPin") and session.options.pin and not current.get(12, False),
        "native lifetime controls need a known host PIN without pending force-change")


def cross(session, boundary, retained, applet):
    if boundary in (Boundary.WARM, Boundary.USB_RESET):
        return native_cross(session, boundary, retained)
    if boundary == Boundary.OTHER:
        session.select("openpgp" if applet == "piv" else "piv")
    elif boundary == Boundary.INVALID:
        session.check("invalid AID cannot select or deselect an applet", session.apdu(codec.apdu(0xa4, 4, data=b"\xf0\xff\xff\xff\xff")).status, 0x6a82)
    session.select(applet)


def piv(session):
    from yubikit.piv import PIN_POLICY
    for boundary, pin, management in product(BOUNDARIES, (False, True), (False, True)):
        with session.case(f"native.lifetime.PIV.{boundary.value}.PIN-{pin}.management-{management}", ("P03", "P06", "P11", "P17", "X11", "G10", "G14"),
                effects=("replace_piv_slot_82", "create_fido_credential", "reboot", "session_recovery"), touch=True):
            eligible(session, boundary)
            with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                with selected_cleanup(session, "piv", key_fixture(session, policy=PIN_POLICY.ONCE)) as (sdk, key):
                    session.select("openpgp")
                    session.select("piv")
                    if pin:
                        sdk.verify_pin(session.options.piv_pin)
                    if management:
                        sdk.authenticate(session.options.management_key)
                    piv_grants(session, sdk, key, pin, management)
                    cross(session, boundary, retained, "piv")
                    session.select("piv")
                    piv_grants(session, sdk, key, pin and boundary in RETAINS_GRANTS, management and boundary in RETAINS_GRANTS)
                    sdk.verify_pin(session.options.piv_pin)
                    sdk.authenticate(session.options.management_key)
                    piv_grants(session, sdk, key, True, True)


def openpgp(session):
    for boundary, bits in product(BOUNDARIES, product((False, True), repeat=len(REFS))):
        live = tuple(reference for reference, enabled in zip(REFS, bits) if enabled)
        with session.case(f"native.lifetime.OpenPGP.{boundary.value}.grants-{''.join(str(int(bit)) for bit in bits)}",
                ("O02", "O07", "O11", "O22", "X11", "G10", "G14"), effects=("replace_openpgp_sig_key", "write_and_restore_openpgp_DO", "config_change", "create_fido_credential", "reboot", "session_recovery"), touch=True):
            eligible(session, boundary)
            with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                with selected_cleanup(session, "openpgp", pgp_fixture(session)) as (sdk, key):
                    for reference in REFS:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, reference)))
                    authenticate(session, sdk, live)
                    grants(session, sdk, key, live)
                    count = sdk.get_signature_counter()
                    cross(session, boundary, retained, "openpgp")
                    session.select("openpgp")
                    session.check("native boundary cannot execute a hidden OpenPGP signature", sdk.get_signature_counter(), count)
                    grants(session, sdk, key, live if boundary in RETAINS_GRANTS else ())
                    authenticate(session, sdk)
                    grants(session, sdk, key)


def oath(session):
    for boundary, grant in product(BOUNDARIES, Grant):
        with session.case(f"native.lifetime.OATH.{boundary.value}.{grant.value}", ("A04", "A10", "A11", "A14", "A15", "X02", "X11", "G09", "G10", "G11", "G14"),
                effects=("applet_reset", "pin_change", "config_change", "create_oath_record", "create_fido_credential", "reboot", "session_recovery"), touch=True):
            eligible(session, boundary)
            with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                secret = setup(session)
                try:
                    known_record(session, NAME, 0)
                    selected = lock(session)
                    old_proof = hmac.digest(secret, selected[0x74], "sha256")
                    if grant in (Grant.CODE, Grant.BOTH):
                        unlock(session, 2, secret, selected)
                    if grant in (Grant.PIN, Grant.BOTH):
                        session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                    oath_grants(session, grant)
                    cross(session, boundary, retained, "oath")
                    after = dict(codec.parse_tlv(session.select("oath")))
                    expected = Grant.CODE if boundary in RETAINS_GRANTS and grant in (Grant.CODE, Grant.BOTH) else Grant.NONE
                    oath_grants(session, expected)
                    session.check("new native session uses a fresh OATH challenge", after[0x74] != selected[0x74])
                    session.check("the pre-boundary mutual-authentication proof cannot be replayed", session.apdu(codec.apdu(0xa3,
                        data=codec.tlv(0x75, old_proof) + codec.tlv(0x74, bytes(8)))).status, 0x6a80)
                    oath_grants(session, expected)
                    unlock(session, 2, secret, after)
                    session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                    private_record(session)
                    known_record(session, NAME, 1)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)


def fido(session):
    for boundary, version in product(BOUNDARIES, (1, 2)):
        with session.case(f"native.lifetime.FIDO.{boundary.value}.protocol-{version}", ("F01", "F03", "F09", "F10", "FE14", "X11", "G10", "G14"),
                effects=("create_fido_credential", "reboot", "session_recovery"), touch=True):
            eligible(session, boundary)
            with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                session.select("fido")
                first_point = agreement(session, version)
                ordinary = pin_token(session, 4, version=version)
                readonly = pin_token(session, 64, version=version)
                before = session.ctap_value(cm(session, *ordinary, 1))
                current = session.ctap_value(session.ctap(4))
                session.require(all(key in current for key in (25, 30)), "encrypted identity/store witnesses need persistent read-only support")
                plaintext = tuple(decrypt_member(readonly[1], label, current[key]) for key, label in ((25, b"encIdentifier"), (30, b"encCredStoreState")))
                used = session.trace.now()
                cross(session, boundary, retained, "fido")
                elapsed = (session.trace.now() - used) / 1_000_000_000
                response = cm(session, *ordinary, 1)
                if boundary == Boundary.WARM:
                    session.check("CPU warm reboot revokes the ordinary in-RAM token", response.status, 0x33)
                elif elapsed < 29:
                    session.check("USB reset preserves a still-live device-wide ordinary token", session.ctap_value(response), before)
                elif elapsed > 31:
                    session.check("a long host reset cannot extend ordinary token idle life", response.status, 0x33)
                else:
                    session.require(False, "host reset overlapped the token idle boundary; exact device timer position is unobserved", "excluded_by_mode")
                session.check("persistent read-only token survives either native boundary", session.ctap_value(cm(session, *readonly, 1)), before)
                after = session.ctap_value(session.ctap(4))
                session.check("native boundary retains public PIN/policy/capability state", stable(after), stable(current))
                for index, (key, label) in enumerate(((25, b"encIdentifier"), (30, b"encCredStoreState"))):
                    session.check("native boundary preserves decrypted identity and store state", decrypt_member(readonly[1], label, after[key]), plaintext[index])
                session.check("PIN ECDH lifetime follows CPU rather than USB reset", agreement(session, version) != first_point, boundary == Boundary.WARM)
                retained.assertion(session)


def run(session):
    piv(session)
    openpgp(session)
    oath(session)
    fido(session)
