# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise every cross-scope cancel pair at an observed pending boundary."""
from contextlib import contextmanager
from itertools import product
import sys

from . import codec
from .binding import require_pair
from .hid_sequences import hooks, send
from .otp_commands import Mode, Route, checksum, configure, fixture, witness
from .otp_transport import DUMMY_ABORT, RESET, feature
from .otp_waits import poll, send as otp_send
from .usb_ccid_cases import abort


def cue(session, action):
    print("oracle: cross-interface presence: " + action, file=sys.stderr)
    session.trace.emit("interaction", action="cross-presence-" + action, stage="requested", source="runner", observed_touch_ns=None)


def ready(session, foreign):
    session.require(session.profile == "rsk", "presence-scope contracts require RS-Key", "excluded_by_profile")
    require_pair(session)
    session.require(session.options.operator, "cross-scope waits require controlled withholding and separate confirmation")
    session.require(session.hid is not None and hasattr(session.hid, "send_only"), "raw HID scope scheduler unavailable", "excluded_by_mode")
    if foreign == "OTP":
        session.require(session.otp_hid is not None and hasattr(session.otp_hid, "raw_feature"), "raw OTP cancel surface unavailable", "excluded_by_mode")
        otp_binding(session)
    if foreign == "CCID":
        session.require(hasattr(session.card, "usb_control"), "native USB class ABORT surface unavailable", "excluded_by_mode")


def otp_binding(session):
    hid, otp = getattr(session.hid, "descriptor", {}), getattr(session.otp_hid, "descriptor", {})
    session.require(hid.get("serial_number") and hid.get("serial_number") == otp.get("serial_number"),
        "OTP and FIDO presence scopes need positively matched selected-device serials", "excluded_by_mode")


def foreign_cancel(session, foreign):
    if foreign == "HID":
        send(session, 0x11, session.hid.cid, label="cross-presence.foreign-HID-CANCEL")
    elif foreign == "OTP":
        feature(session, DUMMY_ABORT)
        feature(session, RESET)
    else:
        result = abort(session, 0, 0)
        session.check("USB class ABORT remains explicitly stalled during a foreign wait", (result.protocol, result.status), ("transport_error", "USB_STALL"))


@contextmanager
def card_probe(session, foreign):
    ready(session, foreign)
    card = session.card
    session.require(hasattr(card, "on_extension"), "native CCID time-extension observation required", "excluded_by_mode")
    old, observed = card.on_extension, []
    def extension(frame):
        if observed:
            return
        observed.append(session.trace.now())
        session.observe("CCID_wait_boundary", frame)
        foreign_cancel(session, foreign)
        reply = session.hid_call(1, b"other-scope", "cross-presence.HID-PING")
        session.check("foreign request is an exact PING or explicit busy response", reply.protocol == "success" and reply.data == b"other-scope" or (reply.protocol, reply.status) == ("transport_error", 6))
        cue(session, "confirm-owner-once")
    cue(session, "withhold-until-confirm-owner")
    card.on_extension = extension
    try:
        yield
        session.require(bool(observed), "no CCID time extension observed; no cross-scope wait claim", "excluded_by_mode")
        session.observe("wait_scope_evidence", "touch-required owner, declared withheld input and actual CCID time extension; the exact device presence-start instant is unobservable; API duration includes callback work")
    finally:
        card.on_extension = old


def card_owners(session):
    from yubikit.openpgp import KEY_REF
    from yubikit.piv import PIN_POLICY, SLOT, TOUCH_POLICY
    from .card_pin_matrix import piv_sign, pgp_sign
    from .openpgp_operations import operation_key
    from .oath_matrix import records
    from .oath_semantics import answer, key_fields
    from .otp import OATH_HASHES
    from .piv_matrix import key_fixture
    for owner, foreign in product(("PIV", "OpenPGP", "OATH", "OTP-CCID"), ("HID", "OTP")):
        with session.case(f"cross.presence.owner-{owner}.cancel-{foreign}", ("X05", "T06", "T07", "T15", "P11", "O11", "A04", "Y07", "G10", "G12", "G14"),
                effects=("replace_piv_slot_82", "replace_openpgp_keys", "create_oath_record", "replace_otp_slot_1", "config_change"), touch=True,
                method="full CCID applet by foreign cancel-scope product; real private/counter controls"):
            ready(session, foreign)
            session.require(hasattr(session.card, "on_extension"), "native CCID time-extension callback required before fixture writes", "excluded_by_mode")
            if owner == "PIV":
                with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                    sdk.authenticate(session.options.management_key)
                    sdk.put_key(SLOT(0x82), key, PIN_POLICY.ONCE, TOUCH_POLICY.ALWAYS)
                    sdk.verify_pin(session.options.piv_pin)
                    with card_probe(session, foreign):
                        piv_sign(session, sdk, key)
                    cue(session, "confirm-fresh-control")
                    piv_sign(session, sdk, key)
            elif owner == "OpenPGP":
                with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, key):
                    original = sdk.get_data(0xd6)
                    session.require(original[:1] != b"\x02", "fixed UIF requires a separate reset-owned fixture")
                    try:
                        sdk.put_data(0xd6, b"\x01\x20")
                        sdk.verify_pin(session.options.openpgp_pin)
                        before = sdk.get_signature_counter()
                        with card_probe(session, foreign):
                            pgp_sign(session, sdk, key)
                        session.check("foreign cancel permits exactly the confirmed owner signature", sdk.get_signature_counter(), before + 1)
                        cue(session, "confirm-fresh-control")
                        pgp_sign(session, sdk, key)
                        session.check("fresh independent owner control alone advances again", sdk.get_signature_counter(), before + 2)
                    finally:
                        if not session.broken:
                            sdk.verify_admin(session.options.openpgp_admin)
                            sdk.put_data(0xd6, original)
            elif owner == "OATH":
                name, secret = b"oracle-cross-presence", OATH_HASHES[0][2]
                with records(session, [(name, key_fields(0x10, 1, 6, secret, 2))]):
                    with card_probe(session, foreign):
                        answer(session, name, bytes(8), secret, "sha1", 6, counter=0)
                    cue(session, "confirm-fresh-control")
                    answer(session, name, bytes(8), secret, "sha1", 6, counter=1)
            else:
                config = bytearray(configure(session.fixture("cross-presence.OTP", 20), Mode.HMAC))
                config[47] |= 8
                config = checksum(config)
                with fixture(session, Route.CARD, 1, config):
                    with card_probe(session, foreign):
                        witness(session, Route.CARD, 1, config)
                    cue(session, "confirm-fresh-control")
                    witness(session, Route.CARD, 1, config)


def fido_owner(session):
    for foreign in ("OTP", "CCID"):
        with session.case("cross.presence.owner-FIDO.cancel-" + foreign, ("X05", "F22", "T06", "T07", "G10", "G12", "G14"), touch=True):
            ready(session, foreign)
            timeline, sent = [], []
            with hooks(session) as hid:
                def keepalive(status, timestamp):
                    timeline.append((status, timestamp))
                    count = sum(item[0] == 2 for item in timeline)
                    if status == 2 and count == 1:
                        foreign_cancel(session, foreign)
                        sent.append("foreign")
                    elif status == 2 and count >= 3 and "owner" not in sent:
                        send(session, 0x11, hid.cid)
                        sent.append("owner")
                hid.on_keepalive = keepalive
                cue(session, "withhold-owner-will-cancel")
                reply = session.ctap(11)
                session.check("owner FIDO selection alone cancels its wait", reply.status, 0x2d)
                session.check("foreign cancellation leaves the owner waiting for its own cancel", sent, ["foreign", "owner"])
                session.check("owner emitted fresh UP-needed after the foreign cancellation", sum(item[0] == 2 for item in timeline) >= 3)
            session.check("owner FIDO channel remains usable", session.hid_call(1, b"presence-recovered").data, b"presence-recovered")


def otp_owner(session):
    for foreign in ("HID", "CCID"):
        with session.case("cross.presence.owner-OTP-HID.cancel-" + foreign, ("X05", "Y07", "T15", "G10", "G12", "G14"),
                effects=("replace_otp_slot_1",), touch=True):
            ready(session, foreign)
            session.require(session.otp_hid is not None and hasattr(session.otp_hid, "raw_feature"), "raw OTP owner required", "excluded_by_mode")
            otp_binding(session)
            config = bytearray(configure(session.fixture("cross-presence.OTP", 20), Mode.HMAC))
            config[47] |= 8
            config = checksum(config)
            with fixture(session, Route.HID, 1, config):
                cue(session, "withhold-OTP-owner")
                otp_send(session, 0x30, session.fixture("cross-presence.OTP.challenge", 64))
                poll(session, lambda value: bool(value[-1] & 0x20), "OTP owner never advertises an actual touch wait")
                foreign_cancel(session, foreign)
                for _ in range(3):
                    session.check("foreign cancellation cannot end or reveal the OTP owner's private result", feature(session).data, bytes(7) + b"\x20")
                feature(session, RESET)
                ended = poll(session, lambda value: not value[-1] & 0x20, "own OTP reset failed to end its wait")
                session.check("own OTP reset returns no stale private stream", ended[-1], 0)
                cue(session, "confirm-fresh-control")
                witness(session, Route.HID, 1, config)


def run(session):
    card_owners(session)
    fido_owner(session)
    otp_owner(session)
