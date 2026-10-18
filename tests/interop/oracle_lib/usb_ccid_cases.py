# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""USB control ABORT and disconnects retain applet/private-operation witnesses."""
from itertools import product
import sys

from . import codec
from .lifecycle import Action, change
from .openpgp_mse import cue
from .openpgp_operations import operation_key, sign
from .trace import Outcome, TransferError


def require(session):
    session.require(session.profile == "rsk", "native CCID USB control/abort profile requires RS-Key", "excluded_by_profile")
    session.require(session.card is not None and hasattr(session.card, "usb_control"), "native USB control backend required; PC/SC cannot provide USB control evidence", "excluded_by_mode")


def abort(session, slot, sequence, data=b"", index=None):
    interface = session.card.descriptor["interface_number"] if index is None else index
    value = sequence << 8 | slot
    wire = bytes([0x21, 1]) + value.to_bytes(2, "little") + interface.to_bytes(2, "little") + len(data).to_bytes(2, "little") + data
    return session._exchange("ccid", "usb_control", "ccid.class.ABORT", wire, session.options.timeout,
        lambda deadline, observe: session.card.usb_control(0x21, 1, value, interface, data, deadline, observe))


def remove(session):
    start = session.trace.now()
    session.trace.emit("interaction", action="remove-selected-key", stage="requested", source="runner", observed_disconnect_ns=None)
    print("oracle: unplug ONLY the selected test key and leave it disconnected", file=sys.stderr)
    input("oracle: after removing that test key, press Enter (do not replug yet): ")
    session.trace.emit("interaction", action="remove-selected-key", stage="reported_complete", source="operator_report",
        interval_start_ns=start, interval_end_ns=session.trace.now(), observed_disconnect_ns=None)


def idle(session):
    from yubikit.openpgp import KEY_REF
    for slot, sequence, body in product((0, 1, 255), (0, 1, 127, 255), (b"", b"x")):
        with session.case(f"transport.USB-CCID.ABORT.idle.slot-{slot}.sequence-{sequence}.body-{len(body)}", ("T10", "G03", "G04", "G10", "G14"), effects=("replace_openpgp_keys", "config_change"), touch=True):
            require(session)
            with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, private):
                sdk.verify_pin(session.options.openpgp_pin)
                sign(session, KEY_REF.SIG, private.public_key(), session.fixture("CCID.USB.before-control"))
                result = abort(session, slot, sequence, body)
                session.check("current RS-Key USB class ABORT is explicitly stalled", (result.protocol, result.status), ("transport_error", "USB_STALL"))
                sign(session, KEY_REF.SIG, private.public_key(), session.fixture("CCID.USB.after-control"))
                session.check("stalled USB control preserves private key, PIN grant and counter scope", sdk.get_signature_counter(), 2)


def waits(session):
    from yubikit.openpgp import KEY_REF
    for mode in ("matching-ABORT", "foreign-slot-ABORT", "foreign-sequence-ABORT", "removal-while-waiting"):
        with session.case("transport.USB-CCID.wait." + mode, ("T10", "O02", "O11", "O19", "O22", "X11", "G10", "G11", "G12", "G14"), effects=("replace_openpgp_keys", "config_change", "session_recovery", "reboot"), touch=True):
            require(session)
            session.require(session.options.operator and hasattr(session.card, "on_extension"), "controlled CCID wait/removal needs an operator and time-extension callback")
            with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, private):
                sdk.put_data(0xd6, b"\x01\x20")
                sdk.verify_pin(session.options.openpgp_pin)
                before = sdk.get_signature_counter()
                original, fired = session.card.on_extension, False
                def extension(frame):
                    nonlocal fired
                    if fired:
                        return
                    fired = True
                    session.observe("CCID_time_extension_before_injection", frame)
                    if mode == "removal-while-waiting":
                        remove(session)
                    else:
                        slot = 1 if mode == "foreign-slot-ABORT" else frame[5]
                        sequence = (frame[6] + 1) & 255 if mode == "foreign-sequence-ABORT" else frame[6]
                        result = abort(session, slot, sequence)
                        session.check("USB control ABORT cannot cancel the current RS-Key command", (result.protocol, result.status), ("transport_error", "USB_STALL"))
                        cue(session, "accept")
                session.card.on_extension = extension
                cue(session, "withhold until the runner requests confirmation or removal")
                try:
                    if mode == "removal-while-waiting":
                        try:
                            session.apdu(codec.apdu(0x2a, 0x9e, 0x9a, session.fixture("CCID.USB.removed-operation")))
                        except TransferError as error:
                            session.check("selected USB removal is observed as disconnect, not fabricated APDU refusal", error.outcome, Outcome.DISCONNECTED)
                            session.observe("removed_operation_outcome", "response unobserved; no mutation replayed")
                        else:
                            session.check("reported removal must produce a disconnect observation", False)
                        change(session, Action.POWER_CYCLE)
                        session.select("openpgp")
                        session.check("unconfirmed removed signature did not advance its persistent counter", sdk.get_signature_counter(), before)
                    else:
                        sign(session, KEY_REF.SIG, private.public_key(), session.fixture("CCID.USB.inflight-control"))
                    session.check("injection followed an actual CCID time-extension response", fired)
                finally:
                    session.card.on_extension = original
                cue(session, "accept")
                sdk.verify_pin(session.options.openpgp_pin)
                sign(session, KEY_REF.SIG, private.public_key(), session.fixture("CCID.USB.fresh-recovery-control"))


def lost_response(session):
    from yubikit.openpgp import KEY_REF
    with session.case("transport.USB-CCID.lost-SIG-response.readback-without-replay", ("T10", "O11", "O22", "X11", "G11", "G14"), effects=("replace_openpgp_keys", "config_change", "session_recovery"), touch=True):
        require(session)
        session.require(hasattr(session.card, "drop_response"), "native bounded response-loss injection required", "excluded_by_mode")
        with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, private):
            sdk.verify_pin(session.options.openpgp_pin)
            before = sdk.get_signature_counter()
            wire = codec.apdu(0x2a, 0x9e, 0x9a, session.fixture("CCID.USB.lost-operation"))
            try:
                session._exchange("card", session.card.layer, "ccid.usb.inject-response-loss", wire, session.options.timeout,
                    lambda deadline, observe: session.card.drop_response(wire, deadline, observe))
            except TransferError as error:
                session.check("injected native loss preserves transmitted evidence and its actual cause", error.transmitted and error.outcome in (Outcome.CANCELLED, Outcome.DISCONNECTED))
                session.broken = True
            else:
                session.check("response-loss injection cannot fabricate a device answer", False)
            change(session, Action.RECONNECT)
            session.select("openpgp")
            current = sdk.get_signature_counter()
            session.check("one lost signature request has at most one committed counter increment", current in (before, before + 1))
            session.observe("lost_SIG_commit", {"before": before, "after": current, "basis": "persistent signature-counter readback", "replayed": False})
            sdk.verify_pin(session.options.openpgp_pin)
            sign(session, KEY_REF.SIG, private.public_key(), session.fixture("CCID.USB.distinct-followup"))
            session.check("fresh follow-up increments only the observed recovered counter", sdk.get_signature_counter(), current + 1)


def run(session):
    idle(session)
    waits(session)
    lost_response(session)
