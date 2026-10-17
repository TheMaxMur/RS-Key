# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Cross-surface state uses explicit transport changes and populated controls."""
import hashlib

from cryptography.hazmat.primitives import hashes

from . import codec
from .cards import connection, fixture_key
from .card_states import sdk_refused
from .fido import cm, info, pin_protocol, pin_token, verified
from .fido_fixtures import credential
from .lifecycle import Action, change
from .runner import CtapRoute
from .trace import TransferError
from .binding import require_pair


def authorization(session):
    from yubikit.piv import KEY_TYPE, SLOT, PivSession
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    for target in ("piv", "openpgp"):
        with session.case("cross.authorization.foreign-to-" + target, ("X01", "P11", "O11", "G10", "G14"), effects=("replace_piv_slot_82", "replace_openpgp_sig_key"), touch=True):
            session.require(session.options.piv_pin and session.options.management_key and session.options.openpgp_pin and session.options.openpgp_admin,
                            "cross-authorization fixtures require both applets' known credentials")
            piv, pgp = PivSession(connection(session)), OpenPgpSession(connection(session))
            key, message = fixture_key(session, "ECCP256"), session.fixture("cross.authorization")
            created = False
            try:
                if target == "piv":
                    session.select("piv")
                    piv.authenticate(session.options.management_key)
                    piv.put_key(SLOT(0x82), key)
                    created = True
                    operation = lambda: piv.sign(SLOT(0x82), KEY_TYPE.ECCP256, message, hashes.SHA256())
                    session.select("openpgp")
                    pgp.verify_pin(session.options.openpgp_pin)
                else:
                    pgp.verify_admin(session.options.openpgp_admin)
                    pgp.put_key(KEY_REF.SIG, key)
                    created = True
                    operation = lambda: pgp.sign(message, hashes.SHA256())
                    session.select("piv")
                    piv.verify_pin(session.options.piv_pin)
                session.select(target)
                sdk_refused(session, operation, "foreign applet authentication cannot authorize populated key", 0x6982)
                (piv if target == "piv" else pgp).verify_pin(session.options.piv_pin if target == "piv" else session.options.openpgp_pin)
                verified(session, "target's own authorization control", key.public_key(), -7, operation(), message)
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    if target == "piv":
                        session.select("piv")
                        piv.authenticate(session.options.management_key)
                        piv.delete_key(SLOT(0x82))
                    else:
                        session.select("openpgp")
                        pgp.verify_admin(session.options.openpgp_admin)
                        pgp.delete_key(KEY_REF.SIG)


def ctap_scope(session):
    for initiating, continuing in ((CtapRoute.HID, CtapRoute.CARD), (CtapRoute.CARD, CtapRoute.HID)):
        with session.case(f"cross.CTAP.token-and-walk.{initiating.value}-to-{continuing.value}", ("X03", "F03", "F09", "F15", "F16")):
            session.require(session.hid is not None and session.card is not None, "select both interfaces of one physical instance")
            require_pair(session)
            session.select("fido")
            with session.route(initiating):
                version, token = pin_token(session, 4)
                metadata = session.ctap_value(cm(session, version, token, 1))
                start = cm(session, version, token, 2)
                session.observe("initiator_walk_status", start.status)
            with session.route(continuing):
                result = cm(session, version, token, 3)
                session.observe("cross_transport_continuation", (result.protocol, result.status))
                result = cm(session, version, token, 1)
                session.observe("cross_transport_token", (result.protocol, result.status))
                if result.protocol == "success":
                    session.check("shared token metadata consistency", session.ctap_value(result), metadata)
                fresh_version, fresh_token = pin_token(session, 4)
                session.check("destination remains usable with fresh token", session.ctap_value(cm(session, fresh_version, fresh_token, 1)), metadata)


def shared_retries(session):
    with session.case("cross.CTAP.shared-PIN-retry-budget", ("X04", "F02", "F06", "G14"), effects=("pin_attempts",)):
        session.require(session.profile == "rsk", "shared retry assertion is profile-specific", "excluded_by_profile")
        session.require(session.hid is not None and session.card is not None and session.options.pin is not None, "select both FIDO transports and known fixture PIN")
        require_pair(session)
        session.select("fido")
        initial = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3]
        session.require(initial >= 3, "two failure probes require at least three remaining attempts")
        try:
            with session.attempts("fido.pin", 3):
                for ordinal, route in enumerate((CtapRoute.HID, CtapRoute.CARD), 1):
                    with session.route(route):
                        protocol = pin_protocol(session, 2)
                        wrong = hashlib.sha256((session.options.pin + "!").encode()).digest()[:16]
                        reply = session.ctap(6, {1: 2, 2: 9, 3: protocol.cose, 6: protocol.encrypt(wrong), 9: 4})
                        session.check("wrong PIN refused across transport", reply.status, 0x31)
                        session.check("shared persistent retry decrement", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], initial - ordinal)
                pin_token(session, 4)
                session.check("correct PIN restores persistent budget", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], initial)
        finally:
            session.ctap_route = CtapRoute.HID


def lost_write(session):
    from yubikit.openpgp import OpenPgpSession
    with session.case("cross.lost-write-response.readback", ("X10", "O07", "G12", "G14"), effects=("write_and_restore_openpgp_DO", "session_recovery")):
        session.require(session.options.openpgp_admin is not None, "lost-write fixture requires known PW3")
        session.require(session.card is not None and hasattr(session.card, "drop_response"), "backend lacks a defined response-loss injection boundary", "excluded_by_mode")
        sdk = OpenPgpSession(connection(session))
        original = sdk.get_data(0x5E)
        fixture = b"oracle-lost-response"
        sdk.verify_admin(session.options.openpgp_admin)
        request = codec.apdu(0xDA, 0, 0x5E, fixture)
        try:
            session.trace.emit("fault_injected", fault="host_response_loss", boundary="after API invocation or socket write, before response delivery", physical_power_cut=False)
            try:
                session._exchange("card", session.card.layer, "openpgp.PUT.lost-response", request, session.options.timeout,
                                  lambda deadline, observe: session.card.drop_response(request, deadline, observe))
            except TransferError as error:
                session.check("loss injection reached expected boundary", error.protocol, "injected_response_loss")
            else:
                session.check("injected write must not return a known response", False)
            change(session, Action.RECONNECT)
            sdk = OpenPgpSession(connection(session))
            observed = sdk.get_data(0x5E)
            session.check("interrupted write leaves one complete value", observed in (original, fixture))
            session.observe("write_readback", "committed" if observed == fixture else "previous_value_retained")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                sdk.verify_admin(session.options.openpgp_admin)
                sdk.put_data(0x5E, original)
                session.check("lost-response fixture restored", sdk.get_data(0x5E), original)


def capacity(session):
    from .otp import oath_open, oath_names, oath_request
    from .cards import connection
    from yubikit.piv import PivSession
    from yubikit.core.smartcard import ApduError
    with session.case("cross.OATH-full.PIV-object", ("X07", "A02", "A03", "P13", "G14"), effects=("capacity", "create_oath_record", "write_piv_fixture_object")):
        session.require(session.options.management_key is not None, "capacity neighbor requires known PIV management key")
        piv = PivSession(connection(session))
        try:
            previous = piv.get_object(0x5F0077)
        except ApduError as error:
            if error.sw != 0x6A82:
                raise
            previous = None
        marker_written = False
        oath_open(session)
        original = oath_names(session)
        created, full = [], False
        try:
            for index in range(4096):
                name = b"oracle-capacity-" + session.fixture("capacity.namespace", 5).hex().encode() + str(index).encode()
                session.require(name not in original, "capacity fixture name collides")
                result = session.apdu(codec.apdu(1, data=codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06fixture-key")))
                if result.protocol == "success":
                    created.append(name)
                    continue
                session.check("capacity refusal has storage cause", result.status in (0x6A84, 0x6581))
                full = True
                break
            session.check("OATH capacity reached within generator bound", full)
            piv = PivSession(connection(session))
            piv.authenticate(session.options.management_key)
            marker = b"oracle-neighbor-capacity"
            piv.put_object(0x5F0077, marker)
            marker_written = True
            session.check("PIV survives full OATH quota", piv.get_object(0x5F0077), marker)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                if marker_written:
                    session.select("piv", required=True)
                    piv.authenticate(session.options.management_key)
                    piv.put_object(0x5F0077, previous)
                oath_open(session)
                for name in created:
                    oath_request(session, 2, codec.tlv(0x71, name))
                session.check("capacity cleanup restores original names", oath_names(session), original)


def run(session):
    authorization(session)
    ctap_scope(session)
    shared_retries(session)
    lost_write(session)
    capacity(session)
    long_operation(session)


def long_operation(session):
    from yubikit.piv import KEY_TYPE, SLOT
    from .piv_lifecycle import fixture_session
    with session.case("cross.RSA-keygen.HID-responsiveness", ("X09", "T06", "P09", "P11"), effects=("replace_piv_slot_82",), touch=True):
        session.require(session.hid is not None and session.card is not None, "select both interfaces of one device")
        require_pair(session)
        backend = session.card
        session.require(hasattr(backend, "on_started") or hasattr(backend, "on_extension"), "backend has no explicit concurrent-operation scheduling boundary", "excluded_by_mode")
        sdk = fixture_session(session)
        marker = session.fixture("cross.concurrent.ping", 32)
        observed, created = [], False
        def probe(*args):
            if not observed:
                # Arm before I/O so a recursive callback cannot issue another probe.
                observed.append(session.trace.now())
                result = session.hid_call(1, marker, "cross.HID-PING.during-RSA-keygen")
                session.observe("other_interface_result", (result.protocol, result.status))
                if result.protocol == "success":
                    session.check("concurrent PING echoes exactly", result.data, marker)
                else:
                    session.check("concurrent refusal is channel-busy", result.status, 6)
        hook = "on_extension" if hasattr(backend, "on_extension") else "on_started"
        previous = getattr(backend, hook)
        try:
            setattr(backend, hook, probe)
            public = sdk.generate_key(SLOT(0x82), KEY_TYPE.RSA2048)
            created = True
            setattr(backend, hook, previous)
            session.check("overlapping interface probe actually ran", len(observed), 1)
            session.observe("overlap_basis", "CCID time extension during processing" if hook == "on_extension" else "PC/SC API invocation; device processing onset is unobservable")
            from .card_keys import private_operation
            sdk.verify_pin(session.options.piv_pin)
            private_operation(session, sdk, SLOT(0x82), public, "RSA2048", piv=True)
        finally:
            setattr(backend, hook, previous)
            if created and not session.broken:
                session.trace.phase = "cleanup"
                sdk.authenticate(session.options.management_key)
                sdk.delete_key(SLOT(0x82))
