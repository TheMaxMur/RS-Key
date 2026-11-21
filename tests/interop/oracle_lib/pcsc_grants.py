# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PC/SC dispositions retire volatile grants without replacing private objects."""
from contextlib import contextmanager
from enum import Enum
from itertools import product

from . import codec
from .card_pin_matrix import piv_sign
from .card_states import sdk_refused
from .oath_access import known_record, lock, unlock
from .oath_gates import Grant, reset
from .oath_pin_matrix import NAME, PIN, private_record, setup
from .openpgp_references import REFS, authenticate, fixture, grants
from .pcsc_sessions import control
from .piv_matrix import key_fixture


class Operation(Enum):
    END = "end-transaction"
    RECONNECT = "reconnect"


class Disposition(Enum):
    LEAVE = "leave"
    RESET = "reset"
    UNPOWER = "unpower"


def require_backend(session):
    session.require(session.card is not None and hasattr(session.card, "pipe"), "native PC/SC disposition backend required", "excluded_by_mode")


@contextmanager
def transition(session, operation, disposition):
    require_backend(session)
    active = False
    try:
        if operation == Operation.END:
            session.check("protected fixture transaction begins", control(session, {"control": "transaction", "begin": True}).protocol, "success")
            active = True
        yield
        request = {"control": "reset", "disposition": disposition.value} if operation == Operation.RECONNECT else {
            "control": "transaction", "begin": False, "disposition": disposition.value}
        session.check("protected fixture disposition completes", control(session, request).protocol, "success")
        active = False
        if operation == Operation.END and disposition != Disposition.LEAVE:
            # Reconnect acknowledges the driver's reset state without causing a second reset.
            session.check("driver reconnect acknowledges completed disposition", control(session, {"control": "reset", "disposition": "leave"}).protocol, "success")
    finally:
        if active and not session.broken:
            control(session, {"control": "transaction", "begin": False, "disposition": "leave"})


def piv(session, operation, disposition):
    from yubikit.piv import PIN_POLICY
    for pin, management in product((False, True), repeat=2):
        with session.case(f"transport.PCSC.PIV.{operation.value}.{disposition.value}.PIN-{pin}.MGM-{management}",
                ("T14", "P03", "P06", "P12", "P17", "G10", "G11", "G14", "X11"), effects=("replace_piv_keys",), touch=True):
            session.require(session.profile == "rsk", "disposition grant expectations require RS-Key", "excluded_by_profile")
            require_backend(session)
            with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                with transition(session, operation, disposition):
                    session.select("openpgp")
                    session.select("piv")
                    if management:
                        sdk.authenticate(session.options.management_key)
                    if pin:
                        sdk.verify_pin(session.options.piv_pin)
                    piv_grants(session, sdk, key, pin, management)
                if disposition != Disposition.LEAVE:
                    session.select("piv", required=True)
                piv_grants(session, sdk, key, pin and disposition == Disposition.LEAVE, management and disposition == Disposition.LEAVE)
                sdk.verify_pin(session.options.piv_pin)
                piv_sign(session, sdk, key)


def piv_grants(session, sdk, key, pin, management):
    if pin:
        piv_sign(session, sdk, key)
    else:
        sdk_refused(session, lambda: piv_sign(session, sdk, key), "PC/SC PIV PIN latch cannot be inherited", 0x6982)
    session.check("PC/SC disposition preserves only the permitted management latch",
        session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6a80 if management else 0x6982)


def openpgp(session, operation, disposition):
    for bits in product((False, True), repeat=len(REFS)):
        live = tuple(reference for reference, enabled in zip(REFS, bits) if enabled)
        with session.case(f"transport.PCSC.OpenPGP.{operation.value}.{disposition.value}.grants-{''.join(str(int(bit)) for bit in bits)}",
                ("T14", "O02", "O11", "O22", "G10", "G11", "G14", "X11"),
                effects=("replace_openpgp_sig_key", "config_change", "write_and_restore_openpgp_DO"), touch=True):
            require_backend(session)
            with fixture(session) as (sdk, key):
                with transition(session, operation, disposition):
                    for reference in REFS:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, reference)))
                    authenticate(session, sdk, live)
                    grants(session, sdk, key, live)
                    counter = sdk.get_signature_counter()
                if disposition != Disposition.LEAVE:
                    session.select("openpgp", required=True)
                session.check("PC/SC disposition does not execute a private operation", sdk.get_signature_counter(), counter)
                grants(session, sdk, key, live if disposition == Disposition.LEAVE else ())
                authenticate(session, sdk)
                grants(session, sdk, key)


def oath(session, operation, disposition):
    for grant in Grant:
        with session.case(f"transport.PCSC.OATH.{operation.value}.{disposition.value}.{grant.value}",
                ("T14", "A10", "A11", "A14", "A15", "G10", "G11", "G14", "X11"),
                effects=("applet_reset", "pin_change", "config_change", "create_oath_record")):
            require_backend(session)
            secret = setup(session)
            try:
                with transition(session, operation, disposition):
                    selected = lock(session)
                    if grant in (Grant.CODE, Grant.BOTH):
                        unlock(session, 2, secret, selected)
                    if grant in (Grant.PIN, Grant.BOTH):
                        session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                    oath_grants(session, grant)
                if disposition != Disposition.LEAVE:
                    session.select("oath", required=True)
                oath_grants(session, grant if disposition == Disposition.LEAVE else Grant.NONE)
                unlock(session, 2, secret)
                session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                private_record(session)
                known_record(session, NAME, 0)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)


def oath_grants(session, grant):
    session.check("PC/SC OATH code latch is independent of its PIN latch", session.apdu(codec.apdu(0xa1)).status,
        0x9000 if grant in (Grant.CODE, Grant.BOTH) else 0x6982)
    session.check("PC/SC OATH private record requires both surviving latches",
        session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x9000 if grant == Grant.BOTH else 0x6982)


def run(session):
    for operation, disposition in product(Operation, Disposition):
        for applet in (piv, openpgp, oath):
            applet(session, operation, disposition)
