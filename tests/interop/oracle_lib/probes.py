# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Non-authenticating observations and parser rejection probes."""
from . import codec
from .runner import AIDS
from .transport import HID_PING
from .trace import Outcome, TransferError

OPENPGP_DOS = (
    0x4F, 0x5B, 0x5E, 0x65, 0x6E, 0x73, 0x7A, 0x93, 0xC0, 0xC1, 0xC2, 0xC3,
    0xC4, 0xC5, 0xC6, 0xCD, 0xD3, 0xD6, 0xD7, 0xD8, 0xD9, 0xDE, 0xF9, 0xFA,
    0xFC, 0x5F2D, 0x5F35, 0x5F50, 0x5F52, 0x7F21, 0x7F66,
    0x101, 0x102, 0x103, 0x104,
)
PIV_OBJECTS = (0x5FC102, 0x5FC107, 0x5FC105, 0x5FC10A, 0x5FC10B, 0x5FC101, 0x5FFF01,
               0x5FC103, 0x5FC106, 0x5FC108, 0x5FC109, 0x5FC10C, 0x5FC121, *range(0x5FC10D, 0x5FC121))
PIV_SLOTS = (0x80, 0x81, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0xF9, *range(0x82, 0x96))


def observe_reply(session, reply, name="response", variable=False):
    session.observe("protocol", reply.protocol)
    session.observe("status", reply.status)
    session.observe(name, reply.data, "presence" if variable else "exact")


def fido(session):
    for length in (0, 1, 56, 57, 58, 115, 116, 1024, 7609):
        with session.case(f"transport.ping.{length}", ("T03", "T04")):
            data = session.fixture("ping", length)
            reply = session.hid_call(HID_PING, data, "ctaphid.ping")
            session.observe("protocol", reply.protocol)
            session.observe("status", reply.status)
            if reply.protocol == "success":
                session.check("echo", reply.data, data)
    with session.case("fido.getinfo", ("F01",)):
        info = session.ctap_value(session.ctap(4))
        session.bind("fido.info", info)
        stable = {key: value for key, value in info.items() if key not in (3, 0x19, 0x1E)}
        session.observe("capabilities", stable)
        for key, name in ((3, "aaguid"), (0x19, "encIdentifier"), (0x1E, "encCredStoreState")):
            if key in info:
                session.observe(name, info[key], "presence")
        session.check("versions array", isinstance(info.get(1), list))
    for protocol in (1, 2):
        for subcommand, label in ((1, "retries"), (2, "key-agreement"), (7, "uv-retries")):
            with session.case(f"fido.pin.{protocol}.{label}", ("F02", "F03", "F08")):
                reply = session.ctap(6, {1: protocol, 2: subcommand})
                session.observe("status", reply.status)
                if reply.status == 0:
                    value = session.ctap_value(reply)
                    if subcommand == 2:
                        from .fido import PinProtocol
                        key = value[1]
                        session.check("P256 key-agreement point shape", (key[1], key[3], key[-1], len(key[-2]), len(key[-3])), (2, -25, 1, 32, 32))
                        PinProtocol(protocol, key)
                    session.observe("value", value, "presence" if subcommand == 2 else "exact")
    for command, label in ((1, "make"), (2, "assert"), (6, "pin"), (10, "credential-management"), (13, "config")):
        for name, raw in (("empty-map", b"\xa0"), ("wrong-type", b"\x80"), ("truncated-map", b"\xa1")):
            with session.case(f"fido.invalid.{label}.{name}", ("G01", "G02", "G05", "F01")):
                try:
                    reply = session.ctap(command, raw=raw)
                except TransferError as error:
                    if session.profile == "trezor" and error.outcome == Outcome.HOST_REJECTED and not error.transmitted:
                        session.require(False, "wallet routing guard prevents this ambiguous encoding")
                    raise
                observe_reply(session, reply)
                session.check("incomplete request refused", reply.protocol != "success")
    with session.case("fido.next-without-begin", ("F13",)):
        reply = session.ctap(8)
        observe_reply(session, reply)
        session.check("no active assertion walk", reply.protocol != "success")
    with session.case("fido.largeblobs.read", ("F19",)):
        reply = session.ctap(12, {1: 64, 3: 0})
        observe_reply(session, reply)


def select_catalog(session):
    for name in AIDS:
        if session.profile == "trezor":
            continue
        with session.case(f"select.{name}", ("T11", "G09")):
            reply = session.apdu(codec.apdu(0xA4, 4, data=AIDS[name]), f"select.{name}")
            session.bind(f"applet.{name}.status", reply.status)
            observe_reply(session, reply, variable=name in ("oath", "piv", "rescue"))


def card_reads(session, applet, requests):
    for label, request, families, variable in requests:
        with session.case(f"{applet}.{label}", families):
            session.select(applet)
            reply = session.apdu(request)
            observe_reply(session, reply, variable=variable)


def openpgp(session):
    requests = [(f"get-data.{tag:04x}", codec.apdu(0xCA, tag >> 8, tag & 255), ("O01", "O07"),
                 tag not in (0xC0, 0xC4, 0x5F52, 0x7F66)) for tag in OPENPGP_DOS]
    requests.extend((f"challenge.{length}", codec.apdu(0x84, le=length), ("O17",), True)
                    for length in (1, 8, 32, 64, 256))
    requests.extend((f"pw-status.{reference:02x}", codec.apdu(0x20, p2=reference), ("O02",), False)
                    for reference in (0x81, 0x82, 0x83))
    card_reads(session, "openpgp", requests)


def piv(session):
    requests = [("version", codec.apdu(0xFD), ("P01",), False),
                ("serial", codec.apdu(0xF8), ("P01",), True),
                ("pin-status", codec.apdu(0x20, p2=0x80), ("P03",), False)]
    requests.extend((f"metadata.{slot:02x}", codec.apdu(0xF7, p2=slot), ("P02",), True) for slot in PIV_SLOTS)
    requests.extend((f"object.{tag:06x}", codec.apdu(0xCB, 0x3F, 0xFF, codec.tlv(0x5C, tag.to_bytes(3, "big"))),
                     ("P13",), True) for tag in PIV_OBJECTS)
    requests.extend((f"invalid-body.{ins:02x}", codec.apdu(ins, data=b"\x00"), ("G03", "G13"), False)
                    for ins in (0x20, 0x87, 0x47, 0xCB, 0xDB, 0xF7, 0xFD))
    card_reads(session, "piv", requests)


def oath(session):
    card_reads(session, "oath", [
        ("list", codec.apdu(0xA1), ("A03",), True),
        ("remaining-without-begin", codec.apdu(0xA5), ("A08",), False),
        ("invalid-list-parameters", codec.apdu(0xA1, p1=1), ("G13", "A03"), False),
        ("unknown-name", codec.apdu(0xA2, p2=1, data=codec.tlv(0x71, b"oracle.missing") + codec.tlv(0x74, b"\x00" * 8)), ("A04",), False),
    ])


def otp(session):
    requests = [("status", codec.apdu(3), ("Y01",), False)]
    requests.extend((label, codec.apdu(1, p1=command), ("Y01",), command == 0x10)
                    for label, command in (("serial", 0x10), ("config", 0x13), ("status-extended", 0x14)))
    card_reads(session, "otp", requests)
    for command, label, expected_len in ((-1, "status", 0), (0x10, "serial", 4)):
        with session.case(f"otp.hid.{label}", ("T15", "Y01")):
            observe_reply(session, session.otp_call(command, expected_len=expected_len), variable=command == 0x10)


def management(session):
    card_reads(session, "management", [("read-config", codec.apdu(0x1D), ("M01",), True)])
    if session.profile in ("rsk", "yubikey"):
        with session.case("management.hid-read-config", ("M01", "M05")):
            observe_reply(session, session.hid_call(0x42, name="management.read-config"), variable=True)


def rsk(session):
    if session.profile != "rsk":
        with session.case("rsk.profile", ("V01", "R01")):
            session.require(False, "RS-Key vendor commands do not apply to this profile", "excluded_by_profile")
        return
    requests = [(f"status.{p1:02x}.{p2:02x}", codec.apdu(0x1E, p1, p2, cla=0x80), ("R01", "R04"), p1 in (1, 2, 4))
                for p1, p2 in ((1, 0), (2, 0), (3, 0), (4, 1), (4, 2), (6, 0), (7, 0), (8, 0))]
    requests.append(("public-key", codec.apdu(0x10, 2, cla=0x80), ("R02",), True))
    card_reads(session, "rescue", requests)
    card_reads(session, "vendor", [("counter", codec.apdu(2), ("V11",), False),
                                    ("led", codec.apdu(0x11), ("V12",), False)])
    for subcommand, name in ((5, "backup-state"), (11, "attestation-state"), (15, "config-commands")):
        with session.case(f"rsk.{name}", ("V02", "V06", "V10")):
            reply = session.ctap(0x41, {1: subcommand})
            observe_reply(session, reply)
    for target in (1, 2):
        with session.case(f"rsk.config-read.{target}", ("V09",)):
            observe_reply(session, session.ctap(0x41, {1: 13, 2: {1: target}}))


READ_SUITES = {"fido": fido, "select": select_catalog, "oath": oath, "otp": otp,
               "piv": piv, "openpgp": openpgp, "management": management, "rsk": rsk}
