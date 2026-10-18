# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every applet rejects next to already populated private neighbors and a live lock."""
from . import codec
from .apdu_dispatch import READS
from .cross_reset import Fixtures
from .fido import info
from .otp import oath_open
from .otp_states import commands, config
from .piv_lifecycle import wire_pin
from .vendor_matrix import point, vacant


def reject(session, fixture, applet, kind):
    if applet == "oath":
        oath_open(session)
    else:
        session.select(applet, required=True)
    if kind == "unknown-INS":
        session.check("known applet has its exact unsupported-instruction rejection",
            session.apdu(codec.apdu(0xee, cla=0x80 if applet == "rescue" else 0)).status, 0x6d00)
    elif applet == "piv":
        before = fixture.piv.get_pin_metadata().attempts_remaining
        session.check("PIV invalid VERIFY mode is refused before PIN comparison", session.apdu(codec.apdu(0x20, 1, 0x80, wire_pin(session.options.piv_pin))).status, 0x6a80)
        session.check("PIV parser refusal keeps its exact retry budget", fixture.piv.get_pin_metadata().attempts_remaining, before)
    elif applet == "openpgp":
        before = fixture.pgp.get_data(0xc4)
        session.check("OpenPGP invalid VERIFY mode has its parameter refusal", session.apdu(codec.apdu(0x20, 1, 0x81, session.options.openpgp_pin.encode())).status, 0x6b00)
        session.check("OpenPGP parser refusal preserves all retry records", fixture.pgp.get_data(0xc4), before)
    elif applet == "oath":
        session.check("OATH rejects oversized challenge against a populated known secret",
            session.apdu(codec.apdu(0xa2, data=codec.tlv(0x71, fixture.oath_name) + codec.tlv(0x74, bytes(65)))).status, 0x6a80)
    elif applet == "otp":
        command, _, offset = commands(session.options.otp_slot)
        bad = bytearray(config(fixture.otp_key))
        bad[-1] ^= 1
        before = session.card_value(session.apdu(codec.apdu(3)))
        session.check("OTP rejects CRC without replacing its populated secret", session.apdu(codec.apdu(1, command, offset, bytes(bad) + bytes(6))).status, 0x6700)
        session.check("OTP rejection cannot advance program sequence or change slot flags", session.card_value(session.apdu(codec.apdu(3))), before)
    elif applet == "management":
        body = codec.tlv(3, fixture.config[3])
        session.check("management rejects a valid identical write without its known lock code", session.apdu(codec.apdu(0x1c, data=bytes([len(body)]) + body)).status, 0x6986)
    elif applet == "fido":
        session.require(info(session).get(4, {}).get("clientPin"), "missing-authority refusal needs the configured host PIN")
        session.check("FIDO missing authorization cannot inherit a neighbor's grants", session.ctap(10, {1: 1}).status, 0x36)
    elif applet == "vendor":
        vacant(session)
        value = point()
        value[-2] = value[-2][:-1]
        session.check("vendor rejects a single coordinate width defect", session.ctap(0x41, {1: 1, 2: {1: value}}).status, 2)
    else:
        session.check("rescue refuses short digest before requesting a signature", session.apdu(codec.apdu(0x10, 1, data=bytes(31), cla=0x80)).status, 0x6700)


def run(session):
    for applet in READS:
        for kind in ("unknown-INS", "known-command"):
            fixture = Fixtures(session)
            with session.case(f"cross.rejection.{applet}.{kind}.populated-neighbors", ("X01", "X12", "G03", "G09", "G10", "G13", "G14"),
                    effects=("replace_piv_slot_82", "replace_openpgp_sig_key", "create_fido_credential", "create_oath_record", "replace_otp_slot_" + str(session.options.otp_slot), "config_change"), touch=True):
                try:
                    fixture.prepare()
                    reject(session, fixture, applet, kind)
                    fixture.verify(None)
                finally:
                    if fixture.config is not None and not session.broken:
                        session.trace.phase = "cleanup"
                        fixture.cleanup(None)
