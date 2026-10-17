# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Command and response chaining around an existing OpenPGP certificate object."""
from . import codec
from .openpgp_lifecycle import fixture_session, request


def write_chain(session, data, chunk, defect=None):
    pieces = [data[offset:offset + chunk] for offset in range(0, len(data), chunk)] or [b""]
    for index, piece in enumerate(pieces):
        final = index == len(pieces) - 1
        ins, p1, p2 = 0xDA, 0x7F, 0x21
        if final and defect == "different-INS":
            ins = 0xDB
        elif final and defect == "different-P1":
            p1 = 0x7E
        elif final and defect == "different-P2":
            p2 = 0x22
        if index == 1 and defect == "intervening-SELECT":
            session.select("openpgp")
        reply = session.apdu(codec.apdu(ins, p1, p2, piece, cla=0 if final else 0x10), "openpgp.certificate.chain")
        if not final:
            session.card_value(reply)
    return reply


def run(session):
    for size in (0, 1, 127, 128, 254, 255, 256, 1024, 2048, 4095, 4096):
        for chunk in (127, 255):
            with session.case(f"transport.APDU.command-chain.size-{size}.chunk-{chunk}", ("T11", "T12", "T13", "O16", "G03", "G14"), effects=("write_and_restore_openpgp_certificate",)):
                sdk = fixture_session(session)
                selector = bytes.fromhex("60045c027f21")
                request(session, 0xA5, 0, 4, selector)
                original = sdk.get_data(0x7F21)
                fixture = session.fixture("chained.certificate", size)
                try:
                    result = write_chain(session, fixture, chunk)
                    if result.protocol == "success":
                        session.check("complete chain writes exact certificate", sdk.get_data(0x7F21), fixture)
                    else:
                        session.check("command-chain refusal is an applet error", result.protocol, "applet_error")
                        session.observe("object_limit_refusal", result.status)
                        session.check("oversize chain preserves prior object", sdk.get_data(0x7F21), original)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(0x7F21, original)
                        session.check("certificate restored after chain", sdk.get_data(0x7F21), original)
    for defect in ("different-INS", "different-P1", "different-P2", "intervening-SELECT"):
        with session.case("transport.APDU.command-chain." + defect, ("T12", "O16", "G12", "G14"), effects=("write_and_restore_openpgp_certificate",)):
            sdk = fixture_session(session)
            original = sdk.get_data(0x7F21)
            try:
                sdk.put_data(0x7F21, b"oracle-chain-marker")
                data = session.fixture("chain.invalid", 300)
                result = write_chain(session, data, 127, defect)
                if defect == "intervening-SELECT" and result.protocol == "success":
                    session.check("SELECT discards the old chain prefix", sdk.get_data(0x7F21), data[127:])
                else:
                    session.check("interrupted or mismatched chain refused", result.protocol, "applet_error")
                    session.check("rejected chain preserves certificate", sdk.get_data(0x7F21), b"oracle-chain-marker")
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.verify_admin(session.options.openpgp_admin)
                    sdk.put_data(0x7F21, original)
