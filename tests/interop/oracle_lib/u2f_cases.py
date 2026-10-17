# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""U2F malformed references, controls and both ISO7816 encodings."""
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .fido import u2f_apdu, verified


def run(session):
    for transport in ("hid", "card"):
        for request, label in ((bytes.fromhex("00030000"), "bare"), (bytes.fromhex("0003000000"), "short-Le"),
                               (u2f_apdu(3), "extended"), (u2f_apdu(3, data=b"\x00"), "extra-data")):
            with session.case(f"u2f.VERSION.{transport}.{label}", ("U01", "T11", "G05", "G14")):
                if transport == "card":
                    session.select("fido")
                    reply = session.apdu(request, "u2f.card.VERSION")
                else:
                    reply = session.hid_call(3, request, "u2f.hid.VERSION")
                session.observe("VERSION.encoding.status", reply.status)
                if label == "extra-data":
                    session.check("VERSION forbids command data", reply.status, 0x6700)
                elif label == "extended" or transport == "card":
                    session.check("U2F VERSION value", session.card_value(reply), b"U2F_V2")
    for defect in ("wrong-application", "damaged-handle", "unknown-handle", "empty-handle", "reserved-control", "short-body", "length-mismatch"):
        with session.case("u2f.AUTH.reference." + defect, ("U03", "U04", "U05", "U06", "G03", "G09", "G14"), touch=True):
            session.require("u2f.fixture" in session.values, "run the u2f fixture suite first")
            fixture = session.values["u2f.fixture"]
            handle, application, challenge = fixture["handle"], fixture["application"], fixture["challenge"]
            damaged, rp, mode = handle, application, 7
            if defect == "wrong-application":
                rp = bytes([application[0] ^ 1]) + application[1:]
            elif defect == "damaged-handle":
                damaged = bytes([handle[0] ^ 1]) + handle[1:]
            elif defect == "unknown-handle":
                damaged = session.fixture("u2f.unknown", len(handle))
            elif defect == "empty-handle":
                damaged = b""
            elif defect == "reserved-control":
                mode = 0xFF
            payload = challenge + rp + bytes([len(damaged)]) + damaged
            if defect == "short-body":
                payload = payload[:63]
            elif defect == "length-mismatch":
                payload = payload[:-1]
            result = session.hid_call(3, u2f_apdu(2, mode, payload), "u2f.AUTH." + defect)
            session.check("invalid U2F reference/control refused", result.protocol, "applet_error")
            session.observe("refusal_status", result.status)
            valid = challenge + application + bytes([len(handle)]) + handle
            control = session.card_value(session.hid_call(3, u2f_apdu(2, 3, valid), "u2f.AUTH.valid-control"))
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fixture["public_key"])
            verified(session, "U2F key remains usable after refusal", public, -7, control[5:], application + control[:5] + challenge)
