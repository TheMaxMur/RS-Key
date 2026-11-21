# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Attestation origin and validation order retain certificates, counters and keys."""
from itertools import product

from . import codec, pgp_keys
from .card_keys import private_operation
from .cards import encoded_public, fixture_key
from .openpgp_uif import attest, generated


def inputs(slot):
    yield "valid", 0x80, int(slot), 0, b"", None
    yield "wrong-CLA", 0, int(slot), 0, b"", 0x6e00
    for reference in (0, 4, 0x80, 0x81, 0xa4, 0xb6, 0xb8, 255):
        yield f"unknown-reference-{reference}", 0x80, reference, 0, b"", 0x6a80
    for p2 in (1, 127, 128, 255):
        yield f"P2-{p2}", 0x80, int(slot), p2, b"", 0x6a80
    for size in (1, 2, 16, 127, 128, 255):
        yield f"body-length-{size}", 0x80, int(slot), 0, bytes(size), 0x6a80
    yield "CLA-before-reference", 0, 255, 0, b"", 0x6e00
    yield "body-before-reference", 0x80, 255, 0, b"x", 0x6a80


def run(session):
    from yubikit.openpgp import KEY_REF
    for slot, origin, mode, authorized in product((KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT), ("generated", "imported", "empty"), (0, 1), (False, True)):
        for label, cla, p1, p2, body, invalid in inputs(slot):
            with session.case(f"openpgp.ATTEST.{slot.name}.{origin}.mode-{mode}.PW81-{authorized}.{label}", ("O02", "O09", "O10", "O19", "O20", "O22", "G01", "G03", "G04", "G09", "G10", "G13", "G14"),
                    effects=("replace_openpgp_keys", "config_change", "write_openpgp_certificates"), touch=True):
                session.require(session.profile == "rsk", "attestation input/origin precedence requires RS-Key", "excluded_by_profile")
                with generated(session, slot, mode) as (sdk, public, occurrence):
                    if origin == "imported":
                        key = fixture_key(session, "SECP256R1")
                        pgp_keys.put_key(session, sdk, slot, key)
                        public = key.public_key()
                    elif origin == "empty":
                        pgp_keys.delete_key(session, sdk, slot)
                    before, old_cert = sdk.get_signature_counter(), sdk.get_data(0x7f21)
                    if authorized:
                        sdk.verify_pin(session.options.openpgp_pin)
                    else:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x81)))
                        sdk.verify_admin(session.options.openpgp_admin)
                    expected = 0x6982 if not authorized else invalid if invalid is not None else 0x9000 if origin == "generated" else 0x6985
                    attest(session, sdk, slot, public, occurrence, expected, codec.apdu(0xfb, p1, p2, body, cla=cla))
                    spent = authorized and mode == 0 and cla == 0x80 and p2 == 0 and not body
                    left = sdk.get_data(0xc4)[4]
                    session.check("ATTEST spends one-shot PW1 only past class/body and touch gates", session.apdu(codec.apdu(0x20, p2=0x81)).status, 0x9000 if authorized and not spent else 0x63c0 | min(left, 15))
                    session.check("ATTEST success and all refusals leave SIG counter untouched", sdk.get_signature_counter(), before)
                    if expected != 0x9000:
                        session.card_value(session.apdu(codec.apdu(0xa5, occurrence, 4, bytes.fromhex("60045c027f21"))))
                        session.check("refused ATTEST leaves original selected certificate exact", sdk.get_data(0x7f21), old_cert)
                    if origin != "empty":
                        session.check("attestation refusal never replaces the subject public key", encoded_public(sdk.get_public_key(slot)), encoded_public(public))
                        sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                        private_operation(session, sdk, slot, public, "SECP256R1")
                    else:
                        session.check("empty origin remains empty after refused ATTEST", session.apdu(codec.apdu(0x47, 0x81, data=slot.crt)).status, 0x6a88)
                    sdk.verify_admin(session.options.openpgp_admin)
                    public = pgp_keys.generate(session, sdk, slot, "SECP256R1")
                    sdk.verify_pin(session.options.openpgp_pin)
                    attest(session, sdk, slot, public, occurrence)
