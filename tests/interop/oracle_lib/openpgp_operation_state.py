# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Private-operation references, empty slots and persisted counter ownership."""
from itertools import product
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec, pgp_keys
from .card_keys import private_operation
from .lifecycle import Action, change
from .openpgp_operations import operation_key, sign


def grammar(session):
    from yubikit.openpgp import KEY_REF
    for slot, mode, authorized in product((KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT), (0, 1), (False, True)):
        for defect in ("empty-key", "P1", "P2", "both", "invalid-mode"):
            with session.case(f"openpgp.private-state.{slot.name}.mode-{mode}.authorized-{authorized}.{defect}", ("O02", "O11", "O12", "O13", "O15", "O19", "O22", "G04", "G09", "G10", "G13", "G14"), effects=("replace_openpgp_keys", "config_change"), touch=True):
                with operation_key(session, slot, "SECP256R1", mode) as (sdk, private):
                    if defect == "empty-key":
                        pgp_keys.delete_key(session, sdk, slot)
                    required = 0x81 if slot == KEY_REF.SIG else 0x82
                    session.card_value(session.apdu(codec.apdu(0x20, 0xff, required)))
                    if authorized:
                        sdk.verify_pin(session.options.openpgp_pin, extended=required == 0x82)
                    before = sdk.get_signature_counter()
                    ins, p1, p2, body = (0x88, 0, 0, session.fixture("OpenPGP.AUT.syntax")) if slot == KEY_REF.AUT else (0x2a, 0x9e, 0x9a, session.fixture("OpenPGP.SIG.syntax")) if slot == KEY_REF.SIG else (0x2a, 0x80, 0x86, b"\xa6\x00")
                    if defect == "P1":
                        p1 = 255
                    elif defect == "P2":
                        p2 = 255
                    elif defect == "both":
                        p1 = p2 = 255
                    elif defect == "invalid-mode":
                        ins, p1, p2 = 0x2a, 0x86, 0x81
                    expected = 0x6985 if authorized else 0x6982
                    if defect != "empty-key":
                        expected = 0x6b00 if slot == KEY_REF.AUT and defect != "invalid-mode" else 0x6a86
                    session.check("operation mode/reference validation and empty-key refusal are exact", session.apdu(codec.apdu(ins, p1, p2, body)).status, expected)
                    session.check("private-operation refusal never increments SIG counter", sdk.get_signature_counter(), before)
                    spent = slot == KEY_REF.SIG and mode == 0 and authorized and defect == "empty-key"
                    session.check("only a valid SIG command with standing PW1 consumes one-shot state", session.apdu(codec.apdu(0x20, p2=required)).status, 0x9000 if authorized and not spent else 0x63c0 | min(sdk.get_data(0xc4)[4], 15))
                    if defect == "empty-key":
                        sdk.verify_admin(session.options.openpgp_admin)
                        pgp_keys.put_key(session, sdk, slot, private)
                    sdk.verify_pin(session.options.openpgp_pin, extended=required == 0x82)
                    private_operation(session, sdk, slot, private.public_key(), "SECP256R1")


def counters(session):
    from yubikit.openpgp import KEY_REF
    for slot, origin, action in product((KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT), ("import", "generate"), Action):
        with session.case(f"openpgp.counter.replace-{slot.name}.{origin}.{action.value}", ("O09", "O10", "O11", "O12", "O13", "O22", "X11", "G09", "G14"), effects=("replace_openpgp_keys", "config_change", "reboot") if action == Action.POWER_CYCLE else ("replace_openpgp_keys", "config_change"), touch=True):
            with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, original):
                extra = False
                try:
                    sdk.verify_pin(session.options.openpgp_pin)
                    for index in range(3):
                        sign(session, KEY_REF.SIG, original.public_key(), session.fixture("OpenPGP.counter." + str(index)))
                    session.check("three real signatures start the counter witness", sdk.get_signature_counter(), 3)
                    change(session, action)
                    session.select("openpgp")
                    session.check("signature counter survives every connection action", sdk.get_signature_counter(), 3)
                    sdk.verify_admin(session.options.openpgp_admin)
                    if origin == "import":
                        replacement = ec.derive_private_key(130 + int(slot), ec.SECP256R1())
                        public = replacement.public_key()
                        pgp_keys.put_key(session, sdk, slot, replacement)
                    else:
                        public = pgp_keys.generate(session, sdk, slot, "SECP256R1")
                    extra = slot != KEY_REF.SIG
                    session.check("only replacing SIG resets its counter", sdk.get_signature_counter(), 0 if slot == KEY_REF.SIG else 3)
                    sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                    private_operation(session, sdk, slot, public, "SECP256R1")
                    session.check("non-SIG replacement and private use leave SIG counter untouched", sdk.get_signature_counter(), 1 if slot == KEY_REF.SIG else 3)
                finally:
                    if extra and not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        pgp_keys.delete_key(session, sdk, slot)


def run(session):
    grammar(session)
    counters(session)
