# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A lost answer triggers readback, never a replay of the unknown mutation."""
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .lifecycle import Action, change, require_action
from .trace import TransferError


def require_loss(session):
    session.require(session.profile == "rsk", "uncertain-write recovery contracts require RS-Key", "excluded_by_profile")
    require_action(session, Action.RECONNECT)
    session.require(hasattr(session.card, "drop_response"), "backend has no defined pre-response loss boundary", "excluded_by_mode")


def lose(session, instruction, operation, *, recovery=Action.RECONNECT):
    require_loss(session)
    backend, sent = session.card, []
    class LossCard:
        def __getattr__(self, name):
            return getattr(backend, name)
        def transfer(self, request, deadline, observe):
            if len(request) >= 4 and request[1] == instruction and not request[0] & 0x10 and not sent:
                sent.append(bytes(request))
                session.current.uncertain_write = True
                session.trace.emit("fault_injected", fault="host_response_loss", instruction=instruction,
                    boundary="backend API invocation or socket/USB write before response delivery", physical_power_cut=False, mutator_replayed=False)
                return backend.drop_response(request, deadline, observe)
            return backend.transfer(request, deadline, observe)
    session.card = LossCard()
    try:
        try:
            operation()
        except TransferError as error:
            session.check("unknown write reached exactly the selected loss boundary", error.protocol, "injected_response_loss")
        else:
            session.check("unknown write must not fabricate a completed answer", False)
    finally:
        session.card = backend
    session.check("unknown mutation was transmitted at most once", len(sent), 1)
    session.observe("unknown_write", {"instruction": instruction, "request_sha256": hashlib.sha256(sent[0]).hexdigest(),
        "commit_status": "unknown until explicit scenario readback", "replayed": False})
    if recovery is not None:
        change(session, recovery)


def classify(session, name, actual, before, after):
    if actual != before and actual != after:
        session.broken = True
        session.values["halt_reason"] = "unknown mutation has neither complete old nor new state; no further mutation or replay is permitted"
    session.check(name + " has one complete old or new value", actual == before or actual == after)
    session.observe(name + ".readback", {"outcome": "unchanged" if actual == before else "committed", "partial": False, "mutation_replayed": False})


def piv_keys(session):
    from yubikit.piv import SLOT, KEY_TYPE
    from .cards import encoded_public
    from .card_pin_matrix import piv_sign
    from .piv_matrix import key_fixture
    from .piv_objects import read, write
    for operation in ("object", "import", "generate", "delete"):
        with session.case("cross.unknown-write.PIV." + operation, ("X10", "X12", "P09", "P10", "P11", "P12", "P13", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "replace_piv_slot_82", "write_and_restore_piv_object"), touch=True):
            require_loss(session)
            with key_fixture(session) as (sdk, old):
                replacement = ec.derive_private_key(int.from_bytes(session.fixture("unknown.PIV.replacement", 24), "big") + 1, ec.SECP256R1()) if operation == "import" else None
                before = read(session, 0x5f0077) if operation == "object" else encoded_public(old.public_key())
                marker = b"oracle-unknown-PIV-object"
                try:
                    sdk.authenticate(session.options.management_key)
                    if operation == "object":
                        lose(session, 0xdb, lambda: write(session, 0x5f0077, marker))
                    elif operation == "import":
                        lose(session, 0xfe, lambda: sdk.put_key(SLOT(0x82), replacement))
                    elif operation == "generate":
                        lose(session, 0x47, lambda: sdk.generate_key(SLOT(0x82), KEY_TYPE.ECCP256))
                    else:
                        lose(session, 0xf6, lambda: sdk.delete_key(SLOT(0x82)))
                    session.select("piv")
                    sdk.verify_pin(session.options.piv_pin)
                    if operation == "object":
                        classify(session, "PIV object", read(session, 0x5f0077), before, marker)
                        piv_sign(session, sdk, old)
                    else:
                        result = session.apdu(codec.apdu(0xf7, p2=0x82))
                        session.check("unknown key mutation leaves present metadata or an actual deletion", result.status in (0x9000, 0x6a88))
                        if result.status == 0x6a88:
                            session.check("only DELETE may remove the populated key", operation, "delete")
                            session.check("deleted private key cannot sign", session.apdu(codec.apdu(0x87, 0x11, 0x82, codec.tlv(0x7c, codec.tlv(0x82, b"") + codec.tlv(0x81, bytes(32))))).status, 0x6a88)
                        else:
                            public = sdk.get_slot_metadata(SLOT(0x82)).public_key
                            encoded = encoded_public(public)
                            if operation == "import":
                                classify(session, "PIV imported key", encoded, before, encoded_public(replacement.public_key()))
                            elif operation == "delete":
                                session.check("uncommitted DELETE retains the exact old public key", encoded, before)
                            else:
                                session.observe("PIV generated-key readback", "old key retained" if encoded == before else "new key committed; response was lost")
                            from .card_keys import private_operation
                            private_operation(session, sdk, SLOT(0x82), public, "ECCP384" if public.curve.key_size == 384 else "ECCP256", piv=True)
                finally:
                    if operation == "delete" and not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("piv")
                        sdk.authenticate(session.options.management_key)
                        if session.apdu(codec.apdu(0xf7, p2=0x82)).status == 0x6a88:
                            sdk.put_key(SLOT(0x82), old)
                    if operation == "object" and not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("piv")
                        sdk.authenticate(session.options.management_key)
                        session.card_value(write(session, 0x5f0077, before))
                        session.check("unknown PIV object fixture is restored", read(session, 0x5f0077), before)


def oath_records(session):
    from .oath_matrix import records
    from .oath_access import known_record
    from .otp import OATH_HASHES, oath_open, oath_names, oath_request
    first, second = b"oracle-unknown-OATH", b"oracle-unknown-renamed"
    for operation in ("create", "replace", "delete", "rename"):
        with session.case("cross.unknown-write.OATH." + operation, ("X10", "X12", "A02", "A03", "A04", "A09", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "create_oath_record")):
            require_loss(session)
            secret = OATH_HASHES[0][2]
            with records(session, [] if operation == "create" else [(first, codec.tlv(0x73, b"\x21\x06" + secret))]):
                names = oath_names(session)
                session.require(first not in names if operation == "create" else second not in names, "unknown-write fixture name collides")
                try:
                    wire = codec.apdu(1, data=codec.tlv(0x71, first) + codec.tlv(0x73, b"\x21\x06" + (secret[::-1] if operation == "replace" else secret))) if operation in ("create", "replace") else codec.apdu(2, data=codec.tlv(0x71, first)) if operation == "delete" else codec.apdu(5, data=codec.tlv(0x71, first) + codec.tlv(0x71, second))
                    lose(session, wire[1], lambda: session.apdu(wire))
                    oath_open(session)
                    current = oath_names(session)
                    expected = names | {first} if operation == "create" else names - {first} if operation == "delete" else (names - {first}) | {second} if operation == "rename" else names
                    classify(session, "OATH name set", current, names, expected)
                    if operation == "replace":
                        response = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, first) + codec.tlv(0x74, bytes(8)))))[0x75]
                        classify(session, "OATH replaced secret", response, b"\x06" + hmac.digest(secret, bytes(8), "sha1"), b"\x06" + hmac.digest(secret[::-1], bytes(8), "sha1"))
                    elif first in current or second in current:
                        known_record(session, second if second in current else first, 0)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        oath_open(session)
                        current = oath_names(session)
                        if second in current:
                            oath_request(session, 2, codec.tlv(0x71, second))
                        if operation == "create" and first in current:
                            oath_request(session, 2, codec.tlv(0x71, first))
                        elif operation != "create" and first not in current:
                            oath_request(session, 1, codec.tlv(0x71, first) + codec.tlv(0x73, b"\x21\x06" + secret))


def openpgp_keys(session):
    from yubikit.openpgp import KEY_REF
    from . import pgp_keys
    from .cards import encoded_public
    from .card_pin_matrix import pgp_sign
    from .openpgp_operations import operation_key, sign
    for operation in ("object", "import", "generate", "delete"):
        with session.case("cross.unknown-write.OpenPGP." + operation, ("X10", "X12", "O06", "O07", "O08", "O09", "O10", "O11", "O22", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "replace_openpgp_keys", "config_change", "write_and_restore_openpgp_DO"), touch=True):
            require_loss(session)
            with operation_key(session, KEY_REF.SIG, "SECP256R1") as (sdk, old):
                sdk.verify_pin(session.options.openpgp_pin)
                pgp_sign(session, sdk, old)
                original = sdk.get_data(0x5e)
                marker = b"oracle-unknown-OpenPGP-object"
                replacement = ec.derive_private_key(int.from_bytes(session.fixture("unknown.OpenPGP.replacement", 24), "big") + 1, ec.SECP256R1())
                try:
                    sdk.verify_admin(session.options.openpgp_admin)
                    if operation == "object":
                        lose(session, 0xda, lambda: sdk.put_data(0x5e, marker))
                    elif operation == "import":
                        lose(session, 0xdb, lambda: pgp_keys.put_key(session, sdk, KEY_REF.SIG, replacement))
                    elif operation == "generate":
                        lose(session, 0x47, lambda: pgp_keys.generate(session, sdk, KEY_REF.SIG, "SECP256R1"))
                    else:
                        # One attribute transition is the deletion command; no second transition is retried.
                        lose(session, 0xda, lambda: sdk.put_data(0xc1, b"\x01\x10\x00\x00\x20\x00"))
                    session.select("openpgp")
                    sdk.verify_pin(session.options.openpgp_pin)
                    if operation == "object":
                        classify(session, "OpenPGP personal object", sdk.get_data(0x5e), original, marker)
                        pgp_sign(session, sdk, old)
                    else:
                        result = session.apdu(codec.apdu(0x47, 0x81, data=KEY_REF.SIG.crt))
                        session.check("unknown OpenPGP mutation leaves a complete public key or deletion", result.status in (0x9000, 0x6a88))
                        if result.status == 0x6a88:
                            session.check("only the attribute deletion may remove the OpenPGP key", operation, "delete")
                            session.check("readback-confirmed deletion revokes private signing", session.apdu(codec.apdu(0x2a, 0x9e, 0x9a, bytes(32))).status, 0x6a88)
                        else:
                            public = sdk.get_public_key(KEY_REF.SIG)
                            if operation == "import":
                                classify(session, "OpenPGP imported public key", encoded_public(public), encoded_public(old.public_key()), encoded_public(replacement.public_key()))
                            elif operation == "delete":
                                session.check("uncommitted deletion preserves exact OpenPGP key", encoded_public(public), encoded_public(old.public_key()))
                            sign(session, KEY_REF.SIG, public, session.fixture("unknown.OpenPGP.private-control"))
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("openpgp")
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(0x5e, original)
                        session.check("unknown OpenPGP object fixture is restored", sdk.get_data(0x5e), original)


def run(session):
    piv_keys(session)
    oath_records(session)
    openpgp_keys(session)
