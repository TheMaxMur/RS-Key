# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Each dynamic quota is filled before creating and using other applets' objects."""
from contextlib import ExitStack

from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .binding import require_pair
from .cards import selected_cleanup
from .card_pin_matrix import piv_sign, pgp_sign
from .credential_matrix import owned, metadata
from .fido import authorize
from .fido_fixtures import credential
from .oath_access import known_record
from .oath_matrix import records
from .otp import OATH_HASHES, oath_open, oath_names, oath_request
from .otp_commands import Mode, Route, configure, fixture as otp_fixture, witness, open_route
from .piv_matrix import key_fixture
from .piv_objects import MAX_OBJECT, POOL_BYTES, POOL_SLOTS, read, write

OATH_RECORDS = 255


def neighbors(session, full):
    phase = session.trace.phase
    try:
        _neighbors(session, full)
    finally:
        session.trace.phase = phase


def _neighbors(session, full):
    from yubikit.openpgp import KEY_REF
    from .openpgp_operations import operation_key
    with ExitStack() as stack:
        piv, piv_key = stack.enter_context(selected_cleanup(session, "piv", key_fixture(session)))
        piv.verify_pin(session.options.piv_pin)
        piv_sign(session, piv, piv_key)
        original = read(session, 0x5f0077) if full != "piv" else None
        try:
            if full != "piv":
                session.card_value(write(session, 0x5f0077, b"oracle-independent-PIV-pool"))
                session.check("another applet's full quota does not block a new PIV object", read(session, 0x5f0077), b"oracle-independent-PIV-pool")
            from . import pgp_keys
            from .card_keys import private_operation
            pgp_slots = []
            for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
                pgp, _ = stack.enter_context(selected_cleanup(session, "openpgp", operation_key(session, slot, "SECP256R1")))
                private = ec.derive_private_key(int.from_bytes(session.fixture("cross.quota.OpenPGP." + slot.name, 24), "big") + 1, ec.SECP256R1())
                pgp.verify_admin(session.options.openpgp_admin)
                pgp_keys.put_key(session, pgp, slot, private)
                pgp.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                private_operation(session, pgp, slot, private.public_key(), "SECP256R1")
                pgp_slots.append((slot, pgp, private))
            pgp_key = next(private for slot, _, private in pgp_slots if slot == KEY_REF.SIG)
            pgp.verify_pin(session.options.openpgp_pin)
            old = pgp.get_data(0x5e)
            try:
                pgp.verify_admin(session.options.openpgp_admin)
                pgp.put_data(0x5e, b"oracle-independent-OpenPGP-object")
                session.check("full neighbor quota still permits a complete OpenPGP object", pgp.get_data(0x5e), b"oracle-independent-OpenPGP-object")
                pgp_sign(session, pgp, pgp_key)
            finally:
                if not session.broken:
                    pgp.verify_admin(session.options.openpgp_admin)
                    pgp.put_data(0x5e, old)
            if full != "fido":
                with credential(session, session.current.name + ".neighbor", resident=True) as key:
                    key.assertion(session)
            if full != "oath":
                name = b"oracle-independent-OATH"
                with records(session, [(name, codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))]):
                    known_record(session, name, 0)
            for slot in range(1, 5):
                config = configure(session.fixture("cross.quota.OTP." + str(slot), 20), Mode.HMAC)
                stack.enter_context(selected_cleanup(session, "otp", otp_fixture(session, Route.CARD, slot, config)))
            for slot in range(1, 5):
                open_route(session, Route.CARD, slot)
                witness(session, Route.CARD, slot, configure(session.fixture("cross.quota.OTP." + str(slot), 20), Mode.HMAC))
            session.select("piv")
            piv.authenticate(session.options.management_key)
            fixed = read(session, 0x5fc10a)
            try:
                session.card_value(write(session, 0x5fc10a, b"oracle-after-fixed-slots-full"))
                session.check("full OTP and OpenPGP slots cannot block fixed PIV object creation", read(session, 0x5fc10a), b"oracle-after-fixed-slots-full")
            finally:
                if not session.broken:
                    session.card_value(write(session, 0x5fc10a, fixed))
            session.select("openpgp")
            for slot, sdk, private in pgp_slots:
                sdk.verify_pin(session.options.openpgp_pin, extended=slot != KEY_REF.SIG)
                private_operation(session, sdk, slot, private.public_key(), "SECP256R1")
            if full != "fido":
                with credential(session, session.current.name + ".after-fixed-slots-full", resident=True) as key:
                    key.assertion(session)
            if full != "oath":
                with records(session, [(b"oracle-after-fixed-slots-full", codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))]):
                    known_record(session, b"oracle-after-fixed-slots-full", 0)
        finally:
            if full != "piv" and not session.broken:
                session.select("piv")
                piv.authenticate(session.options.management_key)
                session.card_value(write(session, 0x5f0077, original))
                session.check("neighbor PIV object is restored after quota witness", read(session, 0x5f0077), original)


def ready(session):
    session.require(session.profile == "rsk", "cross quota contracts require RS-Key", "excluded_by_profile")
    require_pair(session)
    session.require(all((session.options.pin, session.options.piv_pin, session.options.management_key,
                         session.options.openpgp_pin, session.options.openpgp_admin)), "all neighbor credentials are required before filling a store")
    neighbors(session, "none")


def oath(session):
    with session.case("cross.quota.OATH-records.other-applet-creation-and-reclaim", ("X07", "X12", "A02", "A03", "A04", "G09", "G14"),
            effects=("capacity", "create_oath_record", "create_fido_credential",
                     "replace_piv_slot_82", "write_and_restore_piv_object", "replace_openpgp_keys", "config_change", "otp_both_slots", "otp_extra_slots"), touch=True):
        ready(session)
        oath_open(session)
        original = oath_names(session)
        session.require(len(original) < OATH_RECORDS, "quota fixture needs at least one owned record to reclaim")
        created, prefix = [], b"oracle-cross-full-" + session.fixture("quota.OATH.namespace", 5).hex().encode()
        try:
            for index in range(OATH_RECORDS - len(original)):
                name = prefix + str(index).encode()
                session.require(name not in original, "cross-quota OATH name collision")
                oath_request(session, 1, codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))
                created.append(name)
            expected = original | set(created)
            overflow = prefix + b"overflow"
            session.check("OATH's own record quota is actually full", session.apdu(codec.apdu(1, data=codec.tlv(0x71, overflow) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))).status, 0x6a84)
            neighbors(session, "oath")
            oath_open(session)
            session.check("neighbor writes preserve every full OATH name", oath_names(session), expected)
            known_record(session, created[0], 0)
            removed = created.pop()
            oath_request(session, 2, codec.tlv(0x71, removed))
            oath_request(session, 1, codec.tlv(0x71, overflow) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))
            created.append(overflow)
            known_record(session, overflow, 0)
            neighbors(session, "oath")
            oath_open(session)
            session.check("reclaimed OATH quota remains independent after more neighbor writes", oath_names(session), original | set(created))
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                oath_open(session)
                for name in created:
                    oath_request(session, 2, codec.tlv(0x71, name))
                session.check("cross-quota OATH names restored", oath_names(session), original)


def fido(session):
    with session.case("cross.quota.FIDO-residents.other-applet-creation-and-reclaim", ("X07", "X12", "F11", "F14", "F17", "G09", "G14"),
            effects=("capacity", "create_fido_credential", "create_oath_record", "replace_piv_slot_82", "write_and_restore_piv_object", "replace_openpgp_keys", "config_change", "otp_both_slots", "otp_extra_slots"), touch=True):
        ready(session)
        with owned(session) as store:
            before = metadata(session)
            session.require(before[1] == 0 and 1 <= before[2] <= 256, "full resident cross-quota fixture needs an empty bounded store")
            for index in range(before[2]):
                store.create(session.current.name + "." + str(index))
            sample = next(iter(store.live.values()))
            query = {1: sample.challenge, 2: {"id": sample.rp}, 3: {"id": b"cross-quota-overflow"}, 4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
            authorize(session, query, 1, sample.rp, sample.challenge, 8, 9)
            session.check("resident quota is actually full before neighbor writes", session.ctap(1, query).status, 0x28)
            neighbors(session, "fido")
            session.check("neighbor creations cannot change full FIDO quota", metadata(session), {1: before[2], 2: 0})
            sample.assertion(session)
            store.delete(sample)
            session.check("one resident deletion reclaims one independent slot", metadata(session)[2], 1)
            replacement = store.create(session.current.name + ".reclaimed")
            neighbors(session, "fido")
            session.check("reclaimed resident slot remains full after neighbor writes", metadata(session)[2], 0)
            replacement.assertion(session)


def piv(session):
    from .piv_lifecycle import reset, fixture_session
    for kind, width in (("bytes", MAX_OBJECT), ("records", 1)):
        prepared = False
        with session.case("cross.quota.PIV-" + kind + ".prepare", ("X07", "P16"), effects=("capacity", "applet_reset")):
            session.require(session.profile == "rsk", "independent PIV quota requires RS-Key", "excluded_by_profile")
            session.observe("quota_setup", "PIV reset establishes independent empty byte/record quota: " + kind)
            prepared = True
        first = len(session.trace.cases)
        if prepared or session.planning:
            with session.namespace("cross.quota.PIV-" + kind + "."):
                reset(session)
        reset_done = any(row["verdict"] == "pass" for row in session.trace.cases[first:])
        with session.case("cross.quota.PIV-" + kind + ".other-applet-creation-and-reclaim", ("X07", "X12", "P13", "G09", "G14"),
                effects=("capacity", "create_fido_credential", "create_oath_record", "replace_piv_slot_82", "write_and_restore_piv_object", "replace_openpgp_keys", "config_change", "otp_both_slots", "otp_extra_slots"), touch=True):
            session.require(reset_done, "cross-quota pool requires a completed PIV reset")
            ready(session)
            sdk = fixture_session(session)
            value, created = session.fixture("cross.PIV.quota", width), []
            count = POOL_BYTES // width if kind == "bytes" else POOL_SLOTS
            try:
                for index in range(count):
                    identifier = 0x5f8000 + index
                    session.check("cross quota pool fixture is vacant", read(session, identifier), None)
                    session.card_value(write(session, identifier, value))
                    created.append(identifier)
                session.check("PIV pool is actually full before neighbor writes", write(session, 0x5f9000, value).status, 0x6a84)
                neighbors(session, "piv")
                session.select("piv")
                sdk.authenticate(session.options.management_key)
                for identifier in created:
                    session.check("neighbor creation preserves each full-pool object", read(session, identifier), value)
                removed = created.pop()
                session.card_value(write(session, removed, None))
                session.card_value(write(session, 0x5f9000, value))
                created.append(0x5f9000)
                neighbors(session, "piv")
                session.select("piv")
                session.check("reclaimed PIV quota survives new neighbor objects", read(session, 0x5f9000), value)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    session.select("piv")
                    sdk.authenticate(session.options.management_key)
                    for identifier in created:
                        session.card_value(write(session, identifier, None))
                        session.check("cross-quota PIV pool object removed", read(session, identifier), None)


def run(session):
    oath(session)
    fido(session)
    piv(session)
