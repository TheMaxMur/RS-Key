# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Populate private neighbors before resetting one applet, then prove isolation."""
import hmac

from . import pgp_keys
from . import codec, fido_lifecycle, oath_states, openpgp_lifecycle, piv_lifecycle
from .binding import require_pair
from .cards import connection, fixture_key
from .card_pin_matrix import piv_sign, pgp_sign
from .fido_fixtures import credential
from .management_cases import read, write
from .otp import OATH_HASHES, oath_open, oath_names, oath_request, otp_value, slot_select, slot_request, slot_config


class Fixtures:
    def __init__(self, session):
        self.session = session
        self.piv = self.pgp = self.fido = None
        self.piv_key = self.pgp_key = None
        self.oath_name = None
        self.otp_key = None
        self.lock_code = None
        self.config = None
        self.ready = False

    def prepare(self):
        from yubikit.piv import PivSession, SLOT, PIN_POLICY
        from yubikit.openpgp import OpenPgpSession, KEY_REF
        s = self.session
        s.require(s.profile == "rsk", "populated reset isolation is RS-Key-specific", "excluded_by_profile")
        s.require(s.hid is not None and s.card is not None, "reset isolation requires both transports of the selected instance")
        s.require(all((s.options.pin, s.options.piv_pin, s.options.piv_puk, s.options.management_key,
                       s.options.openpgp_pin, s.options.openpgp_admin)), "all known reference credentials are required before creating fixtures")
        require_pair(s)
        self.config = read(s, "card")
        s.require(self.config.get(10) == b"\x00", "an existing unknown management lock cannot be replaced")
        oath_open(s)
        name = b"oracle-cross-reset-" + s.fixture(s.current.name, 8).hex().encode()
        s.require(name not in oath_names(s), "cross-reset OATH fixture name already exists")
        self.piv, self.piv_key = PivSession(connection(s)), fixture_key(s, "ECCP256")
        self.piv.authenticate(s.options.management_key)
        self.piv.put_key(SLOT(0x82), self.piv_key, PIN_POLICY.ONCE)
        self.pgp, self.pgp_key = OpenPgpSession(connection(s)), fixture_key(s, "ECCP256")
        self.pgp.verify_admin(s.options.openpgp_admin)
        pgp_keys.put_key(s, self.pgp, KEY_REF.SIG, self.pgp_key)
        with credential(s, s.current.name + ".FIDO") as fixture:
            self.fido = fixture
        oath_open(s)
        oath_request(s, 1, codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]))
        self.oath_name = name
        slot_select(s)
        key = s.fixture("cross-reset.OTP", 20)
        slot_request(s, {1: 1, 2: 3}[s.options.otp_slot], slot_config(key, variable=False) + bytes(6))
        self.otp_key = key
        code = s.fixture("cross-reset.lock", 16)
        write(s, "card", codec.tlv(10, code))
        self.lock_code = code
        s.check("reset fixture config lock armed", read(s, "card").get(10), b"\x01")
        self.verify(None)
        self.ready = True

    def verify(self, reset):
        from yubikit.piv import PivSession, SLOT
        from yubikit.openpgp import OpenPgpSession, KEY_REF
        s = self.session
        piv = PivSession(connection(s))
        piv.verify_pin(s.options.piv_pin)
        if reset == "piv":
            reply = s.apdu(codec.apdu(0xF7, p2=0x82))
            s.check("PIV reset removed populated private key metadata", reply.status, 0x6A88)
            operation = s.apdu(codec.apdu(0x87, 0x11, 0x82, codec.tlv(0x7C, codec.tlv(0x82, b"") + codec.tlv(0x81, bytes(32)))))
            s.check("old PIV private operation is revoked", operation.status, 0x6A88)
        else:
            piv_sign(s, piv, self.piv_key)
        pgp = OpenPgpSession(connection(s))
        if reset == "openpgp":
            s.check("OpenPGP reset removed populated private key", s.apdu(codec.apdu(0x47, 0x81, data=KEY_REF.SIG.crt)).status, 0x6A88)
            pgp.verify_pin(s.options.openpgp_pin)
            s.check("old OpenPGP private operation is revoked", s.apdu(codec.apdu(0x2A, 0x9E, 0x9A, bytes(32))).status, 0x6A88)
        else:
            pgp.verify_pin(s.options.openpgp_pin)
            pgp_sign(s, pgp, self.pgp_key)
        s.select("fido")
        if reset == "fido":
            reply = s.ctap(2, self.fido.query(s, options={"up": False}, authenticate=False))
            s.check("FIDO reset revokes previous wrapped credential", reply.status, 0x2E)
        else:
            self.fido.assertion(s)
        oath_open(s)
        if reset == "oath":
            s.check("OATH reset removed populated secret record", self.oath_name not in oath_names(s))
            reply = s.apdu(codec.apdu(0xA2, data=codec.tlv(0x71, self.oath_name) + codec.tlv(0x74, bytes(8))))
            s.check("old OATH secret operation is revoked", reply.status, 0x6A80)
        else:
            challenge = s.fixture("cross-reset.OATH", 8)
            answer = dict(codec.parse_tlv(oath_request(s, 0xA2, codec.tlv(0x71, self.oath_name) + codec.tlv(0x74, challenge), p2=1)))[0x76]
            s.check("neighbor OATH private secret survives", answer, b"\x06" + otp_value(OATH_HASHES[0][2], challenge, "sha1", 6).to_bytes(4, "big"))
        slot_select(s)
        challenge = s.fixture("cross-reset.OTP.challenge", 64)
        answer = slot_request(s, {1: 0x30, 2: 0x38}[s.options.otp_slot], challenge, 20)
        s.check("neighbor OTP private secret survives", answer, hmac.digest(self.otp_key, challenge, "sha1"))
        current = read(s, "card")
        s.check("applet reset preserves management lock", current.get(10), b"\x01")
        s.check("applet reset preserves every observed config field", {k: v for k, v in current.items() if k != 10},
                {k: v for k, v in self.config.items() if k != 10})
        reply = write(s, "card", codec.tlv(10, bytes(16)))
        s.observe("reset.locked-write-outcome", (reply.protocol, reply.status))
        s.check("surviving lock still enforces authorization", read(s, "card"), current)

    def cleanup(self, reset):
        from yubikit.piv import PivSession, SLOT
        from yubikit.openpgp import OpenPgpSession, KEY_REF
        s = self.session
        s.require(not s.broken, "transport uncertainty prevents fixture cleanup")
        if self.lock_code is not None:
            write(s, "card", codec.tlv(11, self.lock_code) + codec.tlv(10, bytes(16)))
            s.check("known cross-reset lock removed", read(s, "card"), self.config)
        if self.piv_key is not None and reset != "piv":
            piv = PivSession(connection(s))
            piv.authenticate(s.options.management_key)
            metadata = s.apdu(codec.apdu(0xF7, p2=0x82))
            s.check("cleanup PIV fixture present or already reset", metadata.status in (0x9000, 0x6A88))
            if metadata.status == 0x9000:
                piv.delete_key(SLOT(0x82))
        if self.pgp_key is not None and reset != "openpgp":
            pgp = OpenPgpSession(connection(s))
            pgp.verify_admin(s.options.openpgp_admin)
            present = s.apdu(codec.apdu(0x47, 0x81, data=KEY_REF.SIG.crt))
            s.check("cleanup OpenPGP fixture present or already reset", present.status in (0x9000, 0x6A88))
            if present.status == 0x9000:
                pgp_keys.delete_key(s, pgp, KEY_REF.SIG)
        if self.oath_name is not None and reset != "oath":
            oath_open(s)
            if self.oath_name in oath_names(s):
                oath_request(s, 2, codec.tlv(0x71, self.oath_name))
        if self.otp_key is not None:
            slot_select(s)
            slot_request(s, {1: 1, 2: 3}[s.options.otp_slot], bytes(58))
        s.observe("cleanup_limit", "owned PIV/OpenPGP/OTP fixture slots are emptied; an applet reset retains factory state, while unrelated applet secrets are verified before cleanup")


def run(session):
    for target, reset in (("piv", piv_lifecycle.reset), ("openpgp", openpgp_lifecycle.lifecycle),
                          ("oath", oath_states.reset), ("fido", fido_lifecycle.reset)):
        fixtures = Fixtures(session)
        with session.namespace("cross.reset." + target + "."):
            effects = ("replace_piv_slot_82", "replace_openpgp_sig_key", "create_fido_credential", "create_oath_record",
                       "replace_otp_slot_" + str(session.options.otp_slot), "config_change")
            with session.case("populate-private-neighbors", ("X01", "X06", "X07", "M06"), effects=effects, touch=True):
                fixtures.prepare()
            completed = False
            try:
                if fixtures.ready or session.planning:
                    before = len(session.trace.cases)
                    reset(session)
                    completed = any(row["verdict"] == "pass" for row in session.trace.cases[before:])
                with session.case("verify-private-isolation", ("X06", "X07", "M06", "P16", "O21", "F23", "A12"), effects=effects, touch=True):
                    session.require(fixtures.ready and completed, "populated fixtures and a completed applet reset are required")
                    fixtures.verify(target)
            finally:
                with session.case("cleanup-owned-fixtures", ("X06", "M06"), effects=effects):
                    session.require(fixtures.config is not None, "no cross-reset fixture was created")
                    fixtures.cleanup(target if completed else None)
