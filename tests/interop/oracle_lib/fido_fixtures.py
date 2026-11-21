# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Fresh credential bindings shared by stateful extension and list scenarios."""
import hashlib
from contextlib import contextmanager
from dataclasses import dataclass

from .fido import auth_data, authorize, cm, info, pin_protocol, pin_token, public_key, verified


@dataclass
class Credential:
    rp: str
    descriptor: dict
    key: object
    algorithm: int
    registration: dict
    parsed: dict
    challenge: bytes
    deleted: bool = False

    def query(self, session, extensions=None, options=None, allow=None, authenticate=True):
        request = {1: self.rp, 2: self.challenge, 3: [self.descriptor] if allow is None else allow,
                   5: {"up": True} if options is None else options}
        if extensions is not None:
            request[4] = extensions
        if authenticate:
            authorize(session, request, 2, self.rp, self.challenge, 6, 7)
        return request

    def assertion(self, session, **kwargs):
        value = session.ctap_value(session.ctap(2, self.query(session, **kwargs)))
        signed = auth_data(value[2])
        session.check("assertion bound to fixture RP", signed["rp_hash"], hashlib.sha256(self.rp.encode()).digest())
        verified(session, "fixture assertion signature", self.key, self.algorithm, value[3], value[2] + self.challenge)
        return value, signed

    def delete(self, session):
        if self.deleted:
            raise ValueError("owned credential was already deleted")
        version, token = pin_token(session, 4)
        session.ctap_value(cm(session, version, token, 6, {2: self.descriptor}))
        self.deleted = True


@contextmanager
def credential(session, label, resident=False, extensions=None, options=None, algorithms=None, rp=None, extra=None, *, authenticate=True):
    if resident:
        session.require(info(session).get(4, {}).get("rk") and info(session).get(4, {}).get("credMgmt") and session.options.pin,
                        "resident fixtures require rk, credMgmt and a PIN for deletion")
    rp = rp or session.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
    challenge = session.fixture(label + ".hash")
    request = {1: challenge, 2: {"id": rp}, 3: {"id": session.fixture(label + ".user", 16)},
               4: [{"type": "public-key", "alg": alg} for alg in (algorithms or [-7])],
               7: {"rk": resident} if options is None else options}
    if extensions is not None:
        request[6] = extensions
    if extra is not None:
        request.update(extra)
    if authenticate:
        authorize(session, request, 1, rp, challenge, 8, 9)
    descriptor = fixture = None
    try:
        value = session.ctap_value(session.ctap(1, request))
        parsed = auth_data(value[2])
        session.check("registration bound to fixture RP", parsed["rp_hash"], hashlib.sha256(rp.encode()).digest())
        descriptor = {"type": "public-key", "id": parsed["credential_id"]}
        fixture = Credential(rp, descriptor, public_key(parsed["cose"]), parsed["cose"][3], value, parsed, challenge)
        session.bind(label + ".credential", descriptor)
        yield fixture
    finally:
        if resident and descriptor is not None and not session.broken and (fixture is None or not fixture.deleted):
            phase = session.trace.phase
            session.trace.phase = "cleanup"
            version, token = pin_token(session, 4)
            session.ctap_value(cm(session, version, token, 6, {2: descriptor}))
            session.trace.phase = phase


def provision_after_reset(session, current):
    session.check("reset established an unset PIN", current.get(4, {}).get("clientPin"), False)
    session.failed_auth.discard("fido.pin")
    session.options.pin = None
    session.values.pop("u2f.fixture", None)
    session.bind("fido.info", current)
    if session.initial_pin is None:
        return
    session.require(session.profile != "trezor", "wallet profile excludes fixture PIN provisioning", "excluded_by_profile")
    raw = session.initial_pin.encode()
    session.require(4 <= len(session.initial_pin) and len(raw) <= 63, "original fixture PIN does not fit factory policy")
    protocol = pin_protocol(session)
    encrypted = protocol.encrypt(raw.ljust(64, b"\x00"))
    session.ctap_value(session.ctap(6, {1: protocol.version, 2: 3, 3: protocol.cose,
                                       4: protocol.authenticate(encrypted), 5: encrypted}))
    session.options.pin = session.initial_pin
    session.bind("fido.info", session.ctap_value(session.ctap(4)))
    pin_token(session, 2, "reset-control.oracle.invalid")
    session.observe("PIN_fixture_recovery", "supplied fixture PIN reprovisioned and verified after witnessed factory reset")
