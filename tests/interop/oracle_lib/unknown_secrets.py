# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Bounded candidate checks recover lost PIN/code changes without replaying them."""
from . import codec
from .uncertain_writes import lose, require_loss


def candidate(session, domain, values, operation, success=0x9000):
    with session.attempts(domain, len(values) + 1):
        for label, value in values:
            reply = operation(value)
            session.check("secret recovery has a comparison result rather than an encoding/transport failure",
                reply.protocol == "success" and reply.status == success or reply.is_rejection and (reply.status in (0x31, 0x6982, 0x6a80) or isinstance(reply.status, int) and reply.status & 0xfff0 == 0x63c0))
            if reply.status == success:
                session.observe("unknown_secret_readback", {"outcome": label, "candidate_checks_bounded": len(values), "unknown_mutator_replayed": False})
                return value
    session.broken = True
    session.values["halt_reason"] = "neither known old nor new secret authenticates; stop before any further secret mutation"
    session.check("lost secret mutation retains one complete known old or new verifier", False)


def piv(session):
    from yubikit.piv import PIN_POLICY
    from .card_pin_matrix import piv_sign
    from .piv_lifecycle import wire_pin
    from .piv_matrix import key_fixture
    for reference, option in ((0x80, "piv_pin"), (0x81, "piv_puk")):
        with session.case(f"cross.unknown-write.PIV.secret-{reference:02x}", ("X10", "P03", "P04", "P05", "P11", "G09", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "pin_change", "pin_attempts", "replace_piv_slot_82"), touch=True):
            require_loss(session)
            old = getattr(session.options, option)
            session.require(old is not None, "known original PIV PIN/PUK required before changing it")
            new = "87654321" if old != "87654321" else "76543210"
            with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                metadata = sdk.get_pin_metadata() if reference == 0x80 else sdk.get_puk_metadata()
                session.require(metadata.attempts_remaining > 1, "two candidates need an independently available recovery retry")
                lose(session, 0x24, lambda: session.apdu(codec.apdu(0x24, p2=reference, data=wire_pin(old) + wire_pin(new))))
                session.select("piv")
                if reference == 0x80:
                    current = candidate(session, ("piv", reference), (("unchanged", old), ("committed", new)),
                        lambda value: session.apdu(codec.apdu(0x20, p2=reference, data=wire_pin(value))))
                    session.options.piv_pin = current
                    piv_sign(session, sdk, key)
                    if current != old:
                        session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=wire_pin(current) + wire_pin(old))))
                    session.options.piv_pin = old
                else:
                    session.observe("PUK_recovery_scope", "PUK has no VERIFY command; each bounded candidate is an explicit CHANGE-to-original recovery, never a replay of the unknown CHANGE-to-new request")
                    candidate(session, ("piv", reference), (("unchanged", old), ("committed", new)),
                        lambda value: session.apdu(codec.apdu(0x24, p2=reference, data=wire_pin(value) + wire_pin(old))))
                sdk.verify_pin(old if reference == 0x80 else session.options.piv_pin)
                piv_sign(session, sdk, key)
                final = sdk.get_pin_metadata() if reference == 0x80 else sdk.get_puk_metadata()
                session.check("known original secret recovery restores the retry budget", final.attempts_remaining, final.total_attempts)


def openpgp(session):
    from .card_pin_matrix import pgp_sign
    from .openpgp_references import fixture
    for reference, option in ((0x81, "openpgp_pin"), (0x83, "openpgp_admin")):
        with session.case(f"cross.unknown-write.OpenPGP.secret-{reference:02x}", ("X10", "O02", "O03", "O05", "O11", "O22", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "pin_change", "pin_attempts", "replace_openpgp_sig_key", "config_change", "write_and_restore_openpgp_DO"), touch=True):
            require_loss(session)
            old = getattr(session.options, option)
            session.require(old is not None, "known original OpenPGP password required")
            new = "oracle-unknown-password" if old != "oracle-unknown-password" else "oracle-replacement-password"
            with fixture(session) as (sdk, key):
                retries = sdk.get_data(0xc4)[4 if reference == 0x81 else 6]
                session.require(retries > 1, "two password candidates need an available recovery retry")
                count = sdk.get_signature_counter()
                lose(session, 0x24, lambda: session.apdu(codec.apdu(0x24, p2=reference, data=(old + new).encode())))
                session.select("openpgp")
                current = candidate(session, ("openpgp", reference), (("unchanged", old), ("committed", new)),
                    lambda value: session.apdu(codec.apdu(0x20, p2=reference, data=value.encode())))
                setattr(session.options, option, current)
                session.check("password loss and readback cannot execute a signature", sdk.get_signature_counter(), count)
                sdk.verify_pin(session.options.openpgp_pin)
                pgp_sign(session, sdk, key)
                if current != old:
                    session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=(current + old).encode())))
                setattr(session.options, option, old)
                sdk.verify_pin(session.options.openpgp_pin)
                sdk.verify_admin(session.options.openpgp_admin)
                pgp_sign(session, sdk, key)


def oath(session):
    import hmac
    from .oath_access import known_record, lock, set_code, unlock
    from .oath_gates import reset
    from .oath_pin_matrix import NAME, PIN, NEW_PIN, private_record, setup
    for operation in ("PIN-install", "PIN-change", "access-code"):
        with session.case("cross.unknown-write.OATH." + operation, ("X10", "A04", "A10", "A11", "A14", "A15", "G09", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "pin_change", "pin_attempts", "applet_reset", "config_change", "create_oath_record"), touch=True):
            require_loss(session)
            secret = setup(session, pin=None if operation == "PIN-install" else PIN)
            try:
                if operation == "access-code":
                    new = session.fixture("unknown.OATH.replacement-code", 20)
                    lose(session, 3, lambda: set_code(session, 2, new))
                    selected = lock(session)
                    def verify(value):
                        return session.apdu(codec.apdu(0xa3, data=codec.tlv(0x75, hmac.digest(value, selected[0x74], "sha256")) + codec.tlv(0x74, bytes(8))))
                    active = candidate(session, ("oath", "code"), (("unchanged", secret), ("committed", new)), verify)
                    session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))))
                    private_record(session)
                    known_record(session, NAME, 0)
                    if active != secret:
                        set_code(session, 2, secret)
                else:
                    command = 0xb4 if operation == "PIN-install" else 0xb3
                    payload = codec.tlv(0x80, NEW_PIN) if command == 0xb4 else codec.tlv(0x80, PIN) + codec.tlv(0x81, NEW_PIN)
                    lose(session, command, lambda: session.apdu(codec.apdu(command, data=payload)))
                    selected = lock(session)
                    unlock(session, 2, secret, selected)
                    if command == 0xb4 and session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status == 0x9000:
                        session.check("uncommitted PIN installation leaves the PIN verifier unset", session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, NEW_PIN))).status, 0x6985)
                        session.observe("unknown_secret_readback", {"outcome": "unchanged-unset", "unknown_mutator_replayed": False})
                    else:
                        values = (("committed", NEW_PIN),) if command == 0xb4 else (("unchanged", PIN), ("committed", NEW_PIN))
                        active_pin = candidate(session, ("oath", 0xb2), values, lambda value: session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, value))))
                        unlock(session, 2, secret)
                        session.card_value(session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, active_pin))))
                    private_record(session)
                    known_record(session, NAME, 0)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)


def run(session):
    piv(session)
    openpgp(session)
    oath(session)
