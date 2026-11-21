# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV reference grammar and retry changes retain populated private keys."""
from itertools import product

from . import codec
from .card_pin_matrix import piv_sign
from .piv_lifecycle import fixture_session, recovered, wire_pin
from .piv_matrix import key_fixture
from .piv_policies import cue
from .runner import AIDS

VALID_KEYS = (*range(0x82, 0x96), 0x9a, 0x9c, 0x9d, 0x9e)


def metadata(session):
    for reference in range(256):
        if reference in (*VALID_KEYS, 0x80, 0x81, 0x9b, 0xf9):
            continue
        with session.case(f"piv.metadata.unknown-{reference:02x}", ("P02", "P14", "G04", "G09", "G14"), effects=("replace_piv_keys",), touch=True):
            session.require(session.profile == "rsk", "metadata reference catalog requires RS-Key", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                session.check("unknown metadata reference has a stable refusal", session.apdu(codec.apdu(0xf7, p2=reference)).status, 0x6a88)
                session.check("unknown attestation reference cannot name a private key", session.apdu(codec.apdu(0xf9, p1=reference)).status, 0x6a88)
                piv_sign(session, sdk, key)
    for reference, p1 in product((0x80, 0x81, 0x82, 0x9b, 0xf9), (1, 2, 127, 128, 255)):
        with session.case(f"piv.metadata.reference-{reference:02x}.P1-{p1}", ("P02", "G04", "G13", "G14"), effects=("replace_piv_keys",), touch=True):
            session.require(session.profile == "rsk", "metadata parameter strictness requires RS-Key", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                session.check("metadata validates P1 before its reference", session.apdu(codec.apdu(0xf7, p1, reference)).status, 0x6a86)
                piv_sign(session, sdk, key)


def selections(session):
    from yubikit.piv import PIN_POLICY
    candidates = [(f"prefix-{size}", AIDS["piv"][:size], True) for size in range(5, len(AIDS["piv"]) + 1)]
    candidates += [("unknown", b"\xf0\xff\xff\xff\xff", False), ("suffix", AIDS["piv"] + b"\x00", False), ("empty", b"", False)]
    for label, aid, accepted in candidates:
        with session.case("piv.selection.grants." + label, ("P01", "P03", "P06", "P17", "G09", "G10", "G14"), effects=("replace_piv_keys", "write_piv_fixture_object"), touch=True):
            session.require(session.profile == "rsk", "selection preservation requires RS-Key", "excluded_by_profile")
            with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                sdk.verify_pin(session.options.piv_pin)
                result = session.apdu(codec.apdu(0xa4, 4, data=aid))
                session.check("selection accepts only an unambiguous registered prefix", result.status, 0x9000 if accepted else 0x6a82)
                session.select("piv")
                piv_sign(session, sdk, key)
                # A malformed protected write distinguishes the management ACL without changing storage.
                session.check("same or refused SELECT preserves management authorization", session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6a80)


def rotation_failures(session):
    for defect in ("missing-auth", "P1", "P2", "algorithm-zero", "algorithm-unknown", "reference", "no-body", "one-byte", "short-header", "short-key", "long-key", "declared-length", "wrong-tag"):
        with session.case("piv.management-key.refusal." + defect, ("P01", "P02", "P06", "P07", "G01", "G03", "G04", "G10", "G13", "G14"), effects=("replace_piv_keys", "config_change"), touch=True):
            session.require(session.profile == "rsk", "management-key refusal ordering requires RS-Key", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                before = sdk.get_management_key_metadata()
                algorithm = int(sdk.management_key_type)
                body = bytes([algorithm]) + codec.tlv(0x9b, session.options.management_key)
                p1, p2, expected = 0xff, 0xff, 0x6a80
                if defect == "missing-auth":
                    session.select("openpgp")
                    session.select("piv")
                    expected = 0x6982
                elif defect in ("P1", "P2"):
                    p1, p2 = (0, 0xff) if defect == "P1" else (0xff, 0xfd)
                    expected = 0x6a86
                elif defect.startswith("algorithm-"):
                    body = bytes([0 if defect == "algorithm-zero" else 255]) + body[1:]
                elif defect in ("reference", "wrong-tag"):
                    body = body[:1] + bytes([0xf9 if defect == "reference" else 0x53]) + body[2:]
                elif defect in ("no-body", "one-byte", "short-header"):
                    body = body[:{"no-body": 0, "one-byte": 1, "short-header": 2}[defect]]
                    expected = 0x6a80 if defect == "one-byte" else 0x6700
                elif defect in ("short-key", "long-key"):
                    body = body[:-1] if defect == "short-key" else body + b"x"
                    expected = 0x6700
                else:
                    body = body[:2] + bytes([body[2] - 1]) + body[3:]
                session.check("rotation refusal preserves its exact validation precedence", session.apdu(codec.apdu(0xff, p1, p2, body)).status, expected)
                after = sdk.get_management_key_metadata()
                session.check("refused rotation preserves algorithm and touch policy", (after.key_type, after.touch_policy, after.default_value), (before.key_type, before.touch_policy, before.default_value))
                session.check("refused rotation retains exactly the preceding management grant", session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6982 if defect == "missing-auth" else 0x6a80)
                sdk.authenticate(session.options.management_key)
                session.check("the original management key still opens a protected operation", session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6a80)
                sdk.verify_pin(session.options.piv_pin)
                piv_sign(session, sdk, key)


def management_presence(session):
    from yubikit.core.smartcard import ApduError
    from yubikit.piv import MANAGEMENT_KEY_TYPE, TOUCH_POLICY
    for algorithm, mode in product(MANAGEMENT_KEY_TYPE, ("accept", "decline", "timeout")):
        with session.case(f"piv.management-presence.{algorithm.name}.{mode}", ("P06", "P07", "P17", "G10", "G14"), effects=("replace_piv_keys", "config_change"), touch=True):
            session.require(session.profile == "rsk", "management touch policy requires RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "management presence needs a controlled operator action")
            session.require(mode != "decline" or "display" in session.options.features, "decline requires a declared display")
            session.require(mode != "timeout" or session.options.timeout > 130, "presence timeout requires the full device window")
            session.require(algorithm.name != "TDES" or "fips-profile" not in session.options.features, "FIPS profile excludes installing 3DES", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                original = sdk.get_management_key_metadata()
                temporary = session.fixture("PIV.touch.management." + algorithm.name, algorithm.key_len)
                installed = False
                try:
                    sdk.set_management_key(algorithm, temporary, True)
                    installed = True
                    session.select("openpgp")
                    session.select("piv")
                    cue(session, mode)
                    try:
                        sdk.authenticate(temporary)
                        status = 0x9000
                    except ApduError as error:
                        status = error.sw
                    session.check("management touch controls the complete mutual authentication", status, 0x9000 if mode == "accept" else 0x6982)
                    session.check("management touch result is witnessed by a protected operation", session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6a80 if mode == "accept" else 0x6982)
                    cue(session, "accept")
                    sdk.authenticate(temporary)
                    session.check("fresh accepted touch restores management authorization", session.apdu(codec.apdu(0xdb, 0x3f, 0xff)).status, 0x6a80)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
                finally:
                    if installed and not session.broken:
                        session.trace.phase = "cleanup"
                        cue(session, "accept")
                        sdk.authenticate(temporary)
                        sdk.set_management_key(original.key_type, session.options.management_key, original.touch_policy != TOUCH_POLICY.NEVER)
                        sdk.authenticate(session.options.management_key)


def protected_attestation(session):
    for operation, authorized in product(("generate", "import", "delete", "move-from", "move-onto", "attest"), (False, True)):
        with session.case(f"piv.attestation.protected-reference.{operation}.management-{authorized}", ("P02", "P09", "P10", "P14", "P15", "G09", "G10", "G13", "G14"), effects=("replace_piv_keys",), touch=True):
            session.require(session.profile == "rsk", "factory attestation protection requires RS-Key", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                original = session.card_value(session.apdu(codec.apdu(0xf7, p2=0xf9)))
                if not authorized:
                    session.select("openpgp")
                    session.select("piv")
                scalar = key.private_numbers().private_value.to_bytes(32, "big")
                requests = {"generate": (codec.apdu(0x47, p2=0xf9, data=codec.tlv(0xac, codec.tlv(0x80, b"\x11"))), 0x6a86),
                    "import": (codec.apdu(0xfe, 0x11, 0xf9, codec.tlv(6, scalar)), 0x6a80),
                    "delete": (codec.apdu(0xf6, 0xff, 0xf9), 0x6a88), "move-from": (codec.apdu(0xf6, 0x82, 0xf9), 0x6a88),
                    "move-onto": (codec.apdu(0xf6, 0xf9, 0x82), 0x6a80), "attest": (codec.apdu(0xf9, 0xf9), 0x6a88)}
                request, expected = requests[operation]
                session.check("factory reference refuses replacement before touching the slot", session.apdu(request).status, expected if authorized or operation == "attest" else 0x6982)
                session.check("factory attestation public identity and policies remain exact", session.card_value(session.apdu(codec.apdu(0xf7, p2=0xf9))), original)
                sdk.verify_pin(session.options.piv_pin)
                piv_sign(session, sdk, key)


def changes(session):
    from yubikit.piv import PIN_POLICY
    candidates = (bytes(8), b"\xff" * 8, b"abcde\xff\xff\xff", b"abcdef\xff\xff", b"abcdefg\xff", b"abcdefgh", b"\xffabcdefg", b"ab\xffcdefg", b"ab\x00cdefg")
    for reference, candidate in product((0x80, 0x81), candidates):
        with session.case(f"piv.reference.binary-{reference:02x}." + candidate.hex(), ("P03", "P04", "P05", "G03", "G04", "G14"), effects=("replace_piv_keys", "pin_change"), touch=True):
            session.require(session.profile == "rsk", "opaque reference wire format requires RS-Key", "excluded_by_profile")
            session.require(session.options.piv_puk is not None, "known PUK is required for reference restoration")
            with key_fixture(session) as (sdk, key):
                original = wire_pin(session.options.piv_pin if reference == 0x80 else session.options.piv_puk)
                changed = False
                try:
                    result = session.apdu(codec.apdu(0x24, p2=reference, data=original + candidate))
                    changed = result.status == 0x9000
                    length = len(candidate.rstrip(b"\xff"))
                    session.check("only trailing FF padding is removed from new-reference length", result.status, 0x9000 if 6 <= length <= 8 else 0x6a80)
                    if changed:
                        request = codec.apdu(0x20, p2=0x80, data=candidate) if reference == 0x80 else codec.apdu(0x2c, p2=0x80, data=candidate + wire_pin(session.options.piv_pin))
                        session.check("exact binary replacement reference authorizes its proper path", session.apdu(request).status, 0x9000)
                    piv_sign(session, sdk, key)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        session.card_value(session.apdu(codec.apdu(0x24, p2=reference, data=candidate + original)))
                    if not session.broken:
                        sdk.verify_pin(session.options.piv_pin)
                        piv_sign(session, sdk, key)
    for ins, reference in ((0x24, 0x80), (0x24, 0x81), (0x2c, 0x80)):
        for defect in ("wrong-old-and-bad-new", "short-body", "long-body", "bad-P1", "bad-reference"):
            with session.case(f"piv.reference.order.{ins:02x}.{reference:02x}.{defect}", ("P03", "P04", "P05", "G03", "G04", "G10", "G13", "G14"), effects=("replace_piv_keys", "pin_attempts", "pin_change"), touch=True):
                session.require(session.profile == "rsk", "reference validation precedence requires RS-Key", "excluded_by_profile")
                session.require(session.options.piv_puk is not None, "known PUK required")
                with key_fixture(session, policy=PIN_POLICY.ONCE) as (sdk, key):
                    domain = 0x81 if ins == 0x2c else reference
                    original = wire_pin(session.options.piv_pin if domain == 0x80 else session.options.piv_puk)
                    meta = sdk.get_pin_metadata() if domain == 0x80 else sdk.get_puk_metadata()
                    session.require(meta.attempts_remaining > 1, "wrong reference requires a bounded recovery attempt")
                    p1, p2, body, expected = 0, reference, original + bytes([255]) * 8, 0x6a80
                    if defect == "wrong-old-and-bad-new":
                        body = bytes([original[0] ^ 1]) + original[1:] + bytes([255]) * 8
                        expected = 0x63c0 | min(meta.attempts_remaining - 1, 15)
                    elif defect == "short-body":
                        body = body[:-1]
                    elif defect == "long-body":
                        body += b"x"
                    elif defect == "bad-P1":
                        p1, expected = 1, 0x6a88
                    else:
                        p2, expected = 0x9b, 0x6a88
                    with session.attempts(("piv", domain), 3):
                        result = session.apdu(codec.apdu(ins, p1, p2, body))
                        session.check("reference framing and old-secret ordering are distinct", result.status, expected)
                        remaining = sdk.get_pin_metadata() if domain == 0x80 else sdk.get_puk_metadata()
                        session.check("only wrong-old comparison spends a retry", remaining.attempts_remaining, meta.attempts_remaining - (defect == "wrong-old-and-bad-new"))
                        piv_sign(session, sdk, key)
                        # Correct old plus invalid new resets its retries without altering the secret.
                        session.check("correct old reference recovers retries before rejecting replacement", session.apdu(codec.apdu(ins, p2=reference, data=original + bytes([255]) * 8)).status, 0x6a80)
                        recovered(session, ("piv", domain), "correct old reference verified; invalid replacement was not installed")
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)


def retry_policy(session):
    from .lifecycle import Action, change
    for pin_grant, mgm_grant, totals, body in product((False, True), (False, True), ((0, 0), (0, 3), (3, 0), (1, 2), (255, 255)), (b"", b"x", b"xx")):
        with session.case(f"piv.retry-policy.PIN-{pin_grant}.management-{mgm_grant}.{totals[0]}-{totals[1]}.body-{len(body)}", ("P03", "P04", "P05", "P08", "G03", "G04", "G10", "G13", "G14", "X11"),
                effects=("replace_piv_keys", "pin_change", "reboot"), touch=True):
            session.require(session.profile == "rsk", "retry-policy contract requires RS-Key", "excluded_by_profile")
            session.require(session.options.piv_puk is not None, "known PUK required for retry-policy restoration")
            with key_fixture(session) as (sdk, key):
                original = sdk.get_pin_metadata().total_attempts, sdk.get_puk_metadata().total_attempts
                changed = False
                try:
                    session.select("openpgp")
                    session.select("piv")
                    if pin_grant:
                        sdk.verify_pin(session.options.piv_pin)
                    if mgm_grant:
                        sdk.authenticate(session.options.management_key)
                    result = session.apdu(codec.apdu(0xfa, *totals, data=body))
                    changed = result.status == 0x9000
                    expected = 0x6a80 if len(body) == 1 else 0x6982 if not (pin_grant and mgm_grant) else 0x6a80 if 0 in totals else 0x9000
                    session.check("retry policy validates global framing, both grants and nonzero counts", result.status, expected)
                    session.check("retry policy changes neither total on refusal", (sdk.get_pin_metadata().total_attempts, sdk.get_puk_metadata().total_attempts), totals if changed else original)
                    if changed:
                        session.check("successful SET RETRIES revokes standing PIN grant", session.apdu(codec.apdu(0x20, p2=0x80)).status, 0x63c0 | min(totals[0], 15))
                        sdk.verify_pin("123456")
                        piv_sign(session, sdk, key)
                        change(session, Action.POWER_CYCLE)
                        session.select("piv")
                        session.check("both retry totals persist across cold power", (sdk.get_pin_metadata().total_attempts, sdk.get_puk_metadata().total_attempts), totals)
                        sdk.verify_pin("123456")
                        piv_sign(session, sdk, key)
                    else:
                        sdk.verify_pin(session.options.piv_pin)
                        piv_sign(session, sdk, key)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.authenticate(session.options.management_key)
                        sdk.verify_pin("123456")
                        sdk.set_pin_attempts(*original)
                        sdk.change_pin("123456", session.options.piv_pin)
                        sdk.change_puk("12345678", session.options.piv_puk)
                        sdk.verify_pin(session.options.piv_pin)
                        piv_sign(session, sdk, key)


def blocked_puk(session):
    with session.case("piv.PUK.blocked-correct-secret-cannot-unblock", ("P03", "P04", "P05", "P08", "G10", "G14"), effects=("replace_piv_keys", "pin_change", "pin_attempts"), touch=True):
        session.require(session.profile == "rsk", "bounded PUK blocking requires RS-Key", "excluded_by_profile")
        session.require(session.options.piv_puk is not None, "known PUK required for policy recovery")
        with key_fixture(session) as (sdk, key):
            original = sdk.get_pin_metadata().total_attempts, sdk.get_puk_metadata().total_attempts
            installed = False
            try:
                sdk.set_pin_attempts(3, 2)
                installed = True
                sdk.verify_pin("123456")
                with session.attempts(("piv", 0x81), 3):
                    for left in (1, 0):
                        result = session.apdu(codec.apdu(0x2c, p2=0x80, data=wire_pin("00000000") + wire_pin("654321")))
                        session.check("wrong PUK spends exactly its persistent retry", result.status, 0x63c0 | left if left else 0x6983)
                        session.check("wrong PUK cannot replace or block the PIN", sdk.get_pin_metadata().attempts_remaining, 3)
                        piv_sign(session, sdk, key)
                    session.check("blocked PUK refuses even the known correct secret", session.apdu(codec.apdu(0x2c, p2=0x80, data=wire_pin("12345678") + wire_pin("654321"))).status, 0x6983)
                sdk.verify_pin("123456")
                piv_sign(session, sdk, key)
            finally:
                if installed and not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.authenticate(session.options.management_key)
                    sdk.verify_pin("123456")
                    sdk.set_pin_attempts(*original)
                    recovered(session, ("piv", 0x81), "authenticated retry-policy reset")
                    sdk.change_pin("123456", session.options.piv_pin)
                    sdk.change_puk("12345678", session.options.piv_puk)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)


def run(session):
    metadata(session)
    selections(session)
    rotation_failures(session)
    management_presence(session)
    protected_attestation(session)
    changes(session)
    retry_policy(session)
    blocked_puk(session)
