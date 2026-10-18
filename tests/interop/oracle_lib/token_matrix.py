# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Legacy and scoped grants are tested by the protected operations they open."""
import hashlib
from contextlib import ExitStack

from . import codec
from .credential_matrix import metadata
from .fido import auth_data, cm, info, pin_protocol, pin_token, token_mac, verified
from .fido_fixtures import credential
from .fido_states import change_pin
from .lifecycle import Action, change


def issue(session, version, legacy=False, permissions=None, rp=None):
    session.require(session.options.pin is not None, "token matrix requires the known configured PIN")
    protocol = pin_protocol(session, version)
    fields = {1: version, 2: 5 if legacy else 9, 3: protocol.cose,
              6: protocol.encrypt(hashlib.sha256(session.options.pin.encode()).digest()[:16])}
    if permissions is not None:
        fields[9] = permissions
    if rp is not None:
        fields[10] = rp
    result = session.ctap(6, fields)
    return result, protocol.decrypt(session.ctap_value(result)[2]) if result.protocol == "success" else None


def admission(session):
    for version in (1, 2):
        for permissions in (*range(256), 256, 257, 319, 320, 321, 65535, 0xFFFFFFFF):
            with session.case(f"fido.token.permissions.protocol-{version}.bits-{permissions}", ("F06", "F09", "F10", "G04", "G14"),
                              effects=("create_fido_credential",), touch=True, parameters={"protocol": version, "permissions": permissions}, method="exhaustive-byte-and-overflow-boundaries"):
                session.require(session.profile == "rsk", "permission admission contract requires RS-Key", "excluded_by_profile")
                session.require(info(session).get(4, {}).get("pinUvAuthToken"), "scoped tokens not advertised", "unknown")
                with credential(session, session.current.name) as fixture:
                    before = metadata(session)
                    _, previous = pin_token(session, 4, version=version)
                    retries = session.ctap_value(session.ctap(6, {1: version, 2: 1}))
                    reply, token = issue(session, version, permissions=permissions)
                    low = permissions & 255
                    expected = 0x02 if permissions == 0 else 0x40 if low & 8 or low & 64 and low != 64 else 0
                    session.check("permission request admission matches declared profile", reply.status, expected)
                    session.observe("permission_spec_difference", bool(low & 128 or permissions > 255), "exact")
                    if token is not None:
                        session.check("issued grant has complete token bytes", len(token), 32)
                        probe = cm(session, version, token, 1)
                        if low & (4 | 64):
                            session.check("only CM or persistent RO opens metadata", session.ctap_value(probe), before)
                        else:
                            session.check("token without CM cannot read protected metadata", probe.status, 0x33)
                    else:
                        session.check("refused grant issuance preserves standing grant", session.ctap_value(cm(session, version, previous, 1)), before)
                    session.check("permission validation never spends a PIN retry", session.ctap_value(session.ctap(6, {1: version, 2: 1})), retries)
                    session.check("permission request preserves populated store", metadata(session), before)
                    fixture.assertion(session)
        for permissions in (None, 0, 1, 3, 4, 64, 255):
            for rp in (None, "", "legacy.oracle.invalid"):
                label = "omitted" if permissions is None else str(permissions)
                with session.case(f"fido.token.legacy.protocol-{version}.bits-{label}.RP-{rp!r}", ("F06", "F09", "G01", "G04", "G14")):
                    session.require(session.profile == "rsk", "legacy grant validation requires RS-Key", "excluded_by_profile")
                    before = metadata(session)
                    _, old = pin_token(session, 4, version=version)
                    reply, token = issue(session, version, True, permissions, rp)
                    expected = 0 if permissions in (None, 0) and rp is None else 2
                    session.check("legacy token rejects scoped request fields", reply.status, expected)
                    result = cm(session, version, token if token is not None else old, 1)
                    if expected:
                        session.check("legacy syntax refusal preserves standing CM grant", session.ctap_value(result), before)
                    else:
                        session.check("legacy grant carries MC and GA only", result.status, 0x33)


def assertion(session, fixture, version, token):
    request = fixture.query(session, authenticate=False)
    request.update({6: token_mac(version, token, fixture.challenge), 7: version})
    reply = session.ctap(2, request)
    if reply.protocol == "success":
        value = session.ctap_value(reply)
        signed = auth_data(value[2])
        session.check("scoped assertion has verified UV", bool(signed["flags"] & 4))
        session.check("scoped assertion retains RP", signed["rp_hash"], fixture.parsed["rp_hash"])
        verified(session, "scoped assertion retains private key", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)
    return reply


def rp_binding(session):
    for version in (1, 2):
        for legacy, permissions in ((True, None), (False, 1), (False, 2), (False, 3), (False, 4), (False, 64), (False, 128)):
            for binding in ("omitted", "matching", "foreign", "empty"):
                if legacy and binding != "omitted":
                    continue
                with session.case(f"fido.token.RP.protocol-{version}.legacy-{legacy}.bits-{permissions}.{binding}", ("F06", "F09", "F10", "F11", "F12", "G10", "G14"),
                                  effects=("create_fido_credential",), touch=True):
                    session.require(session.profile == "rsk", "RP grant semantics require RS-Key", "excluded_by_profile")
                    with ExitStack() as stack:
                        left, right = [stack.enter_context(credential(session, session.current.name + suffix)) for suffix in (".left", ".right")]
                        rp = None if binding == "omitted" else left.rp if binding == "matching" else "foreign.oracle.invalid" if binding == "foreign" else ""
                        result, token = issue(session, version, legacy, permissions, rp)
                        session.ctap_value(result)
                        allowed = legacy or bool(permissions & 2)
                        first = assertion(session, left, version, token)
                        expected = 0 if allowed and binding in ("omitted", "matching") else 0x33
                        session.check("GA checks both permission and initial RP binding", first.status, expected)
                        second = assertion(session, right, version, token)
                        session.check("first successful use binds an unscoped grant to its RP", second.status, 0x33)
                        if expected == 0:
                            session.check("RP mismatch preserves the authorized original RP", assertion(session, left, version, token).status, 0)
                        left.assertion(session)
                        right.assertion(session)


def pin_invalidation(session):
    for version in (1, 2):
        for kind in ("legacy", "ordinary", "readonly"):
            for candidate in ("same", "different"):
                with session.case(f"fido.token.PIN-invalidation.protocol-{version}.{kind}.{candidate}", ("F05", "F06", "F09", "F10", "G10", "G14"),
                                  effects=("pin_change", "create_fido_credential"), touch=True):
                    session.require(session.profile == "rsk", "PIN grant invalidation requires RS-Key", "excluded_by_profile")
                    session.require(not info(session).get(27), "policy-enabled PIN changes require the dedicated policy fixture")
                    session.require(kind != "readonly" or info(session).get(4, {}).get("perCredMgmtRO"), "persistent RO token not advertised", "unknown")
                    original = session.options.pin
                    replacement = original if candidate == "same" else "Or4!" + "a" * max(8, info(session).get(13, 4))
                    session.require(original and len(replacement.encode()) <= 63, "known original and bounded replacement PIN required")
                    changed = False
                    with credential(session, session.current.name) as fixture:
                        reply, token = issue(session, version, kind == "legacy", None if kind == "legacy" else 64 if kind == "readonly" else 2,
                                             None if kind != "ordinary" else fixture.rp)
                        session.ctap_value(reply)
                        try:
                            change_pin(session, original, replacement)
                            changed = True
                            session.options.pin = replacement
                            if kind == "readonly":
                                session.check("PIN change invalidates persistent RO grant", cm(session, version, token, 1).status, 0x33)
                            else:
                                session.check("PIN change invalidates prior ordinary or legacy grant", assertion(session, fixture, version, token).status, 0x33)
                            fixture.assertion(session)
                            current = session.ctap_value(session.ctap(4))
                            session.check("PIN change retains configured state", current[4]["clientPin"], True)
                        finally:
                            if changed and not session.broken:
                                session.trace.phase = "cleanup"
                                change_pin(session, replacement, original)
                                session.options.pin = original
                                fixture.assertion(session)


def readonly_isolation(session):
    for version in (1, 2):
        for action in ("reissue", "ordinary-replacement", *Action):
            label = action.value if isinstance(action, Action) else action
            with session.case(f"fido.token.persistent-RO.protocol-{version}.{label}", ("F06", "F09", "F10", "X11", "G14"),
                              effects=("reboot",) if action == Action.POWER_CYCLE else ()):
                session.require(session.profile == "rsk", "persistent grant isolation requires RS-Key", "excluded_by_profile")
                session.require(info(session).get(4, {}).get("perCredMgmtRO"), "persistent grant not advertised", "unknown")
                before = metadata(session)
                _, ordinary = pin_token(session, 4, version=version)
                _, persistent = pin_token(session, 64, version=version)
                standing = cm(session, version, ordinary, 1)
                session.check("RO issuance does not replace ordinary session grant", standing.status, 0)
                session.check("standing ordinary grant retains metadata", session.ctap_value(standing), before)
                if action == "reissue":
                    _, fresh = pin_token(session, 64, version=version)
                    session.check("RO plaintext grant is stable when reissued", fresh, persistent)
                elif action == "ordinary-replacement":
                    _, fresh = pin_token(session, 4, version=version)
                    session.check("ordinary replacement rotates its token", fresh != ordinary)
                    session.check("ordinary replacement invalidates old token", cm(session, version, ordinary, 1).status, 0x33)
                else:
                    change(session, action)
                session.check("persistent RO remains authorized through unrelated session changes", session.ctap_value(cm(session, version, persistent, 1)), before)


def run(session):
    admission(session)
    rp_binding(session)
    pin_invalidation(session)
    readonly_isolation(session)
    refused_change_grants(session)
    replacements(session)


def refused_change_grants(session):
    from contextlib import nullcontext
    for version in (1, 2):
        for defect in ("MAC", "new-policy", "old-PIN"):
            with session.case(f"fido.token.refused-PIN-change.protocol-{version}.{defect}", ("F05", "F09", "F10", "G10", "G13", "G14"), effects=("pin_attempts", "pin_change", "create_fido_credential"), touch=True):
                session.require(session.profile == "rsk", "rejected PIN-change grant ordering requires RS-Key", "excluded_by_profile")
                session.require(info(session).get(4, {}).get("perCredMgmtRO"), "persistent RO grant not advertised", "unknown")
                session.require(not info(session).get(12), "forced-change same-PIN rejection is handled by the policy suite")
                with credential(session, session.current.name) as fixture:
                    before = metadata(session)
                    _, ordinary = pin_token(session, 4, version=version)
                    _, persistent = pin_token(session, 64, version=version)
                    remaining = session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3]
                    session.require(defect != "old-PIN" or remaining > 1, "one failed comparison needs a remaining recovery retry")
                    protocol = pin_protocol(session, version)
                    candidate = "a" if defect == "new-policy" else session.options.pin
                    encrypted = protocol.encrypt(candidate.encode().ljust(64, b"\x00"))
                    old = hashlib.sha256((session.options.pin + ("!" if defect == "old-PIN" else "")).encode()).digest()[:16]
                    old_hash = protocol.encrypt(old)
                    mac = protocol.authenticate(encrypted + old_hash)
                    if defect == "MAC":
                        mac = bytes([mac[0] ^ 1]) + mac[1:]
                    with session.attempts("fido.pin", 3) if defect == "old-PIN" else nullcontext():
                        try:
                            reply = session.ctap(6, {1: version, 2: 4, 3: protocol.cose, 4: mac, 5: encrypted, 6: old_hash})
                            session.check("rejected change has the isolated defect's cause", reply.status, {"MAC": 0x33, "new-policy": 0x37, "old-PIN": 0x31}[defect])
                            result = cm(session, version, ordinary, 1)
                            session.check("failed old-PIN comparison alone revokes ordinary grant", result.status, 0x33 if defect == "old-PIN" else 0)
                            result = cm(session, version, persistent, 1)
                            session.check("persistent grant is revoked before replacement policy is checked", result.status, 0x33 if defect == "new-policy" else 0)
                        finally:
                            if not session.broken:
                                pin_token(session, 4, version=version)
                    session.check("refused PIN change preserves resident state", metadata(session), before)
                    fixture.assertion(session)


def replacements(session):
    for version in (1, 2):
        for old_legacy in (False, True):
            for new_legacy in (False, True):
                with session.case(f"fido.token.replacement.protocol-{version}.legacy-{old_legacy}-to-{new_legacy}", ("F06", "F09", "F10", "G10", "G11", "G14"), effects=("create_fido_credential",), touch=True):
                    session.require(session.profile == "rsk", "ordinary/legacy replacement contract requires RS-Key", "excluded_by_profile")
                    with credential(session, session.current.name) as fixture:
                        persistent = pin_token(session, 64, version=version) if info(session).get(4, {}).get("perCredMgmtRO") else None
                        result, old = issue(session, version, old_legacy, None if old_legacy else 2, None if old_legacy else fixture.rp)
                        session.ctap_value(result)
                        session.check("old grant works before its replacement", assertion(session, fixture, version, old).status, 0)
                        result, fresh = issue(session, version, new_legacy, None if new_legacy else 2, None if new_legacy else fixture.rp)
                        session.ctap_value(result)
                        session.check("each ordinary/legacy replacement invalidates the previous grant", assertion(session, fixture, version, old).status, 0x33)
                        session.check("old grant refusal cannot revoke the replacement", assertion(session, fixture, version, fresh).status, 0)
                        if persistent is not None:
                            session.ctap_value(cm(session, *persistent, 1))
                        fixture.assertion(session)
