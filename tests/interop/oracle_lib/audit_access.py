# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Audit authorization, freshness and persistence have independent journal witnesses."""
import hashlib
from itertools import product
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .fido import info, pin_token, token_mac, verified, verify
from .lifecycle import Action, change, require_action
from .vendor_cases import vendor, AUDIT_CHECKPOINT_DOMAIN


def cue(session, mode):
    session.trace.emit("interaction", action="audit-consent-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: selected key audit confirmation: " + mode, file=sys.stderr)


def authorized(session, grant, sub, parameters=None):
    fields = {1: sub, **({2: parameters} if parameters is not None else {})}
    if grant is not None:
        version, token = grant
        message = b"\xff" * 32 + bytes([0x41, sub]) + (codec.encode(parameters) if parameters is not None else b"")
        fields.update({3: version, 4: token_mac(version, token, message)})
    return fields


def grant(session, version=2):
    policy = info(session).get(4, {})
    session.require(policy.get("clientPin") or session.options.device_pin_state == "unset", "PIN-unset audit consent needs --device-pin-state unset; getInfo does not expose the separate device PIN")
    return pin_token(session, 32, version=version) if policy.get("clientPin") else None


def call(session, fields):
    return session.ctap(0x41, fields)


def window(session, token):
    cue(session, "accept")
    value = session.ctap_value(call(session, authorized(session, token, 7)))
    session.check("audit window has a complete contiguous entry count", len(value[4]), (value[2] - value[1]) * 20)
    session.check("audit window stays in its ring bound", 0 <= value[2] - value[1] <= 128 and len(value[3]) == 32)
    for offset in range(0, len(value[4]), 20):
        session.check("audit entry sequence matches its exported position", int.from_bytes(value[4][offset:offset + 4], "little"), value[1] + offset // 20)
    return value


def verify_checkpoint(session, value, nonce, before):
    head = before[3]
    for at in range(0, len(before[4]), 20):
        head = hashlib.sha256(head + before[4][at:at + 20]).digest()
    session.check("checkpoint signs precisely the exported pre-command head and sequence", (value[1], value[2]), (head, before[2]))
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), value[4])
    message = AUDIT_CHECKPOINT_DOMAIN + value[1] + value[2].to_bytes(4, "little") + nonce
    verified(session, "audit checkpoint verifies its exact domain/head/sequence/nonce", public, -7, value[3], message)
    try:
        verify(public, -7, value[3], message + b"different nonce")
    except InvalidSignature:
        session.check("captured checkpoint cannot be replayed under a different nonce", True)
    else:
        session.check("captured checkpoint cannot be replayed under a different nonce", False)
    return value[4]


def acl(session):
    defects = ("missing-auth", "missing-protocol", "empty-auth", "short-auth", "long-auth", "wrong-MAC", "wrong-permission", "readonly", "protocol-zero", "protocol-unknown")
    for version, sub, defect in product((1, 2), (7, 8, 14), defects):
        with session.case(f"rsk.audit.ACL.protocol-{version}.sub-{sub}.{defect}", ("V07", "V08", "G01", "G03", "G04", "G10", "G13", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "audit ACL requires RS-Key", "excluded_by_profile")
            session.require(info(session).get(4, {}).get("clientPin"), "host-PIN authorization failure needs a known configured PIN")
            before = window(session, grant(session, version))
            permission = 2 if defect == "wrong-permission" else 64 if defect == "readonly" else 32
            session.require(permission != 64 or info(session).get(4, {}).get("perCredMgmtRO"), "read-only token not advertised", "unknown")
            owner = pin_token(session, permission, version=version)
            fields = authorized(session, owner, sub, {1: b"nonce"} if sub == 8 else {1: 1} if sub == 14 else None)
            if defect == "missing-auth":
                fields.pop(4)
            elif defect == "missing-protocol":
                fields.pop(3)
            elif defect in ("empty-auth", "short-auth", "long-auth"):
                fields[4] = b"" if defect == "empty-auth" else fields[4][:-1] if defect == "short-auth" else fields[4] + b"x"
            elif defect == "wrong-MAC":
                fields[4] = bytes([fields[4][0] ^ 1]) + fields[4][1:]
            elif defect.startswith("protocol-"):
                fields[3] = 0 if defect == "protocol-zero" else 3
            policy = session.ctap_value(vendor(session, 14, {1: 2}))[1]
            cue(session, "withhold")
            result = call(session, fields)
            expected = 0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else 2 if defect.startswith("protocol-") else 0x33
            session.check("audit authorization is refused before presence and nonce validation", result.status, expected)
            session.check("refused audit request discloses no journal or signature", result.data[1:], b"")
            session.check("audit authorization failure cannot change logging policy", session.ctap_value(vendor(session, 14, {1: 2}))[1], policy)
            session.check("audit authorization refusal preserves the complete pre-request journal", window(session, grant(session, version)), before)


def consent(session):
    for sub, mode in product((7, 8, 14), ("accept", "decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.audit.consent.sub-{sub}.{mode}", ("V07", "V08", "G10", "G11", "G12", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "audit consent requires RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "audit refusal needs a controlled operator action")
            session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features, "explicit audit decline needs the display profile", "excluded_by_profile")
            session.require(mode != "timeout" or session.options.timeout > 130, "audit timeout requires the full presence window")
            owner = grant(session)
            session.require(sub != 7 or owner is None or mode == "accept", "host-PIN AUDIT_READ needs no extra touch; refusal rows apply to an unprotected PIN-unset profile", "excluded_by_profile")
            policy = session.ctap_value(vendor(session, 14, {1: 2}))[1]
            before = window(session, owner)
            try:
                fields = authorized(session, owner, sub, {1: b"consent"} if sub == 8 else {1: int(not policy)} if sub == 14 else None)
                cue(session, mode)
                result = call(session, fields)
                if sub == 8 and mode == "accept":
                    session.require(result.status != 0x30, "checkpoint signing root is not provisioned", "unsupported_confirmed")
                session.check("audit consent has its distinct operation-denied result", result.status, 0 if mode == "accept" else 0x27)
                if mode != "accept":
                    session.check("audit refusal exposes no data", result.data[1:], b"")
                    session.check("audit refusal preserves the complete journal window", window(session, owner), before)
                    session.check("audit refusal preserves enabled policy", session.ctap_value(vendor(session, 14, {1: 2}))[1], policy)
                elif sub == 8:
                    verify_checkpoint(session, session.ctap_value(result), b"consent", before)
                elif sub == 14:
                    session.check("accepted audit configuration changes policy", session.ctap_value(result)[1], not policy)
                else:
                    session.check("read-only audit command has the same exact window", session.ctap_value(result), before)
            finally:
                if not session.broken:
                    cue(session, "accept")
                    if session.ctap_value(vendor(session, 14, {1: 2}))[1] != policy:
                        session.ctap_value(call(session, authorized(session, owner, 14, {1: int(policy)})))


def persistence(session):
    for enabled, action in product((False, True), Action):
        with session.case(f"rsk.audit.persistence.enabled-{enabled}.{action.value}", ("V07", "V08", "X11", "G11", "G14"), effects=("config_change", "reboot"), touch=True):
            session.require(session.profile == "rsk", "audit persistence requires RS-Key", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "control"), "audit persistence needs a defined connection backend", "excluded_by_mode")
            require_action(session, action)
            original = session.ctap_value(vendor(session, 14, {1: 2}))[1]
            try:
                owner = grant(session)
                cue(session, "accept")
                session.ctap_value(call(session, authorized(session, owner, 14, {1: int(enabled)})))
                before = window(session, owner)
                change(session, action)
                owner = grant(session)
                session.check("audit opt-in policy survives connection action", session.ctap_value(vendor(session, 14, {1: 2}))[1], enabled)
                after = window(session, owner)
                session.check("audit history never rewinds across connection action", after[2] >= before[2] and after[1] >= before[1])
                if not enabled:
                    session.check("disabled audit journal cannot append even on power-up", after, before)
                elif before[1] == after[1]:
                    session.check("reconnection preserves every preexisting journal entry", after[4][:len(before[4])], before[4])
            finally:
                if not session.broken:
                    cue(session, "accept")
                    session.ctap_value(call(session, authorized(session, grant(session), 14, {1: int(original)})))


def freshness(session):
    for length in (0, 1, 31, 32, 33):
        with session.case(f"rsk.audit.checkpoint.exact-nonce-and-replay.length-{length}", ("V07", "V08", "G01", "G03", "G09", "G11", "G14"), touch=True):
            session.require(session.profile == "rsk", "audit freshness requires RS-Key", "excluded_by_profile")
            owner = grant(session)
            nonce = session.fixture("audit.freshness", length)
            public = None
            for repeat in range(2):
                before = window(session, owner)
                cue(session, "accept")
                result = call(session, authorized(session, owner, 8, {1: nonce}))
                if length > 32:
                    session.check("oversized nonce has its exact parameter refusal", result.status, 2)
                    session.check("refused checkpoint cannot append its success event", window(session, owner), before)
                else:
                    session.require(result.status != 0x30, "checkpoint signing root is not provisioned", "unsupported_confirmed")
                    current = verify_checkpoint(session, session.ctap_value(result), nonce, before)
                    if public is not None:
                        session.check("checkpoint retry retains the device signing root", current, public)
                    public = current


def run(session):
    acl(session)
    consent(session)
    freshness(session)
    persistence(session)
