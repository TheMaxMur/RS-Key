#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Validate the self-published FIDO Metadata Statement against source + device.

    nix develop -c python tests/62_metadata_statement.py

This is a drift guard for `metadata/rs-key.metadata.json`. Parts A, C and D are
host-only, so `scripts/emu-suites.sh` sweeps them on every pull request; Part B
needs a device and is the half you run by hand on a board.

Part A (host-only, always runs):
  * required MDS3 statement fields present;
  * `aaguid` (dashed) == the firmware `AAGUID` const in rsk-fido/consts.rs
    == the dashless `authenticatorGetInfo.aaguid`;
  * attestation-root invariant: attestationTypes == ["basic_surrogate"] implies
    attestationRootCertificates == []; RS-Key declares ["basic_full"] and also
    lists no root, because its x5c leaf is a per-device self-signed certificate
    with no shareable root to publish;
  * `authenticationAlgorithms` (FIDO Registry strings) map exactly onto the
    classic COSE ids in `authenticatorGetInfo.algorithms`;
  * `authenticatorVersion` == `authenticatorGetInfo.firmwareVersion`;
  * `userVerificationDetails` names what the embedded getInfo's options claim:
    presence for `up`, a verification method for `uv`, passcode_external for
    `clientPin` (the conformance tool's Authr-Generic-1 P-2 and P-3).

Part B (runs only if a FIDO HID device is plugged in):
  * decodes the live `authenticatorGetInfo` and asserts it equals the embedded
    one, IGNORING the stateful fields (options.ep / options.clientPin /
    forcePINChange / minPINLength) which depend on PIN/enterprise state;
  * encIdentifier / encCredStoreState change on every call, so only presence is
    compared, one way: a member the device sends must be declared.

Part D (host-only, always runs): every published statement against the rules the
FIDO Metadata Statement spec (v3.1.1) and the FIDO Registry (v2.3) write down,
case by case as the conformance tool's metadata-stmt-1 names them.

The statement describes the DEFAULT (shipping) build profile, which advertises
EdDSA (-8): the Windows WebAuthn API drops unadvertised algorithms, breaking
`ssh-keygen -t ed25519-sk`. ES256K (-47) is never advertised (the FIDO
conformance tool cannot verify a secp256k1 self-attestation). The
`fido-conformance` build suppresses -8 too; its EdDSA-free metadata variant
`metadata/rs-key.conformance.metadata.json` is checked here to be exactly the
shipping statement minus EdDSA. `advertise-pqc` adds COSE -48 to algorithms and
`fips-profile` raises minPINLength — if the live device is one of those, Part B
says so instead of failing blindly.
"""
import base64
import hashlib
import json
import os
import re
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
META = os.path.join(ROOT, "metadata", "rs-key.metadata.json")
CONF_META = os.path.join(ROOT, "metadata", "rs-key.conformance.metadata.json")
U2F_META = os.path.join(ROOT, "metadata", "rs-key.u2f.metadata.json")
BUILD_RS = os.path.join(ROOT, "crates", "rsk-fido", "build.rs")

# FIDO Registry (v2.2) sign-algorithm string <-> COSE alg id, classic set only.
ALG_STR_TO_COSE = {
    "secp256r1_ecdsa_sha256_raw": -7,
    "ed25519_eddsa_sha512_raw": -8,
    "secp384r1_ecdsa_sha384_raw": -35,
    "secp521r1_ecdsa_sha512_raw": -36,
    "secp256k1_ecdsa_sha256_raw": -47,
}
COSE_MLDSA44 = -48

REQUIRED = [
    "aaguid", "description", "authenticatorVersion", "protocolFamily", "schema",
    "upv", "authenticationAlgorithms", "publicKeyAlgAndEncodings",
    "attestationTypes", "keyProtection", "matcherProtection", "tcDisplay",
    "attestationRootCertificates", "authenticatorGetInfo",
]
# Fields whose value tracks device state, not model identity.
STATEFUL = {"forcePINChange", "minPINLength", "remainingDiscoverableCredentials",
            "pinComplexityPolicy"}
# Re-encrypted under a fresh IV per call, so a statement carries each as the
# empty placeholder MDS3 takes, and only presence can be compared.
ENCRYPTED_MEMBERS = ((0x19, "encIdentifier"), (0x1E, "encCredStoreState"))
# `makeCredUvNotRqd` tracks alwaysUv (CTAP 2.1 §6.4 requires it false while alwaysUv
# is on), so like `alwaysUv` itself it is device state, not a statement property.
STATEFUL_OPTIONS = {"ep", "clientPin", "makeCredUvNotRqd"}
# Registry §3.1 methods that verify a user rather than only see one.
UV_METHODS = {
    "fingerprint_internal", "voiceprint_internal", "faceprint_internal", "eyeprint_internal",
    "handprint_internal", "pattern_internal", "pattern_external", "passcode_internal",
    "passcode_external",
}


def firmware_aaguid_bytes():
    # consts.rs const-parses the AAGUID from build.rs's PK_AAGUID (an `AAGUID=` env
    # overrides it at build time); the default UUID literal lives in build.rs.
    src = open(BUILD_RS).read()
    m = re.search(r'const DEFAULT:\s*&str\s*=\s*"([0-9a-fA-F-]+)"', src)
    if not m:
        sys.exit("could not find the default AAGUID in rsk-fido/build.rs")
    hexstr = m.group(1).replace("-", "").lower()
    if len(hexstr) != 32:
        sys.exit(f"AAGUID default has {len(hexstr)} hex chars, expected 32")
    return bytes.fromhex(hexstr)


def part_a(stmt):
    fails = []

    for f in REQUIRED:
        if f not in stmt:
            fails.append(f"missing required field: {f}")

    gi = stmt.get("authenticatorGetInfo", {})

    # aaguid: dashed <-> dashless <-> firmware const
    dashed = stmt.get("aaguid", "")
    meta_bytes = bytes.fromhex(dashed.replace("-", ""))
    gi_bytes = bytes.fromhex(gi.get("aaguid", ""))
    fw_bytes = firmware_aaguid_bytes()
    if meta_bytes != fw_bytes:
        fails.append(f"aaguid {meta_bytes.hex()} != firmware const {fw_bytes.hex()}")
    if gi_bytes != fw_bytes:
        fails.append(f"authenticatorGetInfo.aaguid {gi_bytes.hex()} != const {fw_bytes.hex()}")

    # surrogate-only invariant (basic_full stays rootless here on purpose: the
    # x5c leaf is per-device and self-signed)
    if stmt.get("attestationTypes") == ["basic_surrogate"]:
        if stmt.get("attestationRootCertificates") != []:
            fails.append("basic_surrogate requires an empty attestationRootCertificates")

    # authenticationAlgorithms strings map exactly onto the classic COSE ids
    want = {ALG_STR_TO_COSE[s] for s in stmt.get("authenticationAlgorithms", [])
            if s in ALG_STR_TO_COSE}
    unknown = [s for s in stmt.get("authenticationAlgorithms", []) if s not in ALG_STR_TO_COSE]
    if unknown:
        fails.append(f"unknown authenticationAlgorithms strings: {unknown}")
    gi_cose = {a["alg"] for a in gi.get("algorithms", [])}
    if COSE_MLDSA44 in gi_cose:
        fails.append("default-profile statement should NOT advertise COSE -48 (ML-DSA)")
    if want != gi_cose:
        fails.append(f"alg mismatch: metadata {sorted(want)} vs getInfo {sorted(gi_cose)}")

    if stmt.get("authenticatorVersion") != gi.get("firmwareVersion"):
        fails.append("authenticatorVersion != authenticatorGetInfo.firmwareVersion")

    for _, name in ENCRYPTED_MEMBERS:
        if gi.get(name, "") != "":
            fails.append(f"authenticatorGetInfo.{name} must be the empty placeholder")

    # Authr-Generic-1 P-2/P-3: `up` defaults to true (CTAP 2.3 §6.4), and a clientPin
    # the device supports, set or not, is a passcode entered on the platform.
    opts = gi.get("options", {})
    methods = {d.get("userVerificationMethod")
               for combo in stmt.get("userVerificationDetails", []) for d in combo}
    fails += [f"getInfo option {k} is not a boolean" for k, v in opts.items()
              if not isinstance(v, bool)]
    if opts.get("up", True) and "presence_internal" not in methods:
        fails.append("getInfo claims up, userVerificationDetails lacks presence_internal")
    if opts.get("uv") and not methods & UV_METHODS:
        fails.append("getInfo claims uv, userVerificationDetails names no way to verify")
    if not opts.get("up", True) and not opts.get("uv") and "none" not in methods:
        fails.append("getInfo claims neither up nor uv, userVerificationDetails lacks none")
    if "clientPin" in opts and "passcode_external" not in methods:
        fails.append("getInfo supports clientPin, userVerificationDetails lacks passcode_external")

    if fails:
        for f in fails:
            print(f"  FAIL: {f}")
        sys.exit(f"Part A: {len(fails)} failure(s)")
    print(f"Part A OK — aaguid {dashed}, algs {sorted(want)}, fw {gi.get('firmwareVersion')}")


def check_conformance_variant(stmt):
    """The conformance metadata must equal the shipping statement minus EdDSA.

    The `fido-conformance` build drops EdDSA (-8) from getInfo (the conformance
    tool cannot verify an EdDSA self-attestation), so the operator feeds the tool
    `rs-key.conformance.metadata.json`. Deriving it as "shipping minus EdDSA"
    guarantees the two never disagree on anything else.
    """
    if not os.path.exists(CONF_META):
        print("conformance variant: absent (skipped)")
        return
    conf = json.load(open(CONF_META))
    expected = json.loads(json.dumps(stmt))  # deep copy
    expected["authenticationAlgorithms"] = [
        a for a in expected["authenticationAlgorithms"]
        if a != "ed25519_eddsa_sha512_raw"
    ]
    expected["authenticatorGetInfo"]["algorithms"] = [
        a for a in expected["authenticatorGetInfo"]["algorithms"] if a["alg"] != -8
    ]
    gi = conf.get("authenticatorGetInfo", {})
    fails = []
    if "ed25519_eddsa_sha512_raw" in conf.get("authenticationAlgorithms", []):
        fails.append("conformance variant must not list ed25519_eddsa_sha512_raw")
    if any(a["alg"] == -8 for a in gi.get("algorithms", [])):
        fails.append("conformance variant must not advertise COSE -8")
    if conf != expected:
        fails.append("conformance variant must equal the shipping statement minus EdDSA (-8)")
    if fails:
        for f in fails:
            print(f"  FAIL: {f}")
        sys.exit(f"conformance variant: {len(fails)} failure(s)")
    print("conformance variant OK — shipping statement minus EdDSA (-8)")


def _norm(gi, drop_u2f=False):
    """Drop stateful fields so the static surface can be compared. When the live
    device has alwaysUv on, CTAP 2.1 §7.2.4 disables CTAP1/U2F so U2F_V2 legitimately
    drops from versions — harmonize both sides on that projection."""
    out = {k: v for k, v in gi.items() if k not in STATEFUL}
    if "options" in out:
        out["options"] = {k: v for k, v in out["options"].items() if k not in STATEFUL_OPTIONS}
    if drop_u2f and "versions" in out:
        out["versions"] = [v for v in out["versions"] if v != "U2F_V2"]
    return out


def part_b(stmt):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import importlib
        ten = importlib.import_module("10_fido_getinfo")
        import hid  # noqa: F401
    except Exception as e:
        print(f"Part B skipped (no hid / helper): {e}")
        return
    info = ten.find()
    if not info:
        print("Part B skipped — no FIDO HID device plugged in")
        return
    dev = ten.hid.device()
    dev.open_path(info["path"])
    try:
        ten.write(dev, b"\xff\xff\xff\xff" + bytes([ten.CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = ten.read(dev)[15:19]
        resp = ten.send_cbor(dev, cid, b"\x04")
        assert resp[0] == 0x00, f"getInfo status {resp[0]:#x}"
        m = ten.decode(resp[1:])
    finally:
        dev.close()

    live = {
        "versions": m[0x01],
        "extensions": m[0x02],
        "aaguid": m[0x03].hex(),
        "options": m[0x04],
        "maxMsgSize": m[0x05],
        "pinUvAuthProtocols": m[0x06],
        "maxCredentialCountInList": m[0x07],
        "maxCredentialIdLength": m[0x08],
        "algorithms": [{"alg": a["alg"], "type": a["type"]} for a in m[0x0A]],
        # 0x0B is profile-dependent: a `largeblob-ext` build withdraws it with the
        # command it describes, so read it leniently and decide below rather than
        # dying on a KeyError.
        "maxSerializedLargeBlobArray": m.get(0x0B),
        "forcePINChange": m[0x0C],
        "minPINLength": m[0x0D],
        "firmwareVersion": m[0x0E],
        "maxCredBlobLength": m[0x0F],
        "transports": m[0x09],
        "maxRPIDsForSetMinPINLength": m[0x10],
        "remainingDiscoverableCredentials": m[0x14],
        # A member missing from THIS map reads as a drift against the statement,
        # not as an oversight — add both together.
        "vendorPrototypeConfigCommands": m[0x15],
        "attestationFormats": m[0x16],
        "longTouchForReset": m[0x18],
        "transportsForReset": m[0x1A],
        "pinComplexityPolicy": m[0x1B],
        "maxPINLength": m[0x1D],
        "authenticatorConfigCommands": m[0x1F],
    }
    # A member the device sends must be declared, which is the pinned P-1 rule.
    sent = {name for key, name in ENCRYPTED_MEMBERS if key in m}
    for name in sent:
        live[name] = ""
    # The shipped statements describe builds that serve the CTAP 2.1 large-blob
    # design. A `largeblob-ext` build swaps it for the 2.3 extension (§12.4 forbids
    # both), so its getInfo is a different profile — say so instead of reporting
    # every withdrawn member as drift.
    if "largeBlob" in live["extensions"]:
        print("NOTE: live device is a largeblob-ext build (CTAP 2.3 largeBlob in place "
              "of largeBlobKey); the statements target the 2.1 profile — comparison skipped.")
        return

    live_algs = {a["alg"] for a in live["algorithms"]}
    if COSE_MLDSA44 in live_algs:
        print("NOTE: live device is an advertise-pqc build (COSE -48 present); "
              "the statement targets the DEFAULT profile — comparison skipped.")
        return

    # Pick the metadata profile matching the live device: the default build
    # advertises EdDSA (-8); the fido-conformance build drops it (and pairs with
    # the EdDSA-free variant).
    ref = stmt
    if -8 not in live_algs and os.path.exists(CONF_META):
        ref = json.load(open(CONF_META))
        print("NOTE: live device is a fido-conformance build (no EdDSA -8); "
              "comparing against the conformance variant.")

    always_uv_on = bool(live.get("options", {}).get("alwaysUv"))
    want = _norm(ref["authenticatorGetInfo"], drop_u2f=always_uv_on)
    got = _norm(live, drop_u2f=always_uv_on)
    # One the device withholds is not drift: a PIN set, change or forced change
    # revokes the grant both are sealed under until the next boot or pcmr request,
    # and a soft lock hides 0x19. P-1 checks the other direction only.
    for _, name in ENCRYPTED_MEMBERS:
        if name not in sent and want.pop(name, None) is not None:
            print(f"NOTE: the device withholds {name} right now — its placeholder is "
                  "compared only when the member is sent.")
    if want != got:
        for k in sorted(set(want) | set(got)):
            if want.get(k) != got.get(k):
                print(f"  DRIFT {k}: statement={want.get(k)} device={got.get(k)}")
        sys.exit("Part B: live getInfo drifted from the statement")
    print(f"Part B OK — live device getInfo matches the statement "
          f"(stateful fields {sorted(STATEFUL | STATEFUL_OPTIONS)} ignored)")


def part_c(stmt):
    """Every published statement through python-fido2's own MDS3 model — a second
    reader of the same bytes, the one a relying party's library uses."""
    from fido2.mds3 import MetadataStatement

    fails = []
    paths = [p for p in (META, CONF_META, U2F_META) if os.path.exists(p)]
    for path in paths:
        raw = json.load(open(path))
        name = os.path.basename(path)
        try:
            parsed = MetadataStatement.from_dict(raw)
        except Exception as e:  # noqa: BLE001 — any refusal is the finding
            fails.append(f"{name}: python-fido2 refuses it — {type(e).__name__}: {e}")
            continue
        if parsed.authenticator_version != raw["authenticatorVersion"]:
            fails.append(f"{name}: authenticatorVersion read back as {parsed.authenticator_version}")
        if raw.get("aaguid") and str(parsed.aaguid) != raw["aaguid"]:
            fails.append(f"{name}: aaguid read back as {parsed.aaguid}")

    # A parser that takes anything proves nothing about what it took: the same
    # statement without a required member must be refused.
    try:
        MetadataStatement.from_dict({k: v for k, v in stmt.items() if k != "attestationTypes"})
        fails.append("python-fido2 accepted a statement with no attestationTypes — Part C proves nothing")
    except Exception:  # noqa: BLE001 — the refusal is the point
        pass

    if fails:
        for f in fails:
            print(f"  FAIL: {f}")
        sys.exit(f"Part C: {len(fails)} failure(s)")
    print(f"Part C OK — {len(paths)} statement(s) parse under python-fido2's MDS3 model")


# Part D reads FIDO Metadata Statement v3.1.1 PS 2026-01-05 ("MDS") and the FIDO Registry
# of Predefined Values v2.3 PS it cites ("Registry"). The case ids are the conformance
# tool's metadata-stmt-1; the rules are written from the spec text, not from the tool.
STATEMENT_FAMILIES = {META: "fido2", CONF_META: "fido2", U2F_META: "u2f"}
PROTOCOL_FAMILIES = ("uaf", "u2f", "fido2")
MDS3_SCHEMA = 3
MDS3_DESCRIPTION_MAX = 200
# MDS §4: the members of the MetadataStatement dictionary.
MDS3_MEMBERS = {
    "legalHeader", "aaid", "aaguid", "attestationCertificateKeyIdentifiers", "friendlyNames",
    "description", "alternativeDescriptions", "authenticatorVersion", "protocolFamily",
    "schema", "upv", "authenticationAlgorithms", "publicKeyAlgAndEncodings",
    "attestationTypes", "userVerificationDetails", "keyProtection", "isKeyRestricted",
    "isFreshUserVerificationRequired", "matcherProtection", "cryptoStrength",
    "attachmentHint", "tcDisplay", "tcDisplayContentType", "tcDisplayPNGCharacteristics",
    "attestationRootCertificates", "ecdaaTrustAnchors", "icon", "iconDark",
    "providerLogoLight", "providerLogoDark", "supportedExtensions",
    "multiDeviceCredentialSupport", "authenticatorGetInfo", "cxConfigURL",
}
# MDS keeps no list of what it dropped, so this is the IDL diffed across editions:
# 2.0 (RD 2018-07-02) -> 3.0, and 3.1 -> 3.1.1; 3.0 -> 3.1 dropped nothing.
MDS3_DROPPED = {
    "assertionScheme": "3.0", "authenticationAlgorithm": "3.0",
    "publicKeyAlgAndEncoding": "3.0", "operatingEnv": "3.0", "isSecondFactorOnly": "3.0",
    "keyScope": "3.1.1", "cxpConfigURL": "3.1.1",
}
# MDS §4 upv. FIDO2 maps each CTAP 2.3 §6.4 version string; 1.2 is reserved because
# CTAP 2.2 was skipped, and defines no "FIDO_2_2". U2F is 1.0, 1.1 or 1.2 (CTAP1).
FIDO2_UPV = {"FIDO_2_0": (1, 0), "FIDO_2_1": (1, 1), "FIDO_2_3": (1, 3)}
FIDO2_UPV_RESERVED = {(1, 2)}
U2F_UPV = {(1, 0), (1, 1), (1, 2)}
# MDS §3.1 writes an AAGUID the RFC 4122 way, which outputs lower-case hex; §4 wants
# each attestation key identifier as RFC 5280 method 1 (a SHA-1) in lower-case hex.
AAGUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
KEY_IDENTIFIER_RE = r"[0-9a-f]{40}"
# Registry §3.1-§3.7: the strings a statement may carry, and the pairs the Registry
# calls exclusive "in authenticator metadata".
USER_VERIFY = {
    "presence_internal", "fingerprint_internal", "passcode_internal", "voiceprint_internal",
    "faceprint_internal", "location_internal", "eyeprint_internal", "pattern_internal",
    "handprint_internal", "passcode_external", "pattern_external", "none", "all",
}
KEY_PROTECTION = {"software", "hardware", "tee", "secure_element", "remote_handle", "sync_fabric"}
MATCHER_PROTECTION = {"software", "tee", "on_chip"}
ATTACHMENT_HINTS = {
    "internal", "external", "wired", "wireless", "nfc", "bluetooth", "network", "ready",
    "wifi_direct", "smart-card",
}
TC_DISPLAY = {"any", "privileged_software", "tee", "hardware", "remote"}
PUBLIC_KEY_ENCODINGS = {"ecc_x962_raw", "ecc_x962_der", "rsa_2048_raw", "rsa_2048_der", "cose"}
ATTESTATION_TYPES = {"basic_full", "basic_surrogate", "ecdaa", "attca", "anonca", "none"}
KEY_PROTECTION_EXCLUSIVE = (("software", "hardware"), ("software", "tee"),
                            ("software", "secure_element"), ("tee", "secure_element"))
MATCHER_PROTECTION_EXCLUSIVE = (("software", "tee"), ("software", "on_chip"), ("tee", "on_chip"))
TC_DISPLAY_EXCLUSIVE = (("privileged_software", "tee"), ("privileged_software", "hardware"),
                        ("tee", "hardware"))
# MDS §3.2-§3.5: the methods each accuracy descriptor may describe, and its members as
# (bits of the WebIDL unsigned type, or None for a double; required).
ACCURACY_DESCRIPTORS = {
    "caDesc": ({"passcode_internal", "passcode_external"},
               {"base": (16, True), "minLength": (16, True),
                "maxRetries": (16, False), "blockSlowdown": (16, False)}),
    "baDesc": ({"fingerprint_internal", "voiceprint_internal", "faceprint_internal",
                "eyeprint_internal", "handprint_internal"},
               {"selfAttestedFRR": (None, False), "selfAttestedFAR": (None, False),
                "iAPARThreshold": (None, False), "maxTemplates": (16, False),
                "maxRetries": (16, False), "blockSlowdown": (16, False)}),
    "paDesc": ({"pattern_internal", "pattern_external"},
               {"minComplexity": (32, True), "maxRetries": (16, False),
                "blockSlowdown": (16, False)}),
}
# FIDO's own sample statement (MDS §5, which the conformance tool ships as well); the
# icon and the root certificate are matched by the SHA-256 of their decoded bytes.
SAMPLE_AAGUID = "0132d110-bf4e-4208-a403-ab4f5f12efe5"
SAMPLE_DESCRIPTIONS = ("FIDO Alliance Sample FIDO2 Authenticator",
                       "FIDO Alliance Sample U2F Authenticator",
                       "FIDO Alliance Sample UAF Authenticator")
SAMPLE_KEY_IDENTIFIER = "7c0903708b87115b0b422def3138c3c864e44573"
SAMPLE_ICON_SHA256 = "da81834275ebee7dd076f3be596a8ef3a2ba83ae88ee33a376ec280a4f9716e6"
SAMPLE_ROOT_SHA256 = "7231962210d2933ec993a77b4a7203898ab74cdf974ff02d2de3f1ec7cb9de68"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _uint(value, bits):
    """A WebIDL unsigned integer as JSON carries it: an int in range, never a bool."""
    return type(value) is int and 0 <= value < 1 << bits


def _registered(stmt, member, allowed, case, out, empty_ok=False):
    """The Registry strings a list member carries. A missing member, an empty list
    where MDS §1 bars one, and every string the Registry lacks are findings."""
    value = stmt.get(member)
    if not isinstance(value, list) or not (value or empty_ok):
        out.append((case, member, "must be a list of Registry strings"
                    + ("" if empty_ok else ", and not empty (MDS §1)")))
        return set()
    unknown = [v for v in value if not (isinstance(v, str) and v in allowed)]
    if unknown:
        out.append((case, member, f"{unknown} not in the FIDO Registry"))
    return {v for v in value if isinstance(v, str) and v in allowed}


def _exclusive(names, pairs, member, case, out):
    for a, b in pairs:
        if a in names and b in names:
            out.append((case, member, f'"{a}" and "{b}" are exclusive in metadata (Registry)'))


def _versions(stmt):
    """The version strings the embedded authenticatorGetInfo claims."""
    gi = stmt.get("authenticatorGetInfo")
    versions = gi.get("versions") if isinstance(gi, dict) else None
    return [v for v in versions if isinstance(v, str)] if isinstance(versions, list) else []


def _data_url_png(url):
    """The bytes a base64 `data:image/png` URL (RFC 2397) carries, else None."""
    if not isinstance(url, str) or not url.startswith("data:"):
        return None
    header, _, payload = url[len("data:"):].partition(",")
    if header.lower() != "image/png;base64":
        return None
    try:
        return base64.b64decode(payload, validate=True)
    except ValueError:
        return None


def _check_members(stmt, family, out):
    # metadata-stmt-1 P-33 / P-34: a reader keyed on MDS3 ignores a member a later
    # edition dropped, or one outside the §4 dictionary, without a word.
    for key in stmt:
        if key in MDS3_DROPPED:
            out.append(("P-33", key, f"was dropped from the statement in MDS {MDS3_DROPPED[key]}"))
        elif key not in MDS3_MEMBERS:
            out.append(("P-34", key, "is not a MetadataStatement member (MDS §4)"))


def _check_scalars(stmt, family, out):
    # metadata-stmt-1 P-1/P-36: §4 wants a legalHeader in each statement and §1 bars
    # an empty DOMString; the text itself MDS gives only as an example.
    header = stmt.get("legalHeader")
    if not (isinstance(header, str) and header):
        out.append(("P-1", "legalHeader", "must be present and not empty (MDS §4)"))
    # metadata-stmt-1 P-4: "only ASCII characters" — any ASCII, since MDS §4 does not
    # say printable — and at most 200 of them.
    desc = stmt.get("description")
    if not (isinstance(desc, str) and desc):
        out.append(("P-4", "description", "must be present and not empty (MDS §4)"))
    else:
        if not desc.isascii():
            out.append(("P-4", "description", "must contain only ASCII characters (MDS §4)"))
        if len(desc) > MDS3_DESCRIPTION_MAX:
            out.append(("P-4", "description",
                        f"is {len(desc)} characters; MDS §4 allows {MDS3_DESCRIPTION_MAX}"))
    # metadata-stmt-1 P-7: a family MDS §4 names, and the one this file publishes.
    family_value = stmt.get("protocolFamily")
    if family_value not in PROTOCOL_FAMILIES:
        out.append(("P-7", "protocolFamily", f"{family_value!r} is none of {PROTOCOL_FAMILIES}"))
    elif family_value != family:
        out.append(("P-7", "protocolFamily",
                    f"is {family_value!r}, but this file publishes the {family!r} statement"))
    # metadata-stmt-1 P-20: bits of strength when claimed; absent means unknown.
    strength = stmt.get("cryptoStrength")
    if "cryptoStrength" in stmt and not (_uint(strength, 16) and strength > 0):
        out.append(("P-20", "cryptoStrength", f"{strength!r} is not a positive unsigned short"))
    # metadata-stmt-1 P-31: the schema version of this edition.
    schema = stmt.get("schema")
    if not (_uint(schema, 16) and schema == MDS3_SCHEMA):
        out.append(("P-31", "schema", f"is {schema!r}; MDS §4 makes it {MDS3_SCHEMA}"))


def _check_family(stmt, family, out):
    # metadata-stmt-1 P-3, MDS §4: FIDO2 MUST set aaguid and supports no AAID; with
    # neither aaid nor aaguid the attestation key identifiers MUST be set; and
    # supportedExtensions applies to UAF only.
    if family == "fido2":
        aaguid = stmt.get("aaguid")
        if not (isinstance(aaguid, str) and re.fullmatch(AAGUID_RE, aaguid)):
            out.append(("P-3", "aaguid",
                        f"MUST be an MDS §3.1 AAGUID on a fido2 statement; got {aaguid!r}"))
        for member in ("aaid", "attestationCertificateKeyIdentifiers"):
            if member in stmt:
                out.append(("P-3", member, "does not belong on a fido2 statement"))
    ids = stmt.get("attestationCertificateKeyIdentifiers")
    if ids is None and "aaid" not in stmt and "aaguid" not in stmt:
        out.append(("P-3", "attestationCertificateKeyIdentifiers",
                    "MUST be set when neither aaid nor aaguid is (MDS §4)"))
    elif ids is not None and not (isinstance(ids, list) and ids and all(
            isinstance(i, str) and re.fullmatch(KEY_IDENTIFIER_RE, i) for i in ids)):
        out.append(("P-3", "attestationCertificateKeyIdentifiers",
                    "must be a non-empty list of lower-case hex SHA-1 key identifiers"))
    if "supportedExtensions" in stmt and family != "uaf":
        out.append(("P-3", "supportedExtensions", "applies to UAF authenticators only (MDS §4)"))
    if family == "u2f":
        if "authenticatorGetInfo" in stmt:
            out.append(("P-3", "authenticatorGetInfo",
                        "U2F authenticators do not support it (MDS §4)"))
        if stmt.get("authenticationAlgorithms") != ["secp256r1_ecdsa_sha256_raw"]:
            out.append(("P-3", "authenticationAlgorithms",
                        'FIDO U2F has the one algorithm "secp256r1_ecdsa_sha256_raw" (MDS §4)'))


def _check_upv(stmt, family, out):
    # metadata-stmt-1 P-8: a non-empty list of UAF Protocol §3.1.1 Versions, each
    # exactly {major, minor}, both unsigned short.
    upv = stmt.get("upv")
    if not (isinstance(upv, list) and upv):
        out.append(("P-8", "upv", "must be a non-empty list of {major, minor} (MDS §4)"))
        upv = []
    have = set()
    for i, version in enumerate(upv):
        if (isinstance(version, dict) and version.keys() == {"major", "minor"}
                and _uint(version["major"], 16) and _uint(version["minor"], 16)):
            have.add((version["major"], version["minor"]))
        else:
            out.append(("P-8", f"upv[{i}]", "must be {major, minor}, both unsigned short"))
    if family == "u2f":
        for major, minor in sorted(have - U2F_UPV):
            out.append(("P-8", "upv", f"{major}.{minor} is not a U2F version (MDS §4: 1.0-1.2)"))
    elif family == "fido2":
        # metadata-stmt-1 P-32: a fido2 statement carries getInfo, and its upv set is
        # exactly what getInfo.versions maps to.
        if not isinstance(stmt.get("authenticatorGetInfo"), dict):
            out.append(("P-32", "authenticatorGetInfo",
                        "MUST be present on a fido2 statement (MDS §4)"))
            return
        versions = _versions(stmt)
        want = {FIDO2_UPV[v] for v in versions if v in FIDO2_UPV}
        for major, minor in sorted(have - want):
            why = ("is reserved: CTAP 2.2 was skipped" if (major, minor) in FIDO2_UPV_RESERVED
                   else "is what no entry of authenticatorGetInfo.versions maps to")
            out.append(("P-32", "upv", f"{major}.{minor} {why} (MDS §4 upv)"))
        for v in versions:
            if v in FIDO2_UPV and FIDO2_UPV[v] not in have:
                major, minor = FIDO2_UPV[v]
                out.append(("P-32", "upv", f"lacks {major}.{minor}, which getInfo's {v} maps to"))


def _check_registered(stmt, family, out):
    # metadata-stmt-1 P-13 / P-14: Registry §3.6.2 and §3.7 strings; FIDO U2F has the
    # one key encoding (MDS §4 publicKeyAlgAndEncodings).
    _registered(stmt, "publicKeyAlgAndEncodings", PUBLIC_KEY_ENCODINGS, "P-13", out)
    if family == "u2f" and stmt.get("publicKeyAlgAndEncodings") != ["ecc_x962_raw"]:
        out.append(("P-13", "publicKeyAlgAndEncodings",
                    'FIDO U2F has the one encoding "ecc_x962_raw" (MDS §4)'))
    _registered(stmt, "attestationTypes", ATTESTATION_TYPES, "P-14", out)
    # metadata-stmt-1 P-16 / P-19: Registry §3.2 and §3.3 with their exclusive pairs;
    # remote_handle MUST be set together with another key protection type.
    keys = _registered(stmt, "keyProtection", KEY_PROTECTION, "P-16", out)
    _exclusive(keys, KEY_PROTECTION_EXCLUSIVE, "keyProtection", "P-16", out)
    if keys == {"remote_handle"}:
        out.append(("P-16", "keyProtection", '"remote_handle" MUST be combined with another type'))
    matcher = _registered(stmt, "matcherProtection", MATCHER_PROTECTION, "P-19", out)
    _exclusive(matcher, MATCHER_PROTECTION_EXCLUSIVE, "matcherProtection", "P-19", out)
    # metadata-stmt-1 P-22: Registry §3.4 — "internal" only ever stands alone and
    # "external" never does; MDS §4 requires the member from CTAP 2.2 on, i.e. past upv 1.1.
    if "attachmentHint" in stmt:
        hints = _registered(stmt, "attachmentHint", ATTACHMENT_HINTS, "P-22", out)
        if "internal" in hints and len(hints) > 1:
            out.append(("P-22", "attachmentHint",
                        '"internal" cannot be combined with another hint (Registry §3.4)'))
        if hints == {"external"}:
            out.append(("P-22", "attachmentHint",
                        '"external" MUST be combined with another hint (Registry §3.4)'))
    elif any(FIDO2_UPV.get(v, (1, 0)) > FIDO2_UPV["FIDO_2_1"] for v in _versions(stmt)):
        out.append(("P-22", "attachmentHint", "MUST be present for CTAP 2.2 or newer (MDS §4)"))


def _check_uv_details(stmt, family, out):
    # metadata-stmt-1 P-15: alternatives, each a non-empty AND-list of
    # VerificationMethodDescriptor (MDS §3.5, §3.6); the member itself is optional.
    if "userVerificationDetails" not in stmt:
        return
    alternatives = stmt["userVerificationDetails"]
    if not (isinstance(alternatives, list) and alternatives):
        out.append(("P-15", "userVerificationDetails", "must be a non-empty list of combinations"))
        return
    for i, combination in enumerate(alternatives):
        where = f"userVerificationDetails[{i}]"
        if not (isinstance(combination, list) and combination):
            out.append(("P-15", where, "must be a non-empty list of VerificationMethodDescriptor"))
            continue
        for j, descriptor in enumerate(combination):
            _check_uv_method(descriptor, f"{where}[{j}]", out)


def _check_uv_method(descriptor, where, out):
    if not isinstance(descriptor, dict):
        out.append(("P-15", where, "must be a VerificationMethodDescriptor"))
        return
    method = descriptor.get("userVerificationMethod")
    uvm = f"{where}.userVerificationMethod"
    if method == "all":
        out.append(("P-15", uvm, '"all" MUST NOT be used here (MDS §3.5)'))
    elif not (isinstance(method, str) and method in USER_VERIFY):
        out.append(("P-15", uvm, f"{method!r} is not in Registry §3.1"))
    for key in sorted(descriptor.keys() - {"userVerificationMethod"} - ACCURACY_DESCRIPTORS.keys()):
        out.append(("P-15", f"{where}.{key}", "is not a VerificationMethodDescriptor member"))
    # An accuracy descriptor rides only on the methods MDS §3.5 names for it, with its
    # §3.2-§3.4 members; a baDesc MUST set at least one, the others have required ones.
    for name, (methods, members) in ACCURACY_DESCRIPTORS.items():
        if name not in descriptor:
            continue
        accuracy = descriptor[name]
        if not (isinstance(method, str) and method in methods):
            out.append(("P-15", f"{where}.{name}", f"describes only {sorted(methods)}"))
        if not (isinstance(accuracy, dict) and accuracy):
            out.append(("P-15", f"{where}.{name}", "must be a dictionary with at least one member"))
            continue
        for key in sorted(accuracy.keys() - members.keys()):
            out.append(("P-15", f"{where}.{name}.{key}", f"is not a {name} member"))
        for key, (bits, required) in members.items():
            if key not in accuracy:
                if required:
                    out.append(("P-15", f"{where}.{name}.{key}", "is required"))
            elif not (_uint(accuracy[key], bits) if bits else type(accuracy[key]) in (int, float)):
                kind = f"a {bits}-bit unsigned integer" if bits else "a number"
                out.append(("P-15", f"{where}.{name}.{key}", f"must be {kind}"))


def _check_tc_display(stmt, family, out):
    # metadata-stmt-1 P-24: Registry §3.5 strings in a valid combination: "any" MUST
    # be set whenever a display exists, and its three implementations exclude one another.
    shown = _registered(stmt, "tcDisplay", TC_DISPLAY, "P-24", out, empty_ok=True)
    _exclusive(shown, TC_DISPLAY_EXCLUSIVE, "tcDisplay", "P-24", out)
    display = stmt.get("tcDisplay")
    if not (isinstance(display, list) and display):
        return
    if "any" not in shown:
        out.append(("P-24", "tcDisplay", '"any" MUST be set when a display is available'))
    # metadata-stmt-1 P-25 / P-26, MDS §4: a display needs its MIME type, and a PNG one
    # its image characteristics.
    content_type = stmt.get("tcDisplayContentType")
    png_traits = stmt.get("tcDisplayPNGCharacteristics")
    if not (isinstance(content_type, str) and content_type):
        out.append(("P-25", "tcDisplayContentType", "MUST be present when tcDisplay is not empty"))
    elif content_type.lower() == "image/png" and not (isinstance(png_traits, list) and png_traits):
        out.append(("P-26", "tcDisplayPNGCharacteristics",
                    "MUST be present for an image/png display"))


def _check_icon(stmt, family, out):
    # metadata-stmt-1 P-29: MDS §4 allows a PNG or an SVG data: URL; this holds the PNG
    # form the statements use — the signature, then a whole IHDR chunk (length 13, type,
    # data, CRC-32 over type and data). An SVG icon would need its own branch here.
    if "icon" not in stmt:
        return
    png = _data_url_png(stmt["icon"])
    if png is None:
        out.append(("P-29", "icon", "must be a base64 data:image/png URL (RFC 2397)"))
        return
    ihdr = png[8:33]
    if not (png.startswith(PNG_SIGNATURE) and ihdr[:8] == b"\x00\x00\x00\x0dIHDR"
            and ihdr[21:] == zlib.crc32(ihdr[4:21]).to_bytes(4, "big")):
        out.append(("P-29", "icon", "does not decode to a PNG (signature, then an IHDR chunk)"))


def _check_samples(stmt, family, out):
    # metadata-stmt-1 P-35: a value copied from FIDO's sample statement says the
    # statement was never finished.
    aaguid = stmt.get("aaguid")
    if isinstance(aaguid, str) and aaguid.lower() == SAMPLE_AAGUID:
        out.append(("P-35", "aaguid", "is the AAGUID of FIDO's sample statement (MDS §5.3)"))
    if stmt.get("description") in SAMPLE_DESCRIPTIONS:
        out.append(("P-35", "description", "is a FIDO sample statement's description (MDS §5)"))
    ids = stmt.get("attestationCertificateKeyIdentifiers")
    if isinstance(ids, list) and SAMPLE_KEY_IDENTIFIER in ids:
        out.append(("P-35", "attestationCertificateKeyIdentifiers",
                    "lists the key of FIDO's sample statement (MDS §5.2)"))
    png = _data_url_png(stmt.get("icon"))
    if png is not None and hashlib.sha256(png).hexdigest() == SAMPLE_ICON_SHA256:
        out.append(("P-35", "icon", "is the icon of FIDO's sample statements (MDS §5)"))
    roots = stmt.get("attestationRootCertificates")
    for i, cert in enumerate(roots if isinstance(roots, list) else []):
        try:
            der = base64.b64decode(cert, validate=True)
        except (TypeError, ValueError):
            continue
        if hashlib.sha256(der).hexdigest() == SAMPLE_ROOT_SHA256:
            out.append(("P-35", f"attestationRootCertificates[{i}]",
                        "is the root of FIDO's sample statements (MDS §5)"))


def mds3_problems(stmt, family):
    """Every MDS / Registry rule `stmt` breaks, as (case, member, detail) — typed, so
    the self-test can ask which rule answered. `family` is the one its file publishes,
    so a wrong protocolFamily is one finding rather than a different rulebook."""
    out = []
    for check in (_check_members, _check_scalars, _check_family, _check_upv,
                  _check_registered, _check_uv_details, _check_tc_display,
                  _check_icon, _check_samples):
        check(stmt, family, out)
    return out


def part_d(stmt):
    """Every published statement against the MDS3 statement rules: the FIDO Metadata
    Statement spec's and the FIDO Registry's own text, one metadata-stmt-1 case each.
    Part C asks whether a relying party's parser takes the file; this asks the spec."""
    fails = []
    paths = [p for p in STATEMENT_FAMILIES if os.path.exists(p)]
    for path in paths:
        name = os.path.basename(path)
        family = STATEMENT_FAMILIES[path]
        for case, member, detail in mds3_problems(json.load(open(path)), family):
            fails.append(f"{name}: {member}: {detail} [metadata-stmt-1 {case}]")

    # A checker that passes everything proves nothing: the shipping statement broken
    # five ways at once must be reported five times, each by the rule it breaks.
    broken = json.loads(json.dumps(stmt))  # deep copy
    broken["description"] = "x" * (MDS3_DESCRIPTION_MAX + 1)
    broken["protocolFamily"] = "uaf"
    broken["notAnMds3Member"] = True
    broken["icon"] = "data:image/png;base64," + base64.b64encode(b"GIF89a").decode()
    broken["schema"] = MDS3_SCHEMA - 1
    want = {("P-4", "description"), ("P-7", "protocolFamily"), ("P-34", "notAnMds3Member"),
            ("P-29", "icon"), ("P-31", "schema")}
    got = {(case, member) for case, member, _ in mds3_problems(broken, STATEMENT_FAMILIES[META])}
    for case, member in sorted(want - got):
        fails.append(f"self-test: {os.path.basename(META)} with {member} broken passed {case}"
                     " — Part D proves nothing")

    if fails:
        for f in fails:
            print(f"  FAIL: {f}")
        sys.exit(f"Part D: {len(fails)} failure(s)")
    print(f"Part D OK — {len(paths)} statement(s) hold the MDS 3.1.1 / Registry 2.3 rules")


def main():
    stmt = json.load(open(META))
    part_a(stmt)
    check_conformance_variant(stmt)
    part_c(stmt)
    part_d(stmt)
    part_b(stmt)


if __name__ == "__main__":
    main()
