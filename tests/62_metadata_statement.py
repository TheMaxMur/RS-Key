#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Validate the self-published FIDO Metadata Statement against source + device.

    nix develop -c python tests/62_metadata_statement.py

This is a drift guard for `metadata/rs-key.metadata.json`. It is NOT in the
main hardware gate (run it by hand, like the pair/secure-boot scripts).

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
  * `authenticatorVersion` == `authenticatorGetInfo.firmwareVersion`.

Part B (runs only if a FIDO HID device is plugged in):
  * decodes the live `authenticatorGetInfo` and asserts it equals the embedded
    one, IGNORING the stateful fields (options.ep / options.clientPin /
    forcePINChange / minPINLength) which depend on PIN/enterprise state.

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
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
META = os.path.join(ROOT, "metadata", "rs-key.metadata.json")
CONF_META = os.path.join(ROOT, "metadata", "rs-key.conformance.metadata.json")
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
STATEFUL = {"forcePINChange", "minPINLength", "remainingDiscoverableCredentials"}
# `makeCredUvNotRqd` tracks alwaysUv (CTAP 2.1 §6.4 requires it false while alwaysUv
# is on), so like `alwaysUv` itself it is device state, not a statement property.
STATEFUL_OPTIONS = {"ep", "clientPin", "makeCredUvNotRqd"}


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
        "maxSerializedLargeBlobArray": m[0x0B],
        "forcePINChange": m[0x0C],
        "minPINLength": m[0x0D],
        "firmwareVersion": m[0x0E],
        "maxCredBlobLength": m[0x0F],
        "transports": m[0x09],
        "maxRPIDsForSetMinPINLength": m[0x10],
        "remainingDiscoverableCredentials": m[0x14],
        "attestationFormats": m[0x16],
        "maxPINLength": m[0x1D],
        "authenticatorConfigCommands": m[0x1F],
    }
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
    if want != got:
        for k in sorted(set(want) | set(got)):
            if want.get(k) != got.get(k):
                print(f"  DRIFT {k}: statement={want.get(k)} device={got.get(k)}")
        sys.exit("Part B: live getInfo drifted from the statement")
    print(f"Part B OK — live device getInfo matches the statement "
          f"(stateful fields {sorted(STATEFUL | STATEFUL_OPTIONS)} ignored)")


def main():
    stmt = json.load(open(META))
    part_a(stmt)
    check_conformance_variant(stmt)
    part_b(stmt)


if __name__ == "__main__":
    main()
