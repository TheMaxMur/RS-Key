#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Regenerate third_party/wycheproof/*.txt from C2SP/wycheproof.

Wycheproof's vectors are built to break implementations, not to confirm them:
every malformed padding, special-case ciphertext and weak parameter a library
has got wrong gets a case. This fetches the files at one pinned commit, keeps
what the card's own code paths can be driven with, and writes one line per case
in the order the Rust loaders (`crates/rsk-rsa/src/wycheproof.rs`,
`crates/rsk-ec/src/key_wycheproof_tests.rs`) read, so the tests need no JSON
parser and no hash of their own. A rerun at the same commit
rewrites the files byte for byte. Run inside `nix develop`.
"""

import hashlib
import json
import pathlib
import urllib.request

from cryptography.hazmat.primitives.serialization import load_der_private_key

COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230"
URL = "https://raw.githubusercontent.com/C2SP/wycheproof/{commit}/testvectors_v1/{name}.json"
OUT = pathlib.Path(__file__).resolve().parent.parent / "third_party/wycheproof"

# RFC 8017 §9.2 note 1: the DigestInfo prefix of each hash the card's PKCS#1 v1.5
# signer recognises. Written out here, not imported from the Rust, so the vectors
# check that table instead of repeating it.
DIGESTINFO = {
    "SHA-1": ("sha1", "3021300906052b0e03021a05000414"),
    "SHA-224": ("sha224", "302d300d06096086480165030402040500041c"),
    "SHA-256": ("sha256", "3031300d060960864801650304020105000420"),
    "SHA-384": ("sha384", "3041300d060960864801650304020205000430"),
    "SHA-512": ("sha512", "3051300d060960864801650304020305000440"),
}


# The width of each curve's private scalar, and the DER OIDs of RFC 5480's
# id-ecPublicKey and the named curves the SPKI-only files use.
SCALAR_BYTES = {
    "secp256r1": 32, "secp384r1": 48, "secp521r1": 66,
    "secp256k1": 32, "brainpoolP256r1": 32, "brainpoolP384r1": 48,
}
EC_PUBLIC_KEY = "2a8648ce3d0201"
CURVE_OID = {
    "secp256k1": "2b8104000a",
    "brainpoolP256r1": "2b2403030208010107",
    "brainpoolP384r1": "2b240303020801010b",
}


def fetch(name):
    with urllib.request.urlopen(URL.format(commit=COMMIT, name=name)) as reply:
        raw = reply.read()
    return hashlib.sha256(raw).hexdigest(), json.loads(raw)


def field(value):
    return value if value else "-"


def width(value, size):
    """`value` as exactly `size` bytes of hex: Wycheproof writes ASN.1 integers,
    so a field can carry a sign byte or fall short of its width."""
    return int(value, 16).to_bytes(size, "big").hex()


def crt(bits, p, q, dp, dq, qinv):
    half = bits // 16
    return [width(v, half) for v in (p, q, dp, dq, qinv)]


def decrypt(group, case):
    key = group["privateKey"]
    fields = crt(group["keySize"], key["prime1"], key["prime2"],
                 key["exponent1"], key["exponent2"], key["coefficient"])
    return [*fields, field(case["ct"]), field(case["msg"])]


def ecdh(group, case, public=None):
    size = SCALAR_BYTES[group["curve"]]
    public = case["public"] if public is None else public
    return [width(case["private"], size), field(public), field(case["shared"]),
            field(",".join(case["flags"]))]


def ecdh_spki(group, case):
    """The SEC1 point inside `case`'s SubjectPublicKeyInfo, for a DER one naming the
    group's curve; None for the rest, which try an SPKI parser a card does not have."""
    der = bytes.fromhex(case["public"])
    spki = der_tlv(der, 0, 0x30, len(der))
    alg = spki and der_tlv(spki[0], 0, 0x30)
    oid = alg and der_tlv(alg[0], 0, 0x06)
    curve = oid and der_tlv(alg[0], oid[1], 0x06, len(alg[0]))
    bits = curve and der_tlv(spki[0], alg[1], 0x03, len(spki[0]))
    if (not bits or oid[0].hex() != EC_PUBLIC_KEY
            or curve[0].hex() != CURVE_OID[group["curve"]] or bits[0][:1] != b"\x00"):
        return None
    return ecdh(group, case, bits[0][1:].hex())


def der_tlv(der, at, tag, end=None):
    """The value and end of the DER element at `at` if it has `tag`, a minimal length,
    fits, and (given `end`) ends there; None otherwise."""
    if at + 2 > len(der) or der[at] != tag:
        return None
    size, at = der[at + 1], at + 2
    if size & 0x80:
        count = size & 0x7F
        if count not in (1, 2) or at + count > len(der):
            return None
        size, at = int.from_bytes(der[at:at + count], "big"), at + count
        if size < (0x80, 0x100)[count - 1]:
            return None
    if at + size > len(der) or (end is not None and at + size != end):
        return None
    return der[at:at + size], at + size


def x25519(group, case):
    return [case["private"], field(case["public"]), field(case["shared"]),
            field(",".join(case["flags"]))]


def sign(group, case):
    numbers = load_der_private_key(bytes.fromhex(group["privateKeyPkcs8"]), None).private_numbers()
    fields = crt(group["keySize"], f"{numbers.p:x}", f"{numbers.q:x}",
                 f"{numbers.dmp1:x}", f"{numbers.dmq1:x}", f"{numbers.iqmp:x}")
    hash_name, prefix = DIGESTINFO[group["sha"]]
    digest = hashlib.new(hash_name, bytes.fromhex(case["msg"])).hexdigest()
    return [group["sha"], *fields, prefix + digest, case["sig"]]


FILES = (
    (
        "rsa-pkcs1-decrypt.txt",
        [f"rsa_pkcs1_{bits}_test" for bits in (2048, 3072, 4096)],
        decrypt,
        lambda group: True,
        "every case",
        ("bits", lambda group: str(group["keySize"])),
        "p q dP dQ qInv ciphertext message",
    ),
    (
        "rsa-pkcs1-sign.txt",
        [f"rsa_pkcs1_{bits}_sig_gen_test" for bits in (1024, 1536, 2048, 3072, 4096)],
        sign,
        lambda group: group["sha"] in DIGESTINFO and group["privateKey"]["publicExponent"] == "010001",
        "groups with a hash the card's signer recognises and e = 65537, the only\n"
        "#   exponent it imports (so not the unbalanced e = 3 keys)",
        ("bits", lambda group: str(group["keySize"])),
        "hash p q dP dQ qInv DigestInfo signature",
    ),
    (
        "ecdh-ecpoint.txt",
        [f"ecdh_secp{bits}r1_ecpoint_test" for bits in (256, 384, 521)],
        ecdh,
        lambda group: True,
        "every case; the public value is the raw SEC1 point a card is sent",
        ("curve", lambda group: group["curve"]),
        "private(big-endian) public shared flags",
    ),
    (
        "ecdh-spki.txt",
        ["ecdh_secp256k1_test", "ecdh_brainpoolP256r1_test", "ecdh_brainpoolP384r1_test"],
        ecdh_spki,
        lambda group: True,
        "the cases whose public key is a DER SubjectPublicKeyInfo naming the\n"
        "#   group's curve, reduced to the SEC1 point in it (what a card is sent); not\n"
        "#   the rest, which try an SPKI parser a card does not have",
        ("curve", lambda group: group["curve"]),
        "private(big-endian) public shared flags",
    ),
    (
        "x25519.txt",
        ["x25519_test"],
        x25519,
        lambda group: True,
        "every case",
        ("curve", lambda group: group["curve"]),
        "private(RFC 7748, little-endian) public shared flags",
    ),
)


def main():
    OUT.mkdir(exist_ok=True)
    for out, names, row, keep, kept, (head_name, head), fields in FILES:
        sources, lines, total = [], [], 0
        for name in names:
            digest, data = fetch(name)
            sources.append(f"#   testvectors_v1/{name}.json, sha256 {digest}")
            for group in data["testGroups"]:
                total += len(group["tests"])
                if not keep(group):
                    continue
                for case in group["tests"]:
                    values = row(group, case)
                    if values is not None:
                        lines.append(" ".join([
                            head(group), str(case["tcId"]), case["result"],
                            *values, field(case["comment"]),
                        ]))
        header = [
            f"# Wycheproof ({out}). Written by scripts/wycheproof_vectors.py; do not edit.",
            f"# Source: C2SP/wycheproof {COMMIT},",
            *sources,
            f"# Kept: {kept}; {len(lines)} of {total} cases.",
            "# Changed from upstream (Apache-2.0, see LICENSE): filtered as above and",
            "#   rewritten one case per line, integers at their field width.",
            f"# Fields: {head_name} tcId result {fields} comment. Hex; '-' is an empty field.",
        ]
        (OUT / out).write_text("\n".join(header + lines) + "\n")
        print(f"{out}: {len(lines)} of {total} cases")


if __name__ == "__main__":
    main()
