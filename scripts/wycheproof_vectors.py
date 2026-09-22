#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Regenerate third_party/wycheproof/*.txt from C2SP/wycheproof.

Wycheproof's vectors are built to break implementations, not to confirm them:
every malformed padding, special-case ciphertext and weak parameter a library
has got wrong gets a case. This fetches the files at one pinned commit, keeps
what the card's own code paths can be driven with, and writes one line per case
in the order the Rust loader (`crates/rsk-rsa/src/wycheproof.rs`) reads, so the
tests need no JSON parser and no hash of their own. A rerun at the same commit
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
        "p q dP dQ qInv ciphertext message",
    ),
    (
        "rsa-pkcs1-sign.txt",
        [f"rsa_pkcs1_{bits}_sig_gen_test" for bits in (1024, 1536, 2048, 3072, 4096)],
        sign,
        lambda group: group["sha"] in DIGESTINFO and group["privateKey"]["publicExponent"] == "010001",
        "groups with a hash the card's signer recognises and e = 65537, the only\n"
        "#   exponent it imports (so not the unbalanced e = 3 keys)",
        "hash p q dP dQ qInv DigestInfo signature",
    ),
)


def main():
    OUT.mkdir(exist_ok=True)
    for out, names, row, keep, kept, fields in FILES:
        sources, lines, total = [], [], 0
        for name in names:
            digest, data = fetch(name)
            sources.append(f"#   testvectors_v1/{name}.json, sha256 {digest}")
            for group in data["testGroups"]:
                total += len(group["tests"])
                if not keep(group):
                    continue
                for case in group["tests"]:
                    lines.append(" ".join([
                        str(group["keySize"]), str(case["tcId"]), case["result"],
                        *row(group, case), field(case["comment"]),
                    ]))
        header = [
            f"# Wycheproof ({out}). Written by scripts/wycheproof_vectors.py; do not edit.",
            f"# Source: C2SP/wycheproof {COMMIT},",
            *sources,
            f"# Kept: {kept}; {len(lines)} of {total} cases.",
            "# Changed from upstream (Apache-2.0, see LICENSE): filtered as above and",
            "#   rewritten one case per line, integers at their field width.",
            f"# Fields: bits tcId result {fields} comment. Hex; '-' is an empty field.",
        ]
        (OUT / out).write_text("\n".join(header + lines) + "\n")
        print(f"{out}: {len(lines)} of {total} cases")


if __name__ == "__main__":
    main()
