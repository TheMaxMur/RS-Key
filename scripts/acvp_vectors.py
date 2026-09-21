#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Regenerate third_party/acvp/mldsa-*.txt from NIST's ACVP-Server.

`crates/rsk-mldsa` is checked against NIST's own expected results rather than a
second implementation: key generation, signing and verification, for ML-DSA-44,
-65 and -87. This fetches the three ML-DSA `internalProjection.json` files at one
pinned ACVP-Server commit, keeps the cases the crate's API can express — the
external interface, pure (no pre-hash), mu computed inside — and writes one line
of hex per case, so the tests need no JSON parser. A rerun at the same commit
rewrites the files byte for byte. Run inside `nix develop`.
"""

import hashlib
import json
import pathlib
import urllib.request

TAG = "v1.1.0.43"
COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCE = "gen-val/json-files/ML-DSA-{mode}-FIPS204/internalProjection.json"
URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/{path}"
OUT = pathlib.Path(__file__).resolve().parent.parent / "third_party/acvp"

# What `ExpandedKey::sign` and `verify` take: a message and a context, not a
# pre-hashed message or a caller-supplied mu (FIPS 204 Alg 2/3 against Alg 4/5).
EXPRESSIBLE = {"signatureInterface": "external", "preHash": "pure", "externalMu": False}

# FIPS 204 Alg 2: the deterministic variant signs with 32 zero bytes of randomness.
DETERMINISTIC_RND = "00" * 32


def fetch(mode):
    path = SOURCE.format(mode=mode)
    with urllib.request.urlopen(URL.format(commit=COMMIT, path=path)) as reply:
        raw = reply.read()
    return path, hashlib.sha256(raw).hexdigest(), json.loads(raw)


def field(value):
    return value if value else "-"


def keygen(group, case):
    return [case["seed"], case["pk"], case["sk"]]


def siggen(group, case):
    rnd = DETERMINISTIC_RND if group["deterministic"] else case["rnd"]
    return [rnd, case["sk"], field(case["message"]), field(case["context"]), case["signature"]]


def sigver(group, case):
    verdict = "1" if case["testPassed"] else "0"
    return [verdict, case["pk"], field(case["message"]), field(case["context"]),
            case["signature"], case["reason"]]


FILES = (
    ("keyGen", "mldsa-keygen.txt", keygen, False, "seed pk sk"),
    ("sigGen", "mldsa-siggen.txt", siggen, True, "rnd sk message context signature"),
    ("sigVer", "mldsa-sigver.txt", sigver, True, "passes(1/0) pk message context signature reason"),
)


def main():
    OUT.mkdir(exist_ok=True)
    for mode, name, row, filtered, fields in FILES:
        path, digest, data = fetch(mode)
        total, lines = 0, []
        for group in data["testGroups"]:
            total += len(group["tests"])
            if filtered and any(group.get(k) != v for k, v in EXPRESSIBLE.items()):
                continue
            size = group["parameterSet"].removeprefix("ML-DSA-")
            for case in group["tests"]:
                lines.append(" ".join([str(case["tcId"]), size, *row(group, case)]))
        kept = (
            ", ".join(f"{k}={json.dumps(v)}" for k, v in EXPRESSIBLE.items())
            if filtered
            else "every case"
        )
        header = [
            f"# NIST ACVP ML-DSA {mode} (FIPS 204). Written by scripts/acvp_vectors.py; do not edit.",
            f"# Source: usnistgov/ACVP-Server {TAG} ({COMMIT}),",
            f"#   {path}, sha256 {digest}.",
            f"# Kept: {kept} -- {len(lines)} of {total} cases, one per line, NIST's notice in LICENSE.",
            f"# Fields: tcId parameterSet {fields}. Hex as upstream; '-' is an empty field.",
        ]
        (OUT / name).write_text("\n".join(header + lines) + "\n")
        print(f"{name}: {len(lines)} of {total} cases")


if __name__ == "__main__":
    main()
