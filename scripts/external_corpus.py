#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Adapt the pinned upstream seeds to the existing fuzz targets, or replay them.

The source archives and selection rules are recorded in third_party/corpus/README.md.
No upstream response is treated as a conformance oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/corpus"
HASHES = {
    "google.tar.gz": "ef887c40b6e1661386cbceb9e9e7f9c34ab86b22cabbdb841d9db6a663a0de66",
    "canokey.tar.gz": "e4a6b664fb60c25f626436c3c88f3877be6cd91448f7691e2595260b917f94f9",  # gitleaks:allow public corpus SHA-256
    "opensk.json": "2c10bca1dec215acde9bea9d20a07b90e6ce174b423c7c16835d217b0965557c",
}
CTAP = {
    "Cbor_MakeCredentialParameters": 0x01,
    "Cbor_GetAssertionParameters": 0x02,
    "Cbor_ClientPinParameters": 0x06,
}
APPLETS = {"applet0": "piv_apdu", "applet2": "oath_apdu", "applet4": "openpgp_apdu"}


def records():
    for name, digest in HASHES.items():
        if hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"upstream corpus checksum differs: {name}")
    with tarfile.open(SOURCE / "google.tar.gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or member.name == "LICENSE":
                continue
            group, name = member.name.split("/")
            data = archive.extractfile(member).read()
            if group in CTAP:
                yield "fido_cbor", f"google-{group}-{name}", bytes([CTAP[group]]) + data
            elif group == "CtapHidRawData":
                yield "ctaphid", f"google-{name}", data
            else:
                raise ValueError(f"unknown Google corpus group: {group}")
    for index, case in enumerate(json.loads((SOURCE / "opensk.json").read_text())):
        description = case["description"]
        if description == "cbor value":
            commands = CTAP.values()
        else:
            commands = [next(command for group, command in CTAP.items()
                             if description.startswith({
                                 "Cbor_MakeCredentialParameters": "make credential",
                                 "Cbor_GetAssertionParameters": "get assertion",
                                 "Cbor_ClientPinParameters": "client pin",
                             }[group]))]
        for command in commands:
            yield "fido_cbor", f"opensk-{index}-{command}", bytes([command]) + bytes.fromhex(case["hex"])
    with tarfile.open(SOURCE / "canokey.tar.gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or member.name == "LICENSE":
                continue
            group, _, name = member.name.split("/")
            data = archive.extractfile(member).read()
            label = f"canokey-{group}-{name}"
            yield "apdu", label, data
            if group == "applet1":
                yield "fido_u2f", label, data
            elif group in APPLETS and 0 < len(data) < 255:
                yield APPLETS[group], label, bytes([len(data)]) + data


def prepare(destination):
    counts = {}
    for target, name, data in records():
        directory = destination / target
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(data)
        counts[target] = counts.get(target, 0) + 1
    for target, count in sorted(counts.items()):
        print(f"external corpus: {target}: {count} inputs", flush=True)
    return counts


def replay(manifest):
    binaries = {}
    for line in manifest.read_text().splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact" and artifact.get("executable"):
            binaries[artifact["target"]["name"]] = artifact["executable"]
    with tempfile.TemporaryDirectory(prefix="rsk-external-corpus-") as work:
        destination = Path(work)
        for target, count in prepare(destination).items():
            artifacts = ROOT / "fuzz/artifacts" / target
            artifacts.mkdir(parents=True, exist_ok=True)
            result = subprocess.run([binaries[target], str(destination / target), "-runs=0",
                                     f"-artifact_prefix={artifacts}/"],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if result.returncode:
                print(result.stdout)
                result.check_returncode()
            print(f"external replay: {target}: {count} inputs passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, metavar="CARGO_JSON")
    parser.add_argument("--out", type=Path, default=ROOT / "fuzz/corpus")
    args = parser.parse_args()
    if args.replay:
        replay(args.replay)
    else:
        prepare(args.out)


if __name__ == "__main__":
    main()
