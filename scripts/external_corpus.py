#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Adapt pinned upstream seeds and local regressions to the fuzz targets.

The source archives and selection rules are recorded in third_party/corpus/README.md.
No upstream response is treated as a conformance oracle.
"""
import argparse
import hashlib
import hmac
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


def assertion_sequences():
    from fido2 import cbor

    cdh = bytes([0xCD]) * 32
    register = bytes([1]) + cbor.encode({
        1: cdh, 2: {"id": "a.co"}, 3: {"id": bytes([9]), "name": "next"},
        4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True},
        8: hmac.digest(bytes([0x99]) * 32, cdh, "sha256"), 9: 2,
    })
    discover = bytes([2]) + cbor.encode({1: "a.co", 2: cdh, 5: {"up": False}, 8: 6})
    for index, capacity in enumerate((1, 2, 32, 64, 128, 256, 2048)):
        short = bytes([2]) + cbor.encode({1: "a.co", 2: cdh, 5: {"up": False}, 8: index})
        commands = (register, discover, bytes([8, index]), bytes([8, 6]),
                    bytes([8, 6]), short, discover)
        # Raw arm with bounded replies; Next ignores the capacity selector byte.
        data = bytes([20]) + b"".join(len(c).to_bytes(2, "big") + c for c in commands)
        yield "fido_session", f"rs-key-assertion-capacity-{capacity}", data


def backup_sequences():
    ordinary = (0, 64, 256, 700, 65535)
    erase = (0, 116, 256, 2047, 4211, 4212, 4716, 65535)
    for churn, cuts in ((0, ordinary), (31, ordinary), (63, ordinary),
                        (24, erase), (45, erase)):
        for load_cut in cuts:
            for recovery_cut in (0, 17, 700):
                data = (bytes([0xE0, churn]) + load_cut.to_bytes(2, "big")
                        + recovery_cut.to_bytes(2, "big") + bytes([0x33]))
                yield "power_cut", f"rs-key-backup-{churn}-{load_cut}-{recovery_cut}", data


def journal_sequences():
    for mode in (0xD0, 0xD1):
        for settings in (0, 1, 48, 49):
            for cut in (0, 17, 64, 65535):
                for recovery_cut in (0, 17, 65535):
                    data = (bytes([mode, settings]) + cut.to_bytes(2, "big")
                            + recovery_cut.to_bytes(2, "big"))
                    yield "power_cut", f"rs-key-journal-{mode}-{settings}-{cut}-{recovery_cut}", data


def openpgp_cut_sequences():
    for mode in (0xC0, 0xC1, 0xC2, 0xC3):
        for command in range(6):
            for churn in (0, 17):
                for cut in (0, 17, 256, 65535):
                    for recovery in (0, 17, 65535):
                        data = (bytes([mode, command]) + cut.to_bytes(2, "big")
                                + recovery.to_bytes(2, "big") + bytes([churn]))
                        yield "power_cut", f"rs-key-openpgp-{mode}-{command}-{churn}-{cut}-{recovery}", data


def oath_mark_sequences():
    for selector in range(24):
        for position in range(3):
            for persistent in (0, 0x40):
                data = bytes([selector | persistent, position, 1])
                yield "oath_apdu", f"rs-key-oath-mark-read-{selector}-{position}-{persistent}", data


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
    yield from assertion_sequences()
    yield from backup_sequences()
    yield from journal_sequences()
    yield from openpgp_cut_sequences()
    yield from oath_mark_sequences()


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
