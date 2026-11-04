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


def fido_token_sequences():
    """The `TOK1` spend/revocation route in `fido_session_token.rs`.

    Byte 0 is the variant, byte 1 the PIN protocol (0 = 2, 1 = 1), byte 2 extra
    permissions and byte 3 the rpId binding. The target performs a real
    clientPIN handshake and checks the spend, expiry, RP and revocation
    transitions against its own model; no status word is taken as proof.
    """
    seeds = (
        ("spend-mc", b"\x00\x00\x00\x00"),
        ("spend-mc-proto1-bound", b"\x00\x01\x00\x01"),
        ("residual-lbw", b"\x01\x00\x00\x01"),
        ("rp-refusal", b"\x02\x00\x00\x01"),
        ("inactivity-expiry", b"\x03\x00\x00\x00"),
        ("inactivity-mutated-rp", b"\x03\xff\x02\x01"),
        ("absolute-expiry", b"\x04\x00\x00\x00"),
        ("reset-revocation", b"\x05\x01\x00\x00"),
        ("wrong-pin-revocation", b"\x06\x00\x00\x00"),
        ("reissue-proto1", b"\x07\x01\x00\x00"),
        ("reissue-proto2", b"\x07\x00\x00\x00"),
        ("spend-extra-perms", b"\x00\x00\x24\x00"),
    )
    for label, body in seeds:
        yield "fido_session", f"rs-key-fido-token-{label}", b"TOK1" + body


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


# `cross_applet`'s opcode table (fuzz/fuzz_targets/cross_applet.rs): applet
# indices 0-7 in registration order, then F0 management, F1 reset-card, F2
# reset-chaining, F3 refresh-caps, F4 factory-wipe, F5 OTP-HID, F6 SET_CAPS
# hi lo and F7 the scripted OATH code route. The capability-gated applets and
# their bits are `rsk_devconf`'s.
CROSS_APPLET_GATED = (
    (1, "openpgp", 0x0008),  # CAP_OPENPGP
    (3, "oath", 0x0020),     # CAP_OATH
    (4, "otp", 0x0001),      # CAP_OTP
    (5, "piv", 0x0010),      # CAP_PIV
    (7, "fido", 0x0202),     # CAP_FIDO2 | CAP_U2F
)
CROSS_APPLET_SUPPORTED = 0x023B  # rsk_devconf::SUPPORTED_CAPS


def cross_applet_sequences():
    def set_caps(mask):
        return bytes([0xF6, mask >> 8, mask & 0xFF])

    # The cached mask only moves on a refresh, which is the step the worker takes
    # after a config write — a SELECT before it still sees the old set.
    refresh = bytes([0xF3])
    for index, name, cap in CROSS_APPLET_GATED:
        off = CROSS_APPLET_SUPPORTED & ~cap
        refused = set_caps(off) + refresh + bytes([index])
        yield "cross_applet", f"rs-key-cross-applet-{name}-disabled-select", refused
        # The very same SELECT once the config restores the bit: OK, not
        # FILE_NOT_FOUND, so the gate is the mask and not the applet's own select.
        restored = refused + set_caps(CROSS_APPLET_SUPPORTED) + refresh + bytes([index])
        yield "cross_applet", f"rs-key-cross-applet-{name}-reenabled-select", restored
    # Disable every gated applet, then run the trusted display's device-wide wipe:
    # it must take EF_DEV_CONF with it so the disabled applets become reachable.
    disabled = set_caps(0) + refresh + b"".join(bytes([index]) for index, _, _ in CROSS_APPLET_GATED)
    wipe = disabled + bytes([0xF1, 0xF4]) + refresh + bytes([1, 3])
    yield "cross_applet", "rs-key-cross-applet-factory-wipe-restores-caps", wipe


# `fs_ops`'s bytes (fuzz/fuzz_targets/fs_ops.rs): fid = 0xB000 + ((b >> 3) & 7),
# op = b & 7, and the extra byte some ops consume. put/read clamp and the exact
# META_MAX boundary are the contracts its HashMap model checks.
FS_PUT, FS_READ, FS_DELETE = 0, 1, 2
FS_META_ADD, FS_META_FIND, FS_META_DELETE = 3, 4, 5
FS_REBOOT, FS_QUERY = 6, 7


def fs_ops_sequences():
    def op(index, verb, extra=()):
        return bytes([(index << 3) | verb, *extra])

    def reboot():
        return bytes([FS_REBOOT])

    yield "fs_ops", "rs-key-fs-ops-put-read-clamp", (
        op(0, FS_PUT, [40]) + op(0, FS_READ, [0]) + op(0, FS_READ, [16])
        + op(0, FS_READ, [39]) + op(0, FS_READ, [40]) + op(0, FS_READ, [255])
        + op(0, FS_QUERY)
    )
    yield "fs_ops", "rs-key-fs-ops-put-delete", (
        op(0, FS_PUT, [10]) + op(0, FS_PUT, [200]) + op(0, FS_READ, [255])
        + op(0, FS_DELETE) + op(0, FS_READ, [8]) + op(0, FS_QUERY)
        + op(1, FS_PUT, [1]) + op(1, FS_DELETE)
    )
    yield "fs_ops", "rs-key-fs-ops-meta-add-replace-find-delete", (
        op(0, FS_META_ADD, [8]) + op(0, FS_META_ADD, [20]) + op(0, FS_META_FIND)
        + op(0, FS_META_DELETE) + op(0, FS_META_FIND) + op(0, FS_QUERY)
    )
    # Four 255-byte meta values: the first three fit META_MAX, the fourth must
    # answer NoMemory and leave the store untouched; a delete then makes room.
    yield "fs_ops", "rs-key-fs-ops-meta-nomemory-boundary", (
        op(0, FS_META_ADD, [255]) + op(1, FS_META_ADD, [255]) + op(2, FS_META_ADD, [255])
        + op(3, FS_META_ADD, [255]) + op(3, FS_META_FIND) + op(2, FS_META_FIND)
        + op(2, FS_META_DELETE) + op(3, FS_META_ADD, [250]) + op(3, FS_META_FIND)
        + op(0, FS_QUERY)
    )
    yield "fs_ops", "rs-key-fs-ops-reboot-read", (
        op(0, FS_PUT, [50]) + op(0, FS_META_ADD, [6]) + reboot()
        + op(0, FS_READ, [64]) + op(0, FS_META_FIND) + op(0, FS_QUERY)
    )
    yield "fs_ops", "rs-key-fs-ops-reboot-clears-meta", (
        op(0, FS_META_ADD, [4]) + op(0, FS_META_DELETE) + reboot()
        + op(0, FS_QUERY) + op(0, FS_META_FIND)
    )


def _be16(value):
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _le16(value):
    return bytes([value & 0xFF, (value >> 8) & 0xFF])


def credential_cut_sequences():
    """The credential create/replace lifecycle under a cut.

    `0x90` enters the credential driver; byte 1 selects create, replace at a
    sign counter of 73, or replace at 0. Bytes 2-3 and 4-5 are the command and
    recovery byte budgets (`0xFFFF` is no cut). The target asserts the resident
    credential is old-or-new, that a surviving counter never rolls back, and
    that the neighbour survives; a cut at 0 must not be read as a torn value.
    """
    for mode, label in ((0, "create"), (1, "replace"), (2, "replace-zero")):
        for op, rec, tag in ((0xFFFF, 0xFFFF, "no-cut"),
                             (0, 0, "cut-first"),
                             (64, 0, "command-cut"),
                             (0, 64, "recovery-cut")):
            yield "power_cut", f"rs-key-power-cut-credential-{label}-{tag}", bytes(
                [0x90, mode]) + _be16(op) + _be16(rec) + bytes([0])


def config_cut_sequences():
    """The DeviceConfig transitions under a cut.

    `0xA0` enters the config driver; byte 1 selects arm/replace/clear/merge/
    legacy. The target asserts the persisted record and cached capability mask
    are old-or-new, the unrelated neighbour and counter survive, and a recovery
    cut cannot adopt a partially written record.
    """
    for change, label in ((0, "arm"), (1, "replace"), (2, "clear"),
                          (3, "merge"), (4, "legacy")):
        for op, rec, tag in ((0xFFFF, 0xFFFF, "no-cut"),
                             (0, 0, "cut-first"),
                             (64, 0, "command-cut"),
                             (0, 64, "recovery-cut")):
            yield "power_cut", f"rs-key-power-cut-config-{label}-{tag}", bytes(
                [0xA0, change]) + _be16(op) + _be16(rec) + bytes([0])


def piv_cut_sequences():
    """F9 attestation provisioning under a cut.

    `0xB0 | mode` enters the PIV driver; mode 0-3 is first/recreate/repair/
    empty, bit 2 damages the public-key record. The target asserts the F9 key/
    certificate and the unrelated record are old-or-new and that the PIN/PUK
    gates are unchanged.
    """
    for mode, bit, label in ((0, 0, "first"), (1, 0, "recreate"),
                             (2, 0, "repair"), (3, 4, "empty-pubkey")):
        for op, rec, tag in ((0xFFFF, 0xFFFF, "no-cut"),
                             (0, 0, "cut-first"),
                             (64, 0, "command-cut"),
                             (0, 64, "recovery-cut")):
            yield "power_cut", f"rs-key-power-cut-piv-{label}-{tag}", bytes(
                [0xB0 | mode | bit, 7]) + _be16(op) + _be16(rec) + bytes([0])


def reset_cut_sequences():
    """The device-wide reset under a cut.

    `0xF0` enters `reset_probe`; bytes 1-3 are the big-endian byte budget
    (byte 1's low nibble is the top), and byte 4 bit 0 loads the keydev before
    the reset. The target asserts the PIN gate, always-uv gate and backup seal
    hold for every surviving credential, and that a loaded keydev is gone.
    """
    for hi, mid, lo, keydev, tag in ((0x0F, 0xFF, 0xFF, 0, "no-cut"),
                                     (0x00, 0x00, 0x00, 0, "cut-first"),
                                     (0x00, 0x00, 0x10, 0, "cut-16"),
                                     (0x00, 0x00, 0x10, 1, "cut-16-keydev"),
                                     (0x00, 0x10, 0x00, 0, "cut-4096")):
        yield "power_cut", f"rs-key-power-cut-reset-{tag}", bytes(
            [0xF0, hi, mid, lo, keydev])


def authenticated_store_sequences():
    """The real v2 backend across a write/remove and its recovery mount.

    Bytes 0-1 and 2-3 are little-endian byte budgets for the command and the
    recovery mount (`0xFFFF` is no cut); byte 4 bit 0 selects the counter bank,
    bit 1 a MAX_VALUE payload, bit 2 remove instead of write, bit 3
    post-activation damage; byte 5 is the fill byte; byte 6 warms the log with
    0-191 overwrites. Every seed asserts old-or-new on the target fid, the
    acknowledged neighbour, and that damaged bytes are never adopted.
    """
    seeds = (
        ("owner-write", 0x00, 0xFFFF, 0xFFFF, 0xA7, 0),
        ("counter-write", 0x01, 0xFFFF, 0xFFFF, 0x5C, 0),
        ("owner-max-write", 0x02, 0xFFFF, 0xFFFF, 0x24, 0),
        ("owner-delete", 0x04, 0xFFFF, 0xFFFF, 0xA7, 0),
        ("counter-delete", 0x05, 0xFFFF, 0xFFFF, 0x5C, 0),
        ("owner-cut", 0x00, 64, 0, 0xA7, 0),
        ("owner-recovery-cut", 0x00, 0, 64, 0xA7, 0),
        ("counter-cut", 0x01, 0, 0, 0x5C, 0),
        ("owner-warm", 0x00, 0xFFFF, 0xFFFF, 0xA7, 64),
        ("counter-damage", 0x09, 0xFFFF, 0xFFFF, 0x5C, 0),
    )
    for label, flags, op, rec, fill, warm in seeds:
        yield ("authenticated_store", f"rs-key-authenticated-store-{label}",
               _le16(op) + _le16(rec) + bytes([flags, fill, warm]))
    # The stateful v2 histories in `authenticated_store_v2.rs`; the magic routes
    # them away from the original write/remove contract above.
    histories = (
        ("legacy-boot", b"\x00"),
        ("legacy-administer", b"\x01"),
        ("rescue-import", b"\x02"),
        ("rescue-initv2", b"\x03"),
        ("manifest-cut-recover", b"\x04"),
        ("manifest-corrupt", b"\x05"),
        ("activation-witness", b"\x06"),
        ("root-rekey", b"\x07"),
        ("rekey-two-faults", b"\x08\x00\x00"),
        ("rekey-two-faults-long", b"\x08\x00\xff"),
        ("compaction-cold", b"\x09"),
        ("capacity", b"\x0a"),
        ("silent-write-readback", b"\x0b"),
        ("torn-write", b"\x0c"),
        ("read-write-erase", b"\x0d"),
        ("command-recovery-cut", b"\x0e"),
        ("corrupt-during-rekey", b"\x0f\x00"),
        ("corrupt-during-compaction", b"\x0f\x01"),
    )
    for label, history in histories:
        yield ("authenticated_store", f"rs-key-authenticated-store-v2-{label}",
               b"V2H1" + history)


def cross_applet_privileged_sequences():
    """OATH's acknowledged record lifecycle, driven through raw APDUs.

    SELECT OATH (applet 3) then four frames: PUT, CALCULATE, DELETE, CALCULATE.
    `0x08` is the raw-APDU selector (0x07 would SELECT FIDO); each frame is one
    selector byte, one length byte and the APDU. The target records the names an
    acknowledged PUT leaves live and removes them on an acknowledged DELETE, so
    an OK CALCULATE for a name outside that set is an authorization bypass or a
    resurrected record. The final CALCULATE must be refused (`0x6984`).
    """
    name = b"seed"

    def tlv(tag, value):
        return bytes([tag, len(value)]) + value

    def apdu(ins, p1, p2, data):
        return bytes([0, ins, p1, p2]) + (bytes([len(data)]) + data if data else b"")

    put = apdu(0x01, 0, 0,
               tlv(0x71, name) + tlv(0x73, bytes([0x11, 6]) + bytes([0xAA]) * 20))
    calculate = apdu(0xA2, 0, 0x01, tlv(0x71, name) + tlv(0x74, bytes(8)))
    delete = apdu(0x02, 0, 0, tlv(0x71, name))

    def frame(command):
        return bytes([0x08, len(command)]) + command

    yield ("cross_applet", "rs-key-cross-applet-oath-put-calculate-delete",
           bytes([3]) + b"".join(frame(command)
                                 for command in (put, calculate, delete, calculate)))


def cross_applet_oath_code_sequences():
    """The OATH access-code challenge-response, scripted by the 0xF7 route.

    `0xF7 alg secret_len fill challenge[8] variants` makes the target build real
    SET CODE / VALIDATE APDUs, read the applet's challenge from SELECT and
    compute the HMACs at run time; no proof is precomputed here. One seed per
    transition keeps the variant bits independent.
    """
    def script(alg, secret_len, fill, challenge, variants):
        return bytes([0xF7, alg, secret_len, fill]) + challenge + bytes([variants])

    yield ("cross_applet", "rs-key-cross-applet-oath-code-sha1",
           script(1, 14, 0xA5, bytes(range(1, 9)), 0x01))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-sha256",
           script(2, 32, 0x5A, bytes(range(9, 1, -1)), 0x01))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-sha512",
           script(3, 64, 0x3C, bytes([0x11]) * 8, 0x01))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-wrong-set",
           script(1, 14, 0xA5, bytes([0x22]) * 8, 0x02))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-wrong-validate",
           script(3, 20, 0x77, bytes([0x33]) * 8, 0x04))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-stale",
           script(1, 16, 0x44, bytes([0x44]) * 8, 0x08))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-malformed",
           script(2, 14, 0x99, bytes([0x55]) * 8, 0x10))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-replace",
           script(1, 14, 0xA5, bytes([0x66]) * 8, 0x20))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-remove",
           script(1, 14, 0xA5, bytes([0x77]) * 8, 0x40))
    yield ("cross_applet", "rs-key-cross-applet-oath-code-reset",
           script(2, 32, 0x5A, bytes([0x88]) * 8, 0x80))


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
    yield from fido_token_sequences()
    yield from backup_sequences()
    yield from journal_sequences()
    yield from openpgp_cut_sequences()
    yield from oath_mark_sequences()
    yield from cross_applet_sequences()
    yield from cross_applet_privileged_sequences()
    yield from cross_applet_oath_code_sequences()
    yield from fs_ops_sequences()
    yield from credential_cut_sequences()
    yield from config_cut_sequences()
    yield from piv_cut_sequences()
    yield from reset_cut_sequences()
    yield from authenticated_store_sequences()


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
