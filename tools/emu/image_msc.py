#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read BOOTSEL's FAT disk and reload UF2 through an owned Linux USB/IP disk."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time

from image_assurance import KEY, calculate, device, expected_oath, fields, port, put_oath
from image_picoboot import Client, ENUMERATION_TIMEOUT, XIP_BASE, advertised, bootsel

BLOCK_SIZE = 512
UF2_PAYLOAD_SIZE = 256
UF2_MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)
UF2_FAMILY_PRESENT = 0x2000
WRITE_BATCH = 8 * BLOCK_SIZE
COEXISTENCE_ROUNDS = 20
# Linux uapi/linux/fs.h: _IO(0x12, 97), only the owned disk's cache.
BLKFLSBUF = 0x1261


def block_device(node, dev):
    assert "vhci_hcd." in str(node.resolve()), "MSC device is not virtual"
    deadline = time.monotonic() + ENUMERATION_TIMEOUT
    while time.monotonic() < deadline:
        dev.wait_ready()
        blocks = [p for p in node.glob("**/block/*")
                  if (p / "size").exists() and int((p / "size").read_text()) > 0
                  and (Path("/dev") / p.name).exists()]
        if blocks:
            assert len(blocks) == 1, "owned ROM has multiple block devices"
            block = blocks[0]
            assert block.resolve().is_relative_to(node.resolve()), "block is outside the owned USB device"
            disk = Path("/dev") / block.name
            major, minor = map(int, (block / "dev").read_text().split(":"))
            info = disk.stat()
            assert stat.S_ISBLK(info.st_mode) and info.st_rdev == os.makedev(major, minor)
            interface = node / f"{node.name}:1.0"
            assert (interface / "driver").resolve().name == "usb-storage", "MSC driver is not active"
            return disk, int((block / "size").read_text()), os.makedev(major, minor)
        time.sleep(0.05)
    raise TimeoutError("owned MSC block device never appeared")


def fat_files(read, sectors):
    mbr = read(0, BLOCK_SIZE)
    assert mbr[-2:] == b"\x55\xaa" and mbr[450] == 0x0E, "ROM has no FAT16 MBR"
    start, count = struct.unpack_from("<II", mbr, 454)
    assert start == 1 and start + count == sectors
    boot = read(start * BLOCK_SIZE, BLOCK_SIZE)
    assert boot[-2:] == b"\x55\xaa"
    width, cluster, reserved, fats, entries = struct.unpack_from("<HBHBH", boot, 11)
    fat_size = struct.unpack_from("<H", boot, 22)[0]
    assert width == BLOCK_SIZE and 0 < cluster <= 128 and reserved == 1 and fats == 2
    assert 0 < entries <= 512 and entries * 32 % BLOCK_SIZE == 0 and 0 < fat_size <= 1024
    root = start + reserved + fats * fat_size
    data = root + entries * 32 // BLOCK_SIZE
    directory = read(root * BLOCK_SIZE, entries * 32)
    files = {}
    for offset in range(0, len(directory), 32):
        entry = directory[offset:offset + 32]
        if entry[0] == 0:
            break
        if entry[0] == 0xE5 or entry[11] & 0x18:
            continue
        number, length = struct.unpack_from("<HI", entry, 26)
        assert number >= 2 and 0 < length <= cluster * BLOCK_SIZE
        end = read((start + reserved) * BLOCK_SIZE + number * 2, 2)
        assert int.from_bytes(end, "little") >= 0xFFF8, "ROM file spans multiple clusters"
        name = entry[:8].decode("ascii").rstrip() + "." + entry[8:11].decode("ascii").rstrip()
        files[name] = read((data + (number - 2) * cluster) * BLOCK_SIZE, length)
    assert set(files) == {"INDEX.HTM", "INFO_UF2.TXT"}, "ROM directory differs"
    assert b"UF2 Bootloader" in files["INFO_UF2.TXT"] and b"RP2350" in files["INFO_UF2.TXT"]
    assert b"raspberrypi" in files["INDEX.HTM"]
    return files, data + len(files) * cluster


def uf2_pages(blob):
    assert blob and len(blob) % BLOCK_SIZE == 0
    pages = []
    for offset in range(0, len(blob), BLOCK_SIZE):
        magic0, magic1, flags, address, length, number, count, _ = struct.unpack_from("<8I", blob, offset)
        assert (magic0, magic1, struct.unpack_from("<I", blob, offset + 508)[0]) == UF2_MAGIC
        assert flags == UF2_FAMILY_PRESENT and length == UF2_PAYLOAD_SIZE
        assert number == len(pages) and count == len(blob) // BLOCK_SIZE
        assert XIP_BASE <= address and address % UF2_PAYLOAD_SIZE == 0
        pages.append((address - XIP_BASE, blob[offset + 32:offset + 32 + length]))
    return pages


def exercise(args, report):
    uf2 = args.work / "firmware.uf2"
    subprocess.run([args.picotool, "uf2", "convert", str(args.image), "-t", "elf", str(uf2)],
                   check=True, timeout=60)
    blob = uf2.read_bytes()
    pages = uf2_pages(blob)
    tcp_port = port()
    client = Client(args, tcp_port, report)
    store = args.work / "device.flash"
    with device(args.emulator, args.image, store, args.work, "msc", usbip=tcp_port, rom=args.rom) as dev:
        try:
            identity = advertised(tcp_port)
            put_oath(dev)
            bootsel(dev)
            node = client.attach(unbind_storage=False)
            disk, sectors, device_number = block_device(node, dev)
            report["disk"] = {"sectors": sectors, "kernel_driver": "usb-storage"}
            before = store.read_bytes()
            up = int(fields(dev.inspect("status"))["power_ups"])
            with os.fdopen(os.open(disk, os.O_RDWR | os.O_SYNC), "r+b", buffering=0) as handle:
                assert os.fstat(handle.fileno()).st_rdev == device_number and node.exists(), "owned disk changed"
                def read(offset, length):
                    result = os.pread(handle.fileno(), length, offset)
                    assert len(result) == length, "truncated MSC read"
                    return result

                fcntl.ioctl(handle.fileno(), BLKFLSBUF)
                files, lba = fat_files(read, sectors)
                assert lba * BLOCK_SIZE + len(blob) <= sectors * BLOCK_SIZE
                for name, contents in files.items():
                    (args.work / name).write_bytes(contents)
                report["fat_files"] = {name: len(contents) for name, contents in files.items()}
                for attempt in range(COEXISTENCE_ROUNDS):
                    client.run(f"info-with-msc-{attempt}", ["info", "-a"])
                    fcntl.ioctl(handle.fileno(), BLKFLSBUF)
                    assert fat_files(read, sectors)[0] == files, "PICOBOOT changed MSC files"
                report["coexistence_rounds"] = COEXISTENCE_ROUNDS

                programmed = int(fields(dev.inspect("status"))["programmed_bytes"])
                bad = bytearray(blob[:BLOCK_SIZE])
                bad[0] ^= 1
                assert os.pwrite(handle.fileno(), bad, lba * BLOCK_SIZE) == BLOCK_SIZE
                os.fsync(handle.fileno())
                assert int(fields(dev.inspect("status"))["programmed_bytes"]) == programmed
                assert store.read_bytes() == before, "invalid UF2 changed flash"
                report["invalid_uf2"] = "bad magic ignored without programming"

                print(f"MSC: writing {len(pages)} UF2 blocks through {disk}", flush=True)
                peak = programmed
                for offset in range(0, len(blob), WRITE_BATCH):
                    chunk = blob[offset:offset + WRITE_BATCH]
                    assert os.pwrite(handle.fileno(), chunk, lba * BLOCK_SIZE + offset) == len(chunk)
                    peak = max(peak, int(fields(dev.inspect("status"))["programmed_bytes"]))
                os.fsync(handle.fileno())
            state = dev.wait_ready(power_ups=up + 1)
            assert state["bootloader"] == "false", "UF2 reload stayed in BOOTSEL"
            after = store.read_bytes()
            for offset, payload in pages:
                assert after[offset:offset + len(payload)] == payload, f"UF2 payload differs at {offset:#x}"
            last = max(offset + len(payload) for offset, payload in pages)
            assert after[last:] == before[last:], "UF2 reload changed data outside its image"
            count = peak - programmed
            assert count >= (len(pages) - WRITE_BATCH // BLOCK_SIZE) * UF2_PAYLOAD_SIZE
            report["uf2_reload"] = {"blocks": len(pages), "programmed_bytes_before_reboot": count,
                                    "all_payloads_verified": True, "outside_image_unchanged": True}
            client.detach()
            dev.wait_ready(power_ups=int(state["power_ups"]) + 1)
            dev.reconnect()
            assert calculate(dev) == expected_oath(KEY), "UF2 reload lost the OATH credential"
            assert advertised(tcp_port) == identity, "UF2 reboot retained ROM USB descriptors"
            dev.power_cycle()
            assert calculate(dev) == expected_oath(KEY), "cold boot lost the OATH credential"
            report["reboot_persistence"] = "OATH survived UF2 reload and cold boot; USB descriptors refreshed"
        finally:
            client.detach()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--rom", type=Path, help="explicit bootrom fixture (CI stages picoem's pinned A4)")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--picotool", default="picotool")
    parser.add_argument("--usbip", default="usbip")
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0, "run in an isolated Linux VM as root"
    assert Path("/sys/devices/platform/vhci_hcd.0").exists(), "load vhci_hcd first"
    args.work.mkdir(parents=True, exist_ok=False)
    args.work = args.work.resolve()
    args.image, args.emulator = args.image.resolve(strict=True), args.emulator.resolve(strict=True)
    report = {"passed": False, "emulator": hashlib.sha256(args.emulator.read_bytes()).hexdigest(),
              "image": hashlib.sha256(args.image.read_bytes()).hexdigest()}
    if args.rom:
        args.rom = args.rom.resolve(strict=True)
        report["rom"] = hashlib.sha256(args.rom.read_bytes()).hexdigest()
    try:
        exercise(args, report)
        report["passed"] = True
    finally:
        (args.work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"MSC PASSED; report: {args.work / 'report.json'}")


if __name__ == "__main__":
    main()
