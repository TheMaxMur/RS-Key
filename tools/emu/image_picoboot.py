#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run real picotool against an owned image backend through Linux vhci_hcd."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from image_assurance import KEY, calculate, device, expected_oath, fields, port, put_oath

BOOTLOADER_VID = 0x2E8A
BOOTLOADER_PID = 0x000F
USBIP_VERSION = 0x0111
USBIP_DEVLIST = 0x8005
USBIP_DEVICE_LEN = 312
XIP_BASE = 0x10000000
SECTOR_SIZE = 4096
SRAM_ADDRESS = 0x20081000
RAW_ROW = 0x400
ECC_ROW = 0x401
OTP_ROWS = 4096
COMMAND_TIMEOUT = 900
ENUMERATION_TIMEOUT = 180
VENDOR = bytes.fromhex("f000000001")


def receive(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        assert chunk, "USB/IP server closed its operation reply"
        data.extend(chunk)
    return bytes(data)


def advertised(tcp_port):
    with socket.create_connection(("127.0.0.1", tcp_port), timeout=10) as sock:
        sock.sendall(struct.pack(">HHI", USBIP_VERSION, USBIP_DEVLIST, 0))
        assert struct.unpack(">HHI", receive(sock, 8)) == (USBIP_VERSION, 5, 0)
        assert struct.unpack(">I", receive(sock, 4))[0] == 1
        info = receive(sock, USBIP_DEVICE_LEN)
        assert info[256:288].rstrip(b"\0") == b"rsk-emu"
        vid, pid = struct.unpack_from(">HH", info, 300)
        classes = [list(receive(sock, 4)[:3]) for _ in range(info[311])]
        return {"vid": vid, "pid": pid, "interfaces": info[311], "classes": classes}


def active_ports():
    active = {}
    for status in Path("/sys/devices/platform").glob("vhci_hcd.*/status*"):
        for row in status.read_text().splitlines()[1:]:
            values = row.split()
            if int(values[2]) != 4:
                active[int(values[1])] = values[-1]
    return active


class Client:
    def __init__(self, args, tcp_port, report):
        self.args, self.tcp_port, self.report = args, tcp_port, report
        self.selection = []
        self.kernel_port = None

    def run(self, label, arguments, failure=False):
        print(f"picotool: {label}", flush=True)
        result = subprocess.run([self.args.picotool, *arguments, *self.selection],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=COMMAND_TIMEOUT)
        (self.args.work / f"{label}.log").write_text(result.stdout)
        self.report[label] = {"exit": result.returncode}
        if failure:
            assert result.returncode != 0, f"{label}: forbidden operation succeeded"
        else:
            assert result.returncode == 0, f"{label}: {result.stdout}"
        return result.stdout

    def attach(self, unbind_storage=True):
        assert not active_ports(), "this runner requires an isolated, unused vhci_hcd"
        assert advertised(self.tcp_port) == {"vid": BOOTLOADER_VID, "pid": BOOTLOADER_PID,
                                              "interfaces": 2, "classes": [[8, 6, 80], [255, 0, 0]]}
        subprocess.run([self.args.usbip, f"--tcp-port={self.tcp_port}", "attach",
                        "-r", "127.0.0.1", "-b", "rsk-emu"], check=True, timeout=30)
        deadline = time.monotonic() + ENUMERATION_TIMEOUT
        while time.monotonic() < deadline:
            active = active_ports()
            assert len(active) <= 1, "another USB/IP client attached during the run"
            if active:
                self.kernel_port, busid = next(iter(active.items()))
                node = Path("/sys/bus/usb/devices") / busid
                if (node / "idVendor").exists():
                    assert "vhci_hcd." in str(node.resolve()), "device is not virtual"
                    assert int((node / "idVendor").read_text(), 16) == BOOTLOADER_VID
                    assert int((node / "idProduct").read_text(), 16) == BOOTLOADER_PID
                    self.selection = ["--bus", (node / "busnum").read_text().strip(),
                                      "--address", (node / "devnum").read_text().strip(),
                                      "--vid", hex(BOOTLOADER_VID), "--pid", hex(BOOTLOADER_PID)]
                    # Keep kernel SCSI probes out of the owned PICOBOOT session.
                    interface = node / f"{busid}:1.0"
                    while not (interface / "bInterfaceClass").exists():
                        assert time.monotonic() < deadline, "virtual mass-storage interface is missing"
                        time.sleep(0.05)
                    assert (interface / "bInterfaceClass").read_text().strip() == "08"
                    driver = interface / "driver"
                    if unbind_storage and driver.exists():
                        assert driver.resolve().name == "usb-storage"
                        (driver / "unbind").write_text(interface.name)
                    self.report.setdefault("virtual_devices", []).append({"busid": busid, "port": self.kernel_port})
                    return node
            time.sleep(0.05)
        raise TimeoutError("owned virtual BOOTSEL device never enumerated")

    def detach(self):
        if self.kernel_port is not None:
            result = None
            if self.kernel_port in active_ports():
                result = subprocess.run([self.args.usbip, "detach", "-p", str(self.kernel_port)], timeout=30)
            deadline = time.monotonic() + ENUMERATION_TIMEOUT
            while self.kernel_port in active_ports():
                if time.monotonic() >= deadline:
                    if result is not None:
                        result.check_returncode()
                    raise TimeoutError("owned USB/IP port did not detach")
                time.sleep(0.05)
            self.kernel_port = None
            self.selection = []


def bootsel(dev):
    state = fields(dev.inspect("status"))
    dev.select(VENDOR)
    dev.apdu(bytes.fromhex("001f0100"))
    ready = dev.wait_ready(power_ups=int(state["power_ups"]) + 1)
    assert ready["bootloader"] == "true", "image did not enter the real ROM bootloader"


def otp_dump(client, label, ecc=False):
    path = client.args.work / f"{label}.bin"
    client.run(label, ["otp", "dump", "-e" if ecc else "-r", "--output", str(path)])
    return path.read_bytes()


def row(blob, index, width):
    assert len(blob) == OTP_ROWS * width, "OTP dump is not the whole array"
    return int.from_bytes(blob[index * width:(index + 1) * width], "little")


def exercise(args, report):
    tcp_port = port()
    client = Client(args, tcp_port, report)
    store = args.work / "device.flash"
    output = subprocess.check_output(["arm-none-eabi-nm", "--defined-only", "--format=posix", str(args.image)], text=True)
    symbols = {v[0]: int(v[2], 16) for line in output.splitlines() if len(v := line.split()) >= 3}
    kv_start = XIP_BASE + symbols["__kvmain_start"]
    spare = kv_start - SECTOR_SIZE
    with device(args.emulator, args.image, store, args.work, "picoboot", usbip=tcp_port, rom=args.rom) as dev:
        try:
            original_device = advertised(tcp_port)
            report["firmware_device"] = original_device
            put_oath(dev)
            bootsel(dev)
            client.attach()
            client.run("info", ["info", "-a"])

            data = bytes(range(256)) * 4
            (args.work / "sram.bin").write_bytes(data)
            client.run("sram-load", ["load", str(args.work / "sram.bin"), "-t", "bin", "-o", hex(SRAM_ADDRESS), "-v"])
            client.run("sram-save", ["save", "-r", hex(SRAM_ADDRESS), hex(SRAM_ADDRESS + len(data)), str(args.work / "sram-read.bin"), "-t", "bin"])
            assert (args.work / "sram-read.bin").read_bytes() == data
            client.run("sram-verify", ["verify", str(args.work / "sram.bin"), "-t", "bin", "-o", hex(SRAM_ADDRESS)])

            client.run("spare-save", ["save", "-r", hex(spare), hex(spare + SECTOR_SIZE), str(args.work / "spare.bin"), "-t", "bin"])
            assert (args.work / "spare.bin").read_bytes() == b"\xff" * SECTOR_SIZE, "spare sector holds firmware data"
            (args.work / "flash.bin").write_bytes(data)
            client.run("flash-load", ["load", str(args.work / "flash.bin"), "-t", "bin", "-o", hex(spare), "--ignore-partitions", "-v"])
            client.run("flash-save", ["save", "-r", hex(spare), hex(spare + len(data)), str(args.work / "flash-read.bin"), "-t", "bin"])
            assert (args.work / "flash-read.bin").read_bytes() == data
            client.run("flash-verify", ["verify", str(args.work / "flash.bin"), "-t", "bin", "-o", hex(spare)])
            client.run("spare-restore", ["load", str(args.work / "spare.bin"), "-t", "bin", "-o", hex(spare), "--ignore-partitions", "-v"])
            before = store.read_bytes()[kv_start - XIP_BASE:]
            refused = client.run("store-write-refused", ["load", str(args.work / "flash.bin"), "-t", "bin", "-o", hex(kv_start), "--ignore-partitions"], failure=True)
            assert "permission failure" in refused, "store write failed for a reason other than the ROM fence"
            assert store.read_bytes()[kv_start - XIP_BASE:] == before, "refused write changed KV"

            original = otp_dump(client, "otp-before")
            assert row(original, RAW_ROW, 4) == 0 and row(original, ECC_ROW, 4) == 0
            client.run("otp-set-raw", ["otp", "set", "-r", hex(RAW_ROW), "0x1"])
            client.run("otp-add-bit", ["otp", "set", "-r", hex(RAW_ROW), "0x3"])
            client.run("otp-set-ecc", ["otp", "set", "-e", hex(ECC_ROW), "0x1234"])
            refused = client.run("otp-clear-refused", ["otp", "set", "-r", hex(RAW_ROW), "0"], failure=True)
            assert "Cannot clear bits in OTP row(s): current value 000003, new value 000000" in refused
            assert row(otp_dump(client, "otp-after"), RAW_ROW, 4) == 3
            assert row(otp_dump(client, "otp-ecc", ecc=True), ECC_ROW, 2) == 0x1234

            programmed = int(fields(dev.inspect("status"))["programmed_bytes"])
            client.run("firmware-load", ["load", str(args.image), "-t", "elf", "-v"])
            after = int(fields(dev.inspect("status"))["programmed_bytes"])
            assert after > programmed, "full firmware load did not program flash"
            report["firmware_programmed_bytes"] = after - programmed
            client.run("firmware-verify", ["verify", str(args.image), "-t", "elf"])
            client.run("firmware-update", ["load", str(args.image), "-t", "elf", "-u", "-v"])
            up = int(fields(dev.inspect("status"))["power_ups"])
            client.run("reboot", ["reboot"])
            state = dev.wait_ready(power_ups=up + 1)
            assert state["bootloader"] == "false", "picotool reboot stayed in BOOTSEL"
            client.detach()
            dev.wait_ready(power_ups=int(state["power_ups"]) + 1)
            dev.reconnect()
            assert calculate(dev) == expected_oath(KEY), "full reflash lost the OATH credential"
            assert advertised(tcp_port) == original_device, "USB/IP retained bootloader descriptors"
            dev.power_cycle()
            assert calculate(dev) == expected_oath(KEY), "cold boot lost the OATH credential"

            bootsel(dev)
            client.attach()
            assert row(otp_dump(client, "otp-reboot-raw"), RAW_ROW, 4) == 3
            assert row(otp_dump(client, "otp-reboot-ecc", ecc=True), ECC_ROW, 2) == 0x1234
            state = fields(dev.inspect("status"))
            client.detach()
            dev.wait_ready(power_ups=int(state["power_ups"]) + 1)
            assert fields(dev.inspect("status"))["bootloader"] == "true", "detach left the bootloader"
            report["reboot_persistence"] = "OATH survived full reload and cold boot; raw and ECC OTP survived reboot"
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
    print(f"PICOBOOT PASSED; report: {args.work / 'report.json'}")


if __name__ == "__main__":
    main()
