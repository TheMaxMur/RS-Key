#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run a disposable loopback image emulator; never opens physical key handles."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

MATRIX_WORKERS = 2

# RP2350 register blocks used by security_policy::configure_bus_masters.
RESOURCES = [
    ("sysinfo", 0x40000000), ("syscfg", 0x40008000),
    ("clocks", 0x40010000), ("rsm", 0x40018000), ("resets", 0x40020000),
    ("io_bank0", 0x40028000), ("io_qspi", 0x40030000),
    ("pads_bank0", 0x40038000), ("pads_qspi", 0x40040000),
    ("xosc", 0x40048000), ("pll_sys", 0x40050000), ("pll_usb", 0x40058000),
    ("busctrl", 0x40068000), ("uart0", 0x40070000), ("uart1", 0x40078000),
    ("spi0", 0x40080000), ("spi1", 0x40088000),
    ("i2c0", 0x40090000), ("i2c1", 0x40098000),
    ("adc", 0x400a0000), ("pwm", 0x400a8000), ("timer0", 0x400b0000),
    ("hstx", 0x400c0000), ("xip_ctrl", 0x400c8000),
    ("qmi", 0x400d0000), ("watchdog", 0x400d8000), ("rosc", 0x400e8000),
    ("trng", 0x400f0000), ("sha256", 0x400f8000), ("powman", 0x40100000),
    ("ticks", 0x40108000), ("otp", 0x40120000), ("tbman", 0x40160000),
    ("dma", 0x50000400), ("usb_dpram", 0x50100000), ("usbctrl", 0x50110000),
    ("usb_status", 0x50110050), ("usb_interrupts", 0x50110090),
    ("usb_buffer_control", 0x50100080),
    ("pio0", 0x50200000), ("pio1", 0x50300000), ("pio2", 0x50400000),
    ("xip_aux", 0x50500000), ("coresight_trace", 0x50700000),
    ("bootram", 0x400e0000), ("otp_data", 0x40130000), ("otp_raw", 0x40134000),
]
RESOURCES += [(f"dma_channel_{channel}", 0x50000000 + channel * 0x40)
              for channel in range(16)]
RESOURCES += [(f"dma_seccfg_{channel}", 0x50000480 + channel * 4)
              for channel in range(16)]
RESOURCES += [(f"dma_channel_{channel}_{register}", 0x50000000 + channel * 0x40 + offset)
              for channel in range(16)
              for register, offset in (("write_addr", 4), ("trans_count", 8), ("ctrl_trig", 12))]
RESOURCES += [(f"dma_irq_security_{irq}", 0x500004c0 + irq * 4) for irq in range(4)]
RESOURCES += [("dma_misc_security", 0x500004d0), ("dma_mpu_ctrl", 0x50000500),
              ("dma_mpu_base", 0x50000504), ("dma_mpu_limit", 0x50000508)]
RESOURCES += [(f"{name}_alias_{offset:x}", address + offset)
              for name, address in RESOURCES
              if name in ("usbctrl", "dma", "otp", "resets", "clocks", "qmi")
              for offset in (0x1000, 0x2000, 0x3000)]
MEMORY_RESOURCES = [(f"secure_ram_{bank}", 0x20000000 + bank * 0x10000)
                    for bank in range(7)] + [
    ("secure_flash", 0x10000100), ("uncached_secure_flash", 0x14000100),
    ("sram_alias", 0x21000000), ("ns_ram_alias", 0x21070000),
    ("scratch_code", 0x20080100), ("scratch_code_end", 0x20081ffc),
]


def arguments():
    parser = argparse.ArgumentParser(description="Verify a hostile NS access is refused.")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ns-image", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 16), required=True)
    parser.add_argument("--access", choices=("read", "write"), default="read")
    parser.add_argument("--cfsr", type=lambda value: int(value, 16), default=0x8200)
    parser.add_argument("--require-fenced", action="store_true")
    parser.add_argument("--matrix", action="store_true", help="select resources through a zero-address test image")
    parser.add_argument("--base-port", type=int, default=19359)
    return parser.parse_args()


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall((command + "\n").encode())
        with connection.makefile("rb") as stream:
            return stream.readline(32768).decode().strip()


def load_probe(image, access):
    listing = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image.resolve())], text=True)
    symbols = {line.split()[-1]: int(line.split()[0], 16) for line in listing.splitlines()
               if line.endswith((" RSK_NS_PROBE_PROGRESS", " RSK_NS_PROBE_ACCESS"))}
    marker, entry = symbols["RSK_NS_PROBE_PROGRESS"], symbols["RSK_NS_PROBE_ACCESS"]
    assert 0x20070000 <= marker < 0x20080000
    listing = subprocess.check_output(
        ["arm-none-eabi-objdump", "-d", f"--start-address={entry}",
         f"--stop-address={entry + 4}", str(image.resolve())], text=True,
    )
    instruction = re.search(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+)+([a-z][a-z0-9.]*)", listing, re.M)
    assert instruction and int(instruction[1], 16) == entry, "hostile probe instruction missing"
    expected = {"read": "ldr", "write": "str"}[access]
    assert instruction[2].removesuffix(".w") == expected, f"hostile {access} probe is not {expected.upper()}"
    return marker


def run_probe(args, marker, address, base_port, target=None, allowed=False, secure_fault=False):
    assert 1024 <= base_port <= 65533
    ports = tuple(range(base_port, base_port + 3))
    for port in ports:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    with tempfile.NamedTemporaryFile(prefix="rsk-hostile-image-", suffix=".log", mode="w+") as log:
        proc = subprocess.Popen(
            [str(args.emulator.resolve()), "--image", str(args.image.resolve()),
             "--fido-port", str(ports[0]), "--ccid-port", str(ports[1]),
             "--inspect-port", str(ports[2])], stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                assert proc.poll() is None, "emulator exited before fault observation"
                try:
                    status = inspect(ports[2], "status")
                    progress = inspect(ports[2], f"read {marker:x} 4")
                    if target is not None and progress == "ok 01000000":
                        assert inspect(ports[2], f"read {target:x} 4") == "ok 00000000", "matrix image did not wait for its target"
                        value = address.to_bytes(4, "little").hex()
                        assert inspect(ports[2], f"plant {target:x} {value}").startswith("ok ")
                        target = None
                    if allowed and progress == "ok 02000000":
                        assert "dead=false" in status, "allowed access faulted"
                        print(f"PASS: NS RAM {args.access} control completed.", flush=True)
                        return
                    assert progress != "ok 02000000", f"protected {args.access} succeeded: post-probe marker reached"
                    if "dead=true" in status:
                        break
                except ConnectionRefusedError:
                    pass
                time.sleep(0.02)
            else:
                raise AssertionError("hostile image did not fault")
            if args.require_fenced:
                assert "fatal_fenced=true" in inspect(ports[2], "status"), "USB/DPRAM remained live after Secure fatal cleanup"
            progress = inspect(ports[2], f"read {marker:x} 4")
            assert progress == "ok 01000000", progress
            log.seek(0)
            fault = log.read()
            assert not allowed, "NS RAM control was denied"
            check_fault(fault, address, args.access, args.cfsr, secure_fault)
            print(next(line for line in fault.splitlines() if "took a HardFault (" in line), flush=True)
            print(f"PASS: protected {args.access} at 0x{address:08x} refused with NS MPU off; post-{args.access} marker unreachable.", flush=True)
        except AssertionError:
            log.seek(0)
            print(log.read(), end="", flush=True)
            raise
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def check_fault(fault, address, access, cfsr, secure):
    cause, status, location = ("SFSR", 0x48, "SFAR") if secure else ("CFSR", cfsr, "BFAR")
    assert f"{location} 0x{address:08x}" in fault, f"fault address differs from the protected {access}"
    assert f"{cause} 0x{status:08x}" in fault, "fault status differs from the expected access denial"


def load_target(image):
    listing = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image.resolve())], text=True)
    target = int(next(line.split()[0] for line in listing.splitlines()
                      if line.endswith(" RSK_NS_PROBE_TARGET")), 16)
    assert 0x20070000 <= target <= 0x2007fffc
    return target


def run_resource(args, marker, target, index, resource):
    name, address, secure = resource
    print(f"resource: {name}", flush=True)
    try:
        run_probe(args, marker, address, args.base_port + index * 3, target=target, secure_fault=secure)
    except Exception:
        print(f"resource failed: {name} at 0x{address:08x}", flush=True)
        raise


def main():
    args = arguments()
    marker = load_probe(args.ns_image, args.access)
    if not args.matrix:
        run_probe(args, marker, args.address, args.base_port)
        return
    target = load_target(args.ns_image)
    assert target != marker
    assert args.address == 0, "matrix requires a zero-address test image"
    run_probe(args, marker, target, args.base_port, target=target, allowed=True)
    cases = [(name, address, False) for name, address in RESOURCES]
    cases += [(name, address, True) for name, address in MEMORY_RESOURCES]
    with ThreadPoolExecutor(max_workers=MATRIX_WORKERS) as executor:
        jobs = [executor.submit(run_resource, args, marker, target, index, resource)
                for index, resource in enumerate(cases, 1)]
        try:
            for job in as_completed(jobs):
                job.result()
        except BaseException:
            for job in jobs:
                job.cancel()
            raise


if __name__ == "__main__":
    main()
