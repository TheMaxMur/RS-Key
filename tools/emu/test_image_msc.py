# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import struct
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from image_msc import BLOCK_SIZE, UF2_MAGIC, fat_files, uf2_pages
from image_picoboot import Client, ENUMERATION_TIMEOUT


class MscTests(unittest.TestCase):
    def test_fat_files_follow_the_rom_directory_and_reject_a_broken_chain(self):
        disk = bytearray(32 * BLOCK_SIZE)
        disk[510:512] = disk[1022:1024] = b"\x55\xaa"
        disk[450] = 0x0E
        struct.pack_into("<II", disk, 454, 1, 31)
        struct.pack_into("<HBHBH", disk, BLOCK_SIZE + 11, BLOCK_SIZE, 1, 1, 2, 16)
        struct.pack_into("<H", disk, BLOCK_SIZE + 22, 1)
        contents = [(b"INDEX   HTM", b"raspberrypi"), (b"INFO_UF2TXT", b"UF2 Bootloader RP2350")]
        for index, (name, text) in enumerate(contents):
            number = index + 2
            struct.pack_into("<H", disk, 2 * BLOCK_SIZE + number * 2, 0xFFFF)
            entry = 4 * BLOCK_SIZE + index * 32
            disk[entry:entry + 11] = name
            struct.pack_into("<HI", disk, entry + 26, number, len(text))
            disk[(5 + index) * BLOCK_SIZE:(5 + index) * BLOCK_SIZE + len(text)] = text
        read = lambda offset, length: disk[offset:offset + length]
        files, lba = fat_files(read, 32)
        self.assertEqual(files, {"INDEX.HTM": b"raspberrypi", "INFO_UF2.TXT": b"UF2 Bootloader RP2350"})
        self.assertEqual(lba, 7)
        struct.pack_into("<H", disk, 2 * BLOCK_SIZE + 4, 3)
        with self.assertRaisesRegex(AssertionError, "multiple clusters"):
            fat_files(read, 32)

    def test_uf2_payloads_are_checked_before_the_owned_disk_write(self):
        block = bytearray(BLOCK_SIZE)
        struct.pack_into("<8I", block, 0, *UF2_MAGIC[:2], 0x2000, 0x10000000, 256, 0, 1, 0xE48BFF59)
        struct.pack_into("<I", block, 508, UF2_MAGIC[2])
        self.assertEqual(uf2_pages(block), [(0, bytes(256))])
        for offset in (0, 8, 12, 16, 20, 24, 508):
            with self.subTest(offset=offset):
                broken = bytearray(block)
                broken[offset] ^= 1
                with self.assertRaises(AssertionError):
                    uf2_pages(broken)

    def test_detach_accepts_an_already_removed_port_but_preserves_a_live_failure(self):
        for ports, error in [([{0: "3-1"}, {0: "3-1"}, {}], False), ([{0: "3-1"}, {0: "3-1"}], True)]:
            with self.subTest(error=error):
                client = Client(SimpleNamespace(usbip="usbip"), 3240, {})
                client.kernel_port = 0
                result = subprocess.CompletedProcess(["usbip", "detach"], 1)
                with patch("image_picoboot.active_ports", side_effect=ports), \
                     patch("image_picoboot.time.sleep"), \
                     patch("image_picoboot.time.monotonic", side_effect=[0, ENUMERATION_TIMEOUT] if error else [0, 1]), \
                     patch("image_picoboot.subprocess.run", return_value=result):
                    if error:
                        with self.assertRaises(subprocess.CalledProcessError):
                            client.detach()
                        self.assertEqual(client.kernel_port, 0)
                    else:
                        client.detach()
                        self.assertIsNone(client.kernel_port)

    def test_detach_retries_a_refused_request_until_the_owned_port_disappears(self):
        client = Client(SimpleNamespace(usbip="usbip"), 3240, {})
        client.kernel_port = 0
        client.selection = ["--bus", "3", "--address", "1"]
        with patch("image_picoboot.active_ports", side_effect=[{0: "3-1"}, {0: "3-1"}, {}]), \
             patch("image_picoboot.time.sleep"), \
             patch("image_picoboot.time.monotonic", side_effect=[0, 1]), \
             patch("image_picoboot.subprocess.run", side_effect=[
                 subprocess.CompletedProcess(["usbip", "detach"], 1),
                 subprocess.CompletedProcess(["usbip", "detach"], 0),
             ]) as run:
            client.detach()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0], run.call_args_list[1])
        self.assertIsNone(client.kernel_port)
        self.assertEqual(client.selection, [])


if __name__ == "__main__":
    unittest.main()
