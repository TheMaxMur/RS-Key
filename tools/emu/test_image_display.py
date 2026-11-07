# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from PIL import Image

from image_display import HidProgress, cancel, keypad, rgb565


class PixelInputTests(unittest.TestCase):
    def setUp(self):
        self.image = Image.open(Path(__file__).parent / "fixtures/image-pin-scrambled.png").convert("RGB")

    def decode(self):
        return keypad([rgb565(*pixel) for pixel in self.image.get_flattened_data()])

    def test_digits_follow_a_captured_shuffled_pad(self):
        self.assertEqual(self.decode(), {
            "1": (49, 108), "3": (120, 108), "8": (191, 108),
            "7": (49, 163), "9": (120, 163), "6": (191, 163),
            "4": (49, 218), "5": (120, 218), "2": (191, 218), "0": (120, 273),
        })

    def test_a_partial_or_duplicate_digit_cannot_become_a_keypad(self):
        original = self.image.copy()
        self.image.paste(self.image.crop((17, 84, 81, 132)), (159, 84))
        self.assertIsNone(self.decode())
        self.image = original
        self.image.paste((0, 0, 0), (0, 260, 240, 320))
        self.assertIsNone(self.decode())
        self.assertIsNone(keypad([0] * (240 * 320)))

    def test_cancel_keeps_the_channel_bytes_and_has_no_payload(self):
        dev = SimpleNamespace(cid=bytes.fromhex("12345678"), hid=Mock())
        cancel(dev)
        dev.hid.write.assert_called_once_with(bytes.fromhex("0012345678910000") + bytes(57))

    def test_processing_keepalives_do_not_claim_the_presence_wait_has_started(self):
        hid = Mock()
        hid.read.side_effect = [bytes.fromhex("12345678bb000101"), bytes.fromhex("12345678bb000102")]
        progress = HidProgress(hid)
        progress.read(64, 100)
        self.assertFalse(progress.upneeded.is_set())
        progress.read(64, 100)
        self.assertTrue(progress.upneeded.is_set())
        self.assertEqual(progress.keepalives, [1, 2])


if __name__ == "__main__":
    unittest.main()
