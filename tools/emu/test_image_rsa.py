# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import unittest
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from image_rsa import SRAM_BASE, factors, generate, public_key
from image_operations import tlv


class FactorScanTests(unittest.TestCase):
    def test_finds_unaligned_factors_in_both_orders_and_refuses_nonfactors(self):
        for bits in (2048, 3072, 4096):
            with self.subTest(bits=bits):
                key = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
                length = bits // 16
                p, q = key.p.to_bytes(length, "big"), key.q.to_bytes(length, "little")
                blob = bytes(3) + p + bytes(7) + q + bytes(5)
                self.assertEqual(factors(blob, key.public_numbers.n),
                                 [(SRAM_BASE + 3, "big"), (SRAM_BASE + length + 10, "little")])
                changed = bytearray(blob)
                changed[60] ^= 1
                changed[length + 60] ^= 1
                self.assertEqual(factors(changed, key.public_numbers.n), [])
                self.assertEqual(factors(bytes(length) + b"\x01", key.public_numbers.n), [])

    def test_public_keys_keep_each_generated_modulus_size(self):
        for bits in (2048, 3072, 4096):
            with self.subTest(bits=bits):
                key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
                numbers = key.public_numbers()
                answer = tlv(0x7F49, tlv(0x81, numbers.n.to_bytes(bits // 8, "big"))
                             + tlv(0x82, numbers.e.to_bytes(3, "big")))
                self.assertEqual(public_key(answer).public_numbers(), numbers)

    def test_core1_tail_uses_emulated_time_and_still_has_both_deadlines(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        for elapsed, wall, error in [(2, 31, None), (31, 1, "core1 did not wind down"),
                                     (2, 1801, "emulator did not progress")]:
            with self.subTest(elapsed=elapsed, wall=wall):
                dev = SimpleNamespace(image=True, apdu=Mock(return_value=b""),
                                      inspect=Mock(side_effect=["emulated_ns=0", f"emulated_ns={elapsed * 10**9}",
                                                               f"emulated_ns={elapsed * 10**9}"]))
                rows = {"keygen": {"stack": {"core1_used": 2048}}}
                ops = SimpleNamespace(dev=dev, report=rows, run=lambda label, command: command())
                before = {"JOBS": 0, "C1_TRIES": 0, "C0_TRIES": 0, "BUSY": 0, "JOB_PENDING": 0}
                busy = dict(before, JOBS=1, C1_TRIES=1, C0_TRIES=1, BUSY=1)
                with patch("image_rsa.public_key", return_value=key), \
                     patch("image_rsa.counters", side_effect=[before, busy, dict(busy, BUSY=0)]), \
                     patch("image_rsa.clean", return_value={"rsa_factor_matches": 0}), \
                     patch("image_rsa.time.sleep"), \
                     patch("image_rsa.time.monotonic", side_effect=[0, wall]):
                    if error:
                        with self.assertRaisesRegex(AssertionError, error):
                            generate(ops, "keygen", b"", 2048)
                    else:
                        self.assertIs(generate(ops, "keygen", b"", 2048), key)
                        self.assertEqual(rows["keygen"]["core1_wind_down_ns"], elapsed * 10**9)


if __name__ == "__main__":
    unittest.main()
