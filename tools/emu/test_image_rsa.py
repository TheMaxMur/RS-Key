# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from image_rsa import SRAM_BASE, factors


class FactorScanTests(unittest.TestCase):
    def test_finds_unaligned_factors_in_both_orders_and_refuses_nonfactors(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
        p, q = key.p.to_bytes(128, "big"), key.q.to_bytes(128, "little")
        blob = bytes(3) + p + bytes(7) + q + bytes(5)
        self.assertEqual(factors(blob, key.public_numbers.n),
                         [(SRAM_BASE + 3, "big"), (SRAM_BASE + 138, "little")])
        changed = bytearray(blob)
        changed[60] ^= 1
        changed[180] ^= 1
        self.assertEqual(factors(changed, key.public_numbers.n), [])
        self.assertEqual(factors(bytes(128) + b"\x01", key.public_numbers.n), [])


if __name__ == "__main__":
    unittest.main()
