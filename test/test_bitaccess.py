import unittest

from src.riscv.parse import BitAccess


class Test(unittest.TestCase):
    def test_access_single_bits(self):
        self.assertEqual(BitAccess(0b1011)[0], 1)
        self.assertEqual(BitAccess(0b1011)[1], 1)
        self.assertEqual(BitAccess(0b1011)[2], 0)
        self.assertEqual(BitAccess(0b1011)[3], 1)

    def test_access_slice(self):
        self.assertEqual(BitAccess(0b1011)[0:0], 0b1)
        self.assertEqual(BitAccess(0b1011)[0:1], 0b11)
        self.assertEqual(BitAccess(0b1011)[0:], 0b1011)
        self.assertEqual(BitAccess(0b1011)[1:], 0b101)


