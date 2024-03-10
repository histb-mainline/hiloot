import unittest

from hiloot import *


class TestChipID(unittest.TestCase):
    DATA = b'\x07\x00\x00\x00\x037\x98\x03\x00'

    def test_load(self):
        obj = ChipID.from_bytes(self.DATA)
        self.assertIsInstance(str(obj), str)
        self.assertEqual(obj.chipid, 3)
        self.assertEqual(obj.sysid, 0x37980300)
        self.assertTrue(obj.ca)
        self.assertTrue(obj.tee)
        self.assertTrue(obj.multiform)
        self.assertEqual(obj.flags, 7)

        obj = ChipID(*obj)
        self.assertEqual(bytes(obj), self.DATA)


if __name__ == "__main__":
    unittest.main()
