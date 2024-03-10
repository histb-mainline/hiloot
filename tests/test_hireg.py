from io import BufferedRandom, BufferedReader, BytesIO
from typing import Type
import unittest

from hireg import *


def get_istream(data: bytes):
    return BufferedReader(BytesIO(data))  # type: ignore


class TestRegister(unittest.TestCase):
    def test_eof(self):
        self.assertFalse(Register.has_more_reg(get_istream(b'\0' * 0x10)))
        self.assertFalse(Register.has_more_v120(get_istream(b'\0' * 0x10)))


class _TestRegister(unittest.TestCase):
    input: bytes
    output: tuple[int, int, int, int]
    flags: int

    @classmethod
    def generate(cls, input_, output_, flags_=0):
        class TestRegisterType(cls):
            input: bytes = input_
            output: tuple[int, int, int, int] = output_
            flags: int = flags_

        return TestRegisterType


class _TestRegisterReg(_TestRegister):
    CASES: list[tuple[bytes, tuple[int, int, int, int], int]] = [
        (b'\x04\x80\xa3\xf8\1\0\0\0\0\0\0\0\x03\x78\0\0',
         (0xf8a38004, 0x8000, 0x8000, 0), 1)]

    def test_load_insufficient(self):
        with self.assertRaises(ValueError):
            Register.load_reg(get_istream(self.input[:-1]))

    def test_load(self):
        istream = get_istream(self.input)
        self.assertTrue(Register.has_more_reg(istream))

        obj, flags = Register.load_reg(istream)
        self.assertIsInstance(str(obj), str)

        for i, j in zip(tuple(obj), self.output):
            self.assertEqual(i, j)
        self.assertEqual(flags, self.flags)

    def test_dump(self):
        obj = Register(*self.output)
        self.assertEqual(obj.len_reg(), len(self.input))

        ostream = BufferedRandom(BytesIO())  # type: ignore
        obj.dump_reg(ostream, self.flags)
        ostream.seek(0)
        data = ostream.read()
        self.assertEqual(data, self.input)


class _TestRegisterV120(_TestRegister):
    CASES: list[tuple[bytes, tuple[int, int, int, int]]] = [
        # PMC_CTRL in sys_clk (refer to the SDK)
        (b'\xc8\x20\x1f\x01', (0xc8, 1, 0xffffffff, 0)),
        # PWM0 in sys_clk
        (b'\x18\x60\x3F\x29\x00\xDD\x64', (0x18, 0x2900dd, 0xffffffff, 100)),
        # APLL1 in sys_clk
        (b'\x04\x80\x5F\x08\x00\x21\x0A\x03\xE8',
         (0x4, 0x800210a, 0xffffffff, 1000))]

    def test_eof(self):
        self.assertTrue(Register.has_more_v120(get_istream(self.input)))

    def test_load_insufficient(self):
        with self.assertRaises(ValueError):
            Register.load_v120(get_istream(self.input[:-1]), 0)

    def test_load(self):
        istream = get_istream(self.input)
        self.assertTrue(Register.has_more_v120(istream))

        obj = Register.load_v120(istream, 0)[0]
        self.assertIsInstance(str(obj), str)

        for i, j in zip(tuple(obj), self.output):
            self.assertEqual(i, j)

    def test_dump(self):
        obj = Register(*self.output)
        self.assertEqual(obj.len_v120(), len(self.input))

        ostream = BufferedRandom(BytesIO())  # type: ignore
        obj.dump_v120(ostream)
        ostream.seek(0)
        data = ostream.read()
        self.assertEqual(data, self.input)


def load_tests(loader: unittest.TestLoader, tests, pattern):
    cases: list[Type[unittest.TestCase]] = [TestRegister]
    for metacase in [_TestRegisterReg, _TestRegisterV120]:
        for params in metacase.CASES:
            cases.append(metacase.generate(*params))

    suite = unittest.TestSuite()
    for case in cases:
        suite.addTests(loader.loadTestsFromTestCase(case))
    return suite


if __name__ == '__main__':
    unittest.main()
