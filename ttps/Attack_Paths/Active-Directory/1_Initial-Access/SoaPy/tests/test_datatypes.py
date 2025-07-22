import unittest
from io import BytesIO

from hypothesis import given
from hypothesis.strategies import integers, text

from src.encoder.records.datatypes import MultiByteInt31, Utf8String


class TestMultiByteInt31(unittest.TestCase):
    def test_to_bytes_basic(self):
        value = 268435456
        expected_result = b"\x80\x80\x80\x80\x01"
        resuilt = MultiByteInt31(value).to_bytes()
        self.assertEqual(resuilt, expected_result)

    def test_to_bytes_complex(self):
        value = 0x3FFFFFFF
        expected_result = b"\xff\xff\xff\xff\x03"
        resuilt = MultiByteInt31(value).to_bytes()
        self.assertEqual(resuilt, expected_result)

    def test_to_int_basic(self):
        value = BytesIO(b"\x80\x80\x80\x80\x01")
        expected_result = 268435456
        result = MultiByteInt31.parse(value).value
        self.assertEqual(result, expected_result)

    def test_to_int_singlebyte(self):
        value = BytesIO(b"\x0a")
        expected_result = 0xA
        result = MultiByteInt31.parse(value).value
        self.assertEqual(result, expected_result)

    def test_to_int_complex(self):
        value = BytesIO(b"\x0a\x78\x73\x64\x3a\x73\x74\x72\x69\x6e\x67\x99")
        expected_result = 0xA
        result = MultiByteInt31.parse(value).value
        self.assertEqual(result, expected_result)

    @given(i=integers(min_value=0x0, max_value=0xFFFFFFF))
    def test_invariant(self, i):
        bin_val = MultiByteInt31(i).to_bytes()
        int_val = MultiByteInt31.parse(BytesIO(bin_val)).value
        self.assertEqual(int_val, i)


class TestUtf8String(unittest.TestCase):
    def test_to_bytes_basic(self):
        value = "abc"
        expected_result = b"\x03\x61\x62\x63"
        result = Utf8String(value).to_bytes()
        self.assertEqual(result, expected_result)

    def test_to_bytes_complex(self):
        value = b"\xc3\xbcber".decode("utf-8")
        expected_result = b"\x05\xc3\xbcber"
        result = Utf8String(value).to_bytes()
        self.assertEqual(result, expected_result)

    def test_to_string_basic(self):
        value = b"\x03\x61\x62\x63"
        expected_result = "abc"
        result = Utf8String.parse(BytesIO(value)).value
        self.assertEqual(result, expected_result)

    def test_bytes_to_bytes(self):
        value = b"\x05\xc3\xbcber"
        result = Utf8String.parse(BytesIO(value))

        print(result)
        self.assertEqual(result.to_bytes(), value)

    @given(s=text(min_size=0x0, max_size=0xFFFFFFF))
    def test_invariant(self, s):
        bin_val = Utf8String(s).to_bytes()
        str_val = Utf8String.parse(BytesIO(bin_val)).value
        self.assertEqual(str_val, s)
