import unittest

from src.encoder.records import record, dump_records, print_records
from src.encoder.records.text import Chars8TextRecord

import textwrap

from io import BytesIO, StringIO

from base64 import b64decode


class TestRecord(unittest.TestCase):
    def test_collect_records(self):
        """All the record types should be assembled
        when the Record object is initalized
        """
        r = record()
        self.assertEqual(len(r.records), 150)

    def test_singlton_records(self):
        """There should only be one version
        of the records dictionary around for multiple
        Record objects
        """

        r1 = record()
        r2 = record()

        self.assertTrue(r1.records is r2.records)

    def test_parse_bin_to_record_type(self):
        value = b"A\x01a\x04test\x01"
        r = record.parse(BytesIO(value))
        self.assertEqual(r[0].type, 0x41)

    def test_parse_bin_to_record_value(self):
        value = b"A\x01a\x04test\x01"
        r = record.parse(BytesIO(value))
        self.assertEqual(str(r[0]), "<a:test>")

    def test_parse_Chars8TextRecord_value(self):
        value = b64decode("CnhzZDpzdHJpbmeZ")
        expected_result = "xsd:string"
        r = Chars8TextRecord.parse(BytesIO(value))
        self.assertEqual(r.value, expected_result)

    def test_to_int_complex2(self):
        """This caused breaking issues
        by miscalculating the size of some of the elements
        """
        value = b64decode(
            "mAp4c2Q6c3RyaW5nmSQ0MDg5MTk4Yi00NmZkLTQyZjEtYmM1YS03NzA5ZGZlZmUzYzcBQQZhZGRhdGELZGVzY3JpcHRpb24ECkxkYXBTeW50YXiYDVVuaWNvZGVTdHJpbmdBAmFkBXZhbHVlBQN4c2kEdHlwZZg="
        )
        value = BytesIO(value)
        value.read(1)
        result = Chars8TextRecord.parse(value)
        expected = "xsd:string"

        self.assertEqual(result.value, expected)


class TestDumpRecords(unittest.TestCase):
    def test_parse_bin_to_record_dump(self):
        value = b"A\x01a\x04test\x01"
        r = record.parse(BytesIO(value))

        s = dump_records(r)

        self.assertEqual(s, b"A\x01a\x04test\x01")


class TestPrintRecords(unittest.TestCase):
    def test_dict_basic(self):
        value = b"\x56\x08\x01"
        expected_result = "<s:Header></s:Header>"
        r = record.parse(BytesIO(value))
        result = print_records(r)
        self.assertEqual(result, expected_result)

    def test_dict_complex(self):
        value = b"\x44\x0a\x1e\x00\x82\x99\x06\x61\x63\x74\x69\x6f\x6e"
        expected_result = '<a:Action s:mustUnderstand="1">action</a:Action>'

        r = record.parse(BytesIO(value))
        result = print_records(r)
        self.assertEqual(result.replace("\r\n", ""), expected_result)

    def test_dict_xmlns_complex(self):
        value = b"\x56\x02\x0b\x01\x61\x06\x0b\x01\x73\x04\x01"
        expected_result = '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"></s:Envelope>'

        r = record.parse(BytesIO(value))
        result = print_records(r)
        self.assertEqual(result.replace("\r\n", ""), expected_result)

    def test_basic(self):
        value = b"\x40\x09\x49\x6e\x76\x65\x6e\x74\x6f\x72\x79\x01"
        expected_result = "<Inventory></Inventory>"

        r = record.parse(BytesIO(value))
        result = print_records(r)
        self.assertEqual(result.replace("\r\n", ""), expected_result)

    def test_zerowithend_complex(self):
        value = b"\x40\x09\x49\x6e\x76\x65\x6e\x74\x6f\x72\x79\x81"
        expected_result = "<Inventory>0</Inventory>"

        r = record.parse(BytesIO(value))
        result = print_records(r)
        self.assertEqual(result.replace("\r\n", ""), expected_result)

    def test_xmlns_large_complex(self):
        self.maxDiff = None

        value = b"V\x02\x0b\x01a\x06\x0b\x01s\x04V\x08D\n\x1e\x00\x82\x99\x06action\x01V\x0e@\tInventory\x81\x01\x01"

        expected_result = """<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action s:mustUnderstand="1">action</a:Action></s:Header><s:Body><Inventory>0</Inventory></s:Body></s:Envelope>"""

        r = record.parse(BytesIO(value))

        result = print_records(r)

        self.assertEqual(textwrap.dedent(result), textwrap.dedent(expected_result))
