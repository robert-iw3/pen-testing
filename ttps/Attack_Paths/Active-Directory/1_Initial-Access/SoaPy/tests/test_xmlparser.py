from src.encoder import XMLParser
from src.encoder.records import dump_records, print_records
import unittest


class TestXMLParserText(unittest.TestCase):
    def test_parse_simple(self):
        value = "<s:Header></s:Header>"
        r = XMLParser.parse(value)

        s = print_records(r)

        self.assertEqual(s, value)

    def test_parse_basic_case(self):
        value = "<s:Envelope><b:Body></b:Body></s:Envelope>"
        r = XMLParser.parse(value)

        s = print_records(r)

        self.assertEqual(s, value)

    def test_parse_attribute_basic(self):
        value = '<wsen:Filter Dialect="http://schemas.LdapQuery"></wsen:Filter>'
        r = XMLParser.parse(value)
        s = print_records(r)

        self.assertEqual(s, value)

    def test_parse_complex(self):
        value = "<adlq:filter>(&(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))</adlq:filter>"
        r = XMLParser.parse(value)
        s = print_records(r)

        self.assertEqual(s, value)


class TestXMLParserBinary(unittest.TestCase):
    def test_bin_dict_basic(self):
        value = "<s:Header></s:Header>"
        expected_result = b"\x56\x08\x01"
        r = XMLParser.parse(value)

        result = dump_records(r)

        self.assertEqual(result, expected_result)

    def test_bin_dict_complex(self):
        value = '<a:Action s:mustUnderstand="1">action</a:Action>'
        expected_result = b"\x44\x0a\x1e\x00\x82\x99\x06\x61\x63\x74\x69\x6f\x6e"

        r = XMLParser.parse(value)
        result = dump_records(r)
        self.assertEqual(result, expected_result)

    def test_bin_dict_complex2(self):
        """
        These are complex cases, see [MC-NBFX]: 2.2.3.31
        """

        value = "<Inventory>0</Inventory>"
        expected_result = b"\x40\x09\x49\x6e\x76\x65\x6e\x74\x6f\x72\x79\x81"

        r = XMLParser.parse(value)
        result = dump_records(r)
        self.assertEqual(result, expected_result)

    def test_bin_dict_complex3(self):
        """
        These are complex cases, see [MC-NBFX]: 2.2.3.31
        """

        value = "<s:Body><Inventory>0</Inventory></s:Body>"
        expected_result = (
            b"\x56\x0e\x40\x09\x49\x6e\x76\x65\x6e\x74\x6f\x72\x79\x81\x01"
        )

        r = XMLParser.parse(value)
        result = dump_records(r)
        self.assertEqual(result, expected_result)

    def test_bin_complex(self):
        """
        These are complex cases, see [MC-NBFX]: 2.2.3.31
        """
        self.maxDiff = None

        value = """<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header>
<a:Action s:mustUnderstand="1">action</a:Action>
</s:Header>
<s:Body>
<Inventory>0</Inventory>
</s:Body>
</s:Envelope>"""

        expected_result = b"V\x02\x0b\x01a\x06\x0b\x01s\x04V\x08D\n\x1e\x00\x82\x99\x06action\x01V\x0e@\tInventory\x81\x01\x01"

        r = XMLParser.parse(value)
        result = dump_records(r)
        self.assertEqual(result, expected_result)
