import io
from lxml       import etree

def get_xml_declared_encoding(xml_bytes_string):
    parser = etree.XMLParser()
    tree = etree.parse(io.BytesIO(xml_bytes_string), parser=parser)
    return tree.docinfo.encoding