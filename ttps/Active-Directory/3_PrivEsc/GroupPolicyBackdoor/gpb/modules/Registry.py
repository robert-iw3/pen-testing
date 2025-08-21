import uuid
import random

from lxml                       import etree
from datetime                   import datetime, timedelta

from gpb.utils.encodings        import get_xml_declared_encoding
from gpb.modules.utils.filters  import generate_filters

class Registry():
    def __init__(self, module_config, module_options, module_filters, existing_xml, state_folder):
        self.config = module_config
        self.options = module_options
        self.filters = module_filters.filters
        self.xml = existing_xml
        
        if len(self.xml) > 0:
            self.encoding = get_xml_declared_encoding(self.xml)
        else:
            self.encoding = "UTF-8"
        self.state_folder = state_folder
        self.identifier = str(uuid.uuid4()).upper()

        self.run_registry()


    def run_registry(self):
        if len(self.xml) == 0:
            registrysettings = etree.Element("RegistrySettings", attrib={
                "clsid": "{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"
            })
        else:
            registrysettings = etree.XML(self.xml)

        registry = self.registry_generate_xml()

        registrysettings.append(registry)
        tree = etree.ElementTree(registrysettings)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)


    def registry_generate_xml(self):
        
        if self.options.key_type.upper() == "REG_DWORD":
            value = self.options.value.lstrip("0x").zfill(8)
        elif self.options.key_type.upper() == "REG_QWORD":
            value = self.options.value.lstrip("0x").zfill(16)
        elif self.options.key_type.upper() == "REG_MULTI_SZ":
            value = ' '.join(self.options.value.split('||'))
        else:
            value = self.options.value

        registry = etree.Element("Registry", attrib={
            "clsid": "{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}",
            "name": self.options.key,
            "status": self.options.key,
            "image": "7",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
        })

        properties = etree.SubElement(registry, "Properties", attrib={
            "action": "U",
            "displayDecimal": "0",
            "default": "0",
            "hive": self.options.hive,
            "key": self.options.path,
            "name": self.options.key,
            "type": self.options.key_type,
            "value": value
        })

        if self.options.key_type.upper() == "REG_MULTI_SZ":
            values = etree.SubElement(properties, "Values")
            for item in self.options.value.split('||'):
                value = etree.SubElement(values, "Value")
                value.text = item

        generate_filters(registry, self.filters)

        return registry

    def get_xml(self):
        return self.xml