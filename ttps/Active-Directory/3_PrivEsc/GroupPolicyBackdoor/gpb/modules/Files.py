import json
import uuid
import string
import random
import configparser

from lxml import etree
from datetime import datetime, timedelta

from gpb.utils.encodings        import get_xml_declared_encoding
from gpb.modules.utils.filters  import generate_filters, serialize_filters

class Files():
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

        self.run_files()


    def run_files(self) -> None:
        if len(self.xml) == 0:
            files = etree.Element("Files", attrib={
                "clsid": "{215B2E53-57CE-475c-80FE-9EEC14635851}"
            })
        else:
            files = etree.XML(self.xml)

        if self.options.action == "create":
            file = self.create_files_generate_xml()
            self.create_files_generate_reverse_file()
        elif self.options.action == "delete":
            file = self.delete_files_generate_xml()
        else:
            return

        files.append(file)
        tree = etree.ElementTree(files)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)


    def create_files_generate_xml(self):
        file = etree.Element("File", attrib={
            "clsid": "{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}",
            "name": self.options.name,
            "status": self.options.name,
            "image": "0",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
            "bypassErrors": "1"
        })

        properties = etree.SubElement(file, "Properties", attrib={
            "action": "C",
            "fromPath": self.options.source_file,
            "targetPath": self.options.destination_file,
            "readOnly": "0",
            "archive": "0",
            "hidden": "1" if self.options.hidden else "0",
        })

        generate_filters(file, self.filters)

        return file
    

    def delete_files_generate_xml(self):
        file = etree.Element("File", attrib={
            "clsid": "{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}",
            "name": self.options.name,
            "status": self.options.name,
            "image": "3",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
            "bypassErrors": "1"
        })

        properties = etree.SubElement(file, "Properties", attrib={
            "action": "D",
            "targetPath": self.options.destination_file,
            "readOnly": "0",
            "archive": "0",
            "hidden": "0",
        })

        generate_filters(file, self.filters)

        return file


    def create_files_generate_reverse_file(self):
        reverse_module = configparser.ConfigParser(interpolation=None)

        reverse_module["MODULECONFIG"] = {
            "name": "Files",
            "type": self.config.type
        }

        reverse_module["MODULEOPTIONS"] = {
            "action": "delete",
            "task_name": self.options.name,
            "destination_file": self.options.destination_file
        }

        reverse_module["MODULEFILTERS"] = {}
        if len(self.filters) > 0:
            reverse_module["MODULEFILTERS"]["filters"] = json.dumps(serialize_filters(self.filters))

        filename = f"reverse_Files_create_{''.join(random.choices(string.ascii_letters, k=6))}.ini"
        with open(f"{self.state_folder}/revert/{filename}", "a+") as f:
            reverse_module.write(f)
 
    def get_xml(self):
        return self.xml