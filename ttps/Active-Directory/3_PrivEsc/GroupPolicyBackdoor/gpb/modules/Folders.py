import json
import uuid
import string
import random
import configparser

from lxml import etree
from datetime import datetime, timedelta

from gpb.utils.encodings        import get_xml_declared_encoding
from gpb.modules.utils.filters  import generate_filters, serialize_filters

class Folders():
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

        self.run_folders()


    def run_folders(self) -> None:
        if len(self.xml) == 0:
            folders = etree.Element("Folders", attrib={
                "clsid": "{77CC39E7-3D16-4f8f-AF86-EC0BBEE2C861}"
            })
        else:
            folders = etree.XML(self.xml)

        if self.options.action == "create":
            folder = self.create_folders_generate_xml()
            self.create_folders_generate_reverse_file()
        elif self.options.action == "delete":
            folder = self.delete_folders_generate_xml()
        else:
            return

        folders.append(folder)
        tree = etree.ElementTree(folders)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)


    def create_folders_generate_xml(self):
        folder = etree.Element("Folder", attrib={
            "clsid": "{07DA02F5-F9CD-4397-A550-4AE21B6B4BD3}",
            "name": "",
            "status": "",
            "image": "0",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
            "bypassErrors": "1"
        })

        properties = etree.SubElement(folder, "Properties", attrib={
            "action": "C",
            "path": self.options.path,
            "archive": "0",
            "hidden": "1" if self.options.hidden else "0",
        })

        generate_filters(folder, self.filters)

        return folder
    

    def delete_folders_generate_xml(self):
        folder = etree.Element("Folder", attrib={
            "clsid": "{07DA02F5-F9CD-4397-A550-4AE21B6B4BD3}",
            "name": "",
            "status": "",
            "image": "3",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}"
        })

        properties = etree.SubElement(folder, "Properties", attrib={
            "action": "D",
            "path": self.options.path,
            "deleteFolder": "1",
            "deleteSubFolders": "1" if self.options.recursive_delete else "0",
            "deleteFiles": "1" if self.options.recursive_delete else "0",
            "deleteReadOnly": "1",
            "deleteIgnoreErrors": "1",
            "readOnly": "0",
            "archive": "1",
            "hidden": "0"
        })

        generate_filters(folder, self.filters)

        return folder


    def create_folders_generate_reverse_file(self):
        reverse_module = configparser.ConfigParser(interpolation=None)

        reverse_module["MODULECONFIG"] = {
            "name": "Folders",
            "type": self.config.type
        }

        reverse_module["MODULEOPTIONS"] = {
            "action": "delete",
            "path": self.options.path,
            "recursive_delete": True
        }

        reverse_module["MODULEFILTERS"] = {}
        if len(self.filters) > 0:
            reverse_module["MODULEFILTERS"]["filters"] = json.dumps(serialize_filters(self.filters))

        filename = f"reverse_Folders_create_{''.join(random.choices(string.ascii_letters, k=6))}.ini"
        with open(f"{self.state_folder}/revert/{filename}", "a+") as f:
            reverse_module.write(f)
 
    def get_xml(self):
        return self.xml