import json
import uuid
import string
import random
import configparser

from lxml import etree
from datetime import datetime, timedelta

from gpb.utils.encodings        import get_xml_declared_encoding
from gpb.modules.utils.filters  import generate_filters, serialize_filters

class Groups():
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

        self.run_groups()


    def run_groups(self):
        if len(self.xml) == 0:
            groups = etree.Element("Groups", attrib={
                "clsid": "{3125E937-EB16-4b4c-9934-544FC6D24D26}"
            })
        else:
            groups = etree.XML(self.xml)

        group = self.groups_generate_xml()
        if self.options.action == "add":
            self.groups_generate_reverse_file()

        groups.append(group)
        tree = etree.ElementTree(groups)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)


    def groups_generate_xml(self):
        group = etree.Element("Group", attrib={
            "clsid": "{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}",
            "name": self.options.group_name,
            "image": "2",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
        })

        properties = etree.SubElement(group, "Properties", attrib={
            "action": "U",
            "newName": "",
            "description": "",
            "deleteAllUsers": "0",
            "deleteAllGroups": "0",
            "removeAccounts": "0",
            "groupSid": self.options.group_sid,
            "groupName": self.options.group_name
        })

        members = etree.SubElement(properties, "Members")
        member = etree.SubElement(members, "Member", attrib={
            "name": self.options.user_name,
            "action": "REMOVE" if self.options.action == "remove" else "ADD",
            "sid": self.options.user_sid
        })

        generate_filters(group, self.filters)

        return group

    def groups_generate_reverse_file(self):
        reverse_module = configparser.ConfigParser(interpolation=None)

        reverse_module["MODULECONFIG"] = {
            "name": "Groups",
            "type": self.config.type
        }

        reverse_module["MODULEOPTIONS"] = {
            "action": "remove",
            "group_sid": self.options.group_sid,
            "user_sid": self.options.user_sid
        }
        if self.options.group_name:
            reverse_module["MODULEOPTIONS"]["group_name"] = self.options.group_name
        if self.options.user_name:
            reverse_module["MODULEOPTIONS"]["user_name"] = self.options.user_name

        reverse_module["MODULEFILTERS"] = {}
        if len(self.filters) > 0:
            reverse_module["MODULEFILTERS"]["filters"] = json.dumps(serialize_filters(self.filters))

        filename = f"reverse_Groups_add_{''.join(random.choices(string.ascii_letters, k=6))}.ini"
        with open(f"{self.state_folder}/revert/{filename}", "a+") as f:
            reverse_module.write(f)
 
    def get_xml(self):
        return self.xml