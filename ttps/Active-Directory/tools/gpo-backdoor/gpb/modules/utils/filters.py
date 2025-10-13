from lxml import etree

def generate_filters(xml_root, module_filters):
    if len(module_filters) > 0:
        filters = etree.SubElement(xml_root, "Filters")
        for value in module_filters:
            if value.type == "Computer Name":
                etree.SubElement(filters, "FilterComputer", attrib={
                    "bool": value.operator,
                    "not": "0",
                    "type": "DNS",
                    "name": value.value
                })
            elif value.type == "Security Group":
                etree.SubElement(filters, "FilterGroup", attrib={
                    "bool": value.operator,
                    "not": "0",
                    "name": value.group_name,
                    "sid": value.group_sid,
                    "userContext": "0" if value.user_context is False else "1",
                    "primaryGroup": "0" if value.primary_group is False else "1",
                    "localGroup": "0"
                })
            elif value.type == "WMI Query":
                etree.SubElement(filters, "FilterWmi", attrib={
                    "bool": value.operator,
                    "not": "0",
                    "query": value.query,
                    "namespace": value.namespace,
                    "property": "",
                    "variableName": ""
                })

def serialize_filters(filters):
    serialized = []
    for value in filters:
        if value.type == "Computer Name":
            serialized.append({
                "operator": value.operator,
                "type": "Computer Name",
                "value": value.value
            })
        elif value.type == "Security Group":
            serialized.append({
                "operator": value.operator,
                "type": "Security Group",
                "group_name": value.group_name,
                "group_sid": value.group_sid,
                "primary_group": value.primary_group,
                "user_context": value.user_context
            })
        elif value.type == "WMI Query":
            serialized.append({
                "operator": value.operator,
                "type": "WMI Query",
                "query": value.query,
                "namespace": value.namespace,
                "property": ""
            })
    return serialized