import base64

from ldap3          import Server, Connection, SASL, NTLM, KERBEROS, SUBTREE, MODIFY_REPLACE, MODIFY_DELETE, ALL_ATTRIBUTES, SCHEMA, ALL, TLS_CHANNEL_BINDING, ENCRYPT
from config         import GPBLDAPNoResultsError

def get_ldap_session(domain, dc, ldaps, username, password, kerberos=False, all_info=False):
    if ldaps is True:
        server = Server(f'ldaps://{dc}:636', port = 636, use_ssl = True, get_info=SCHEMA if all_info is False else ALL)
    else:
        server = Server(f'ldap://{dc}:389', port = 389, use_ssl = False, get_info=SCHEMA if all_info is False else ALL)

    if kerberos is False:
        if ldaps is True:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, channel_binding=TLS_CHANNEL_BINDING)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    else:
        if ldaps is True:
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True)
        else:
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    return ldap_session

def add_entry(ldap_session, dn, attributes):
    ldap_session.add(dn, attributes=attributes)


def get_entry(ldap_session, dn, search_filter='(objectClass=*)', attributes=ALL_ATTRIBUTES, get_operational_attributes=False):
    entries = []
    ldap_session.search(
        search_base=dn,
        search_filter=search_filter,
        attributes=attributes,
        size_limit=1,
        get_operational_attributes=get_operational_attributes
    )

    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        raise GPBLDAPNoResultsError(f"LDAP query for '{dn}' with search filter {search_filter} did not return any results")
    return entries[0]


def get_entries(ldap_session, search_base, search_filter, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, get_operational_attributes=False):
    entries = []
    ldap_session.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=search_scope,
        attributes=attributes,
        get_operational_attributes=get_operational_attributes
    )

    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        raise GPBLDAPNoResultsError(f"LDAP query for '{search_base}' with search filter {search_filter} did not return any results")
    
    return entries


def delete_entry(ldap_session, dn):
    ldap_session.delete(dn)


def get_entry_attribute(ldap_session, dn, attribute, search_filter='(objectClass=*)', search_scope=SUBTREE):
    entries = []
    ldap_session.search(
        search_base=dn,
        search_filter=search_filter,
        search_scope=search_scope,
        attributes=[attribute,],
        size_limit=1
    )

    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)

    if len(entries) == 0:
        raise GPBLDAPNoResultsError(f"LDAP query for '{dn}' with search filter {search_filter} did not return any results")

    return entries[0]['attributes'][attribute]


def modify_attribute(ldap_session, dn, attribute, new_value):
    ldap_session.modify(dn, {attribute: [(MODIFY_REPLACE, [new_value])]})


def unset_attribute(ldap_session, dn, attribute):
    ldap_session.modify(dn, {attribute: [(MODIFY_DELETE, [])]})

def serialize_ldap_entry_to_json(entry):
    serialized_entry = {}
    for raw_attribute_name, raw_attribute_values in entry['raw_attributes'].items():
        serialized_values = []
        for raw_attribute_value in raw_attribute_values:
            serialized_values.append(base64.b64encode(raw_attribute_value).decode())
        serialized_entry[raw_attribute_name] = serialized_values
    return serialized_entry
