from gpb.protocols.ldap import get_entry_attribute, get_entry

from config import logger, bcolors, GPBLDAPNoResultsError

def get_gpo_by_name(ldap_session, domain, gpo_name):
    domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
    try:
        result = get_entry_attribute(ldap_session, f"CN=Policies,CN=System,{domain_dn}", 'cn', f'(displayName={gpo_name})')
        gpo_guid = result[1:-1]
    except GPBLDAPNoResultsError as e:
        logger.error(f"{bcolors.FAIL}[!] Could not find GPO with name '{gpo_name}'{bcolors.ENDC}")
        return None
    return gpo_guid


def gpo_exists(ldap_session, domain, gpo_guid):
    domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
    try:
        get_entry(ldap_session, f"CN=Policies,CN=System,{domain_dn}", search_filter=f"(cn={{{gpo_guid}}})")

    except GPBLDAPNoResultsError as e:
        logger.error(f"{bcolors.FAIL}[!] Could not find GPO with GUID '{gpo_guid}'{bcolors.ENDC}")
        return None
    return gpo_guid
