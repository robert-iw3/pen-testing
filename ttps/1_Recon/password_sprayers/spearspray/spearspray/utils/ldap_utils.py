import logging

from spearspray.modules.ldap import Ldap
from spearspray.utils.constants import GREEN, RED, YELLOW, RESET

log = logging.getLogger(__name__)

def connect_to_ldap(target, domain, username, password, ssl, ldap_page_size):

    ldap_instance = Ldap(target, domain, username, password, ssl, ldap_page_size)
    ldap_connection = ldap_instance.connect_via_credentials()

    return ldap_instance, ldap_connection

def get_domain_password_policy(ldap_instance, ldap_connection) -> dict:

    try:
        domain_policy = ldap_instance.get_default_password_policy(ldap_connection)
        
        return domain_policy
    except Exception:
        log.exception(f"{RED}[-]{RESET} Error retrieving domain policy.")
        return None

def handle_domain_password_policy(domain_policy: dict) -> None:

    if not domain_policy:
        log.warning(f"{RED}[-]{RESET} No password policy data received")
        return

    def _pluralise(value: int, noun: str) -> str:
        return f"{value} {noun}" + ("s" if value != 1 else "")

    def _format_minutes(total: int | None) -> str:

        if total is None or total < 0:
            return "N/A"
        if total == 0:
            return "0 minutes"

        hours, minutes = divmod(total, 60) # Get hours and minutes from total minutes
        parts: list[str] = []
        if hours:
            parts.append(_pluralise(hours, "hour"))
        if minutes:
            parts.append(_pluralise(minutes, "minute"))
        return " ".join(parts)

    threshold = domain_policy.get("lockoutThreshold")
    duration  = domain_policy.get("lockoutDuration_minutes")
    window    = domain_policy.get("lockOutObservationWindow_minutes")

    # Format threshold for display
    if threshold == 0:
        threshold_str = "0 (lock-out disabled)"
    elif threshold is not None:
        threshold_str = _pluralise(threshold, "attempt")
    else:
        threshold_str = "N/A"

    log.success(f"{GREEN}[+]{RESET} Successfully retrieved Domain Password Policy.")
    log.info(
        f"[!] Threshold: {threshold_str}, "
        f"Lock-out Duration: {_format_minutes(duration)}, "
        f"Observation Window: {_format_minutes(window)}."
    )


def get_users_from_ldap(ldap_instance, ldap_connection, query, fields):

    search_entries = ldap_instance.search(ldap_connection, query, fields)

    if search_entries:
        if len(search_entries) == 1:
            log.success(f"{GREEN}[+]{RESET} Found {len(search_entries)} enabled user.")
        else:
            log.success(f"{GREEN}[+]{RESET} Found {len(search_entries)} enabled users.")
        return search_entries
    else:
        log.error(f"{RED}[-]{RESET} No users found.")
        return

def filter_threshold_users(users_objects: list[dict], domain_policy: dict, operator_threshold: int) -> list[dict]:

    domain_threshold = int(domain_policy.get("lockoutThreshold", 0))

    # No lock-out policy, or operator chose not to filter
    if domain_threshold == 0 or operator_threshold <= 0:
        return users_objects

    if domain_threshold < 0:
        log.warning(f"{RED}[-]{RESET} Invalid lockoutThreshold in domain policy")
        return users_objects

    users_at_risk: list[dict] = []
    users_safe: list[dict] = []

    limit = domain_threshold - operator_threshold
    badpwd_errors = 0

    for user in users_objects:
        raw_bad = user.get("badPwdCount", None)

        if raw_bad is None:
            log.debug(f"{YELLOW}[*]{RESET} User {user.get('sAMAccountName', '<unknown>')} missing badPwdCount; treated as at risk.")
            users_at_risk.append(user)
            badpwd_errors += 1
            continue

        try:
            bad_count = int(raw_bad)
        except (TypeError, ValueError):
            log.debug(f"{YELLOW}[*]{RESET} User {user.get('name', '<unknown>')} has invalid badPwdCount; treated as at risk.")
            users_at_risk.append(user)
            badpwd_errors += 1
            continue

        if bad_count >= limit:
            users_at_risk.append(user)
        else:
            users_safe.append(user)

    if users_at_risk:
        if badpwd_errors > 0:
            log.warning(f"{YELLOW}[*]{RESET} {badpwd_errors} user(s) with invalid or missing badPwdCount treated as at risk.")
            log.info("[!] If the number of affected accounts is high, consider changing DC (preferably the PDC).")
        log.warning(f"{YELLOW}[*]{RESET} {len(users_at_risk)} account(s) have ≤ {operator_threshold} attempt(s) remaining and will be skipped.")
    else:
        log.info(f"{YELLOW}[*]{RESET} No accounts close to lock-out detected.")

    return users_safe


def filter_pso_users(users_objects):

    # Identify users with custom password policies (PSO)
    users_with_pso = [u for u in users_objects if u.get("msDS-ResultantPSO")]

    if users_with_pso:

        if len(users_with_pso) == 1:
            log.warning(f"{YELLOW}[*]{RESET} Among those {len(users_objects)} users, {len(users_with_pso)} has PSO applied.")
        else:
            log.warning(f"{YELLOW}[*]{RESET} Among those {len(users_objects)} users, {len(users_with_pso)} have PSO applied.")
        
        answer = input(f"{YELLOW}[*]{RESET} Do you want to include these users in the spraying? (y/n): ").strip().lower()
        if answer.lower() == "y":
            return users_objects  # Do not filter PSO users (Include all users)
        else:
            return [u for u in users_objects if u not in users_with_pso] # Exclude PSO users for safety
    else:
        log.info(f"{YELLOW}[*]{RESET} No users with PSO found.")
        return users_objects