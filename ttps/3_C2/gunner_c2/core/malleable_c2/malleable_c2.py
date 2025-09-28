import logging
logger = logging.getLogger(__name__)

import json
import argparse
import subprocess
import re
import random
import os
import sys
from typing import Any, Dict, Tuple, Optional, Union
from dataclasses import dataclass
from core.listeners.base import listeners, Listener

class MalleableProfile:
    def __init__(self, name: str, blocks: Dict[str, Any]):
        logger.debug(f"[DEBUG] Created MalleableProfile(name={name}, blocks={list(blocks.keys())})")
        self.name = name
        self.blocks = blocks

    def get_block(self, name: str) -> Any:
        return self.blocks.get(name)


def parse_headers(val):
    """
    Accept either:
      - "Name: Value"
      - '{"Name": "Value", ...}'
    and return a Python dict.
    """
    # try JSON first
    try:
        obj = json.loads(val)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # fallback to single Name: Value
    if ":" in val:
        name, value = val.split(":", 1)
        return { name.strip(): value.strip() }

    raise argparse.ArgumentTypeError(f"Invalid header syntax: {val!r}")


def get_listener_by_port_and_transport(port: int, transport: str):
    """
    Find the first listener whose port and transport match the given values.

    :param port: TCP port number of the listener to find
    :param transport: transport protocol string (e.g. "tcp", "http", "https")
    :return: Listener object if found, otherwise None
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        pass

    transport = transport.lower()
    logger.debug(f"PORT TRANSPORT {port} {transport}")
    for listener in listeners.values():
        # normalize transport comparison
        logger.debug(f"LISTENER: {listener}")
        logger.debug(f"LISTENER PORT AND TRANSPORT: {listener.port} {listener.transport}")
        if listener.port == port and listener.transport.lower() == transport:
            logger.debug("RETURNING LISTENER")
            return listener
    return None

def parse_malleable_profile(path: str) -> Optional[MalleableProfile]:
    """
    Load a JSON‐based malleable‐C2 profile with exactly two top‐level keys:
      - "http-get"
      - "http-post"
    Each of those is a dict with subkeys:
      - "uri"    (string)
      - "client" (dict: headers, metadata)
      - "server" (dict: headers, output)
    
    And in server.output only "base64-json" is supported:
      server.output.base64-json is a dict whose values may include the literal
      "{{payload}}" placeholder.
    """
    logger.debug(f"[DEBUG] Loading JSON profile from {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Failed to load JSON profile: {e}")
        return None

    if not isinstance(data, dict):
        logger.debug("[!] Profile JSON must be an object at top level")
        return None

    # Pull out config so we don’t treat it as an HTTP endpoint:
    config = data.get("config", {})
    if not isinstance(config, dict):
        logger.debug("[!] 'config' must be an object")
        return None

    # Ensure only the two allowed top-level keys exist
    for endpoint in ("http-get", "http-post"):
        if endpoint not in data:
            logger.debug(f"[DEBUG] '{endpoint}' missing, inserting empty defaults")
            data[endpoint] = {}

        ep = data[endpoint]
        if not isinstance(ep, dict):
            print(f"[!] '{endpoint}' must be an object")
            return None

        # fill in defaults
        ep.setdefault("uri", "/")
        ep.setdefault("client", {})
        ep.setdefault("server", {})

        client = ep["client"]
        server = ep["server"]

        if not isinstance(client, dict) or not isinstance(server, dict):
            print(f"[!] '{endpoint}.client' and '{endpoint}.server' must each be objects")
            return None

        # client.headers → dict, metadata → list
        client.setdefault("headers", {})
        client.setdefault("metadata", [])

        # server.headers → dict, output → dict
        server.setdefault("headers", {})
        server.setdefault("output", {})

        output = server["output"]
        if "base64-json" not in output:
            logger.debug(f"[DEBUG] '{endpoint}.server.output.base64-json' missing, inserting empty template")
            output["base64-json"] = {}
        elif not isinstance(output["base64-json"], dict):
            print(f"[!] '{endpoint}.server.output.base64-json' must be an object")
            return None

    # Derive profile name from filename (without extension)
    name = os.path.splitext(os.path.basename(path))[0]
    return MalleableProfile(name, data)

@dataclass
class ClientProfileConfig:
    headers: Dict[str,str]
    useragent: str
    uri: str
    uri_post: str
    interval: Union[int, bool]
    jitter: Union[int, bool]
    # you can add more fields here if you need them,
    # e.g. metadata flags, server-side hints, etc.

def apply_client_profile(
    profile: Optional[Union[str,MalleableProfile]],
    headers: Optional[Dict[str,str]],
    useragent: str
) -> ClientProfileConfig:
    """
    Loads & applies a malleable 'http-get' client block.  Returns
    a small dataclass containing the final headers, UA and URI.
    """
    # 1) parse / normalize profile
    prof_obj: Optional[MalleableProfile] = None
    if profile:
        if isinstance(profile, str):
            prof_obj = parse_malleable_profile(profile)

        elif isinstance(profile, MalleableProfile):
            prof_obj = profile

        else:
            raise ValueError("profile must be a path or MalleableProfile")

    # 2) start with any user-supplied headers
    hdrs: Dict[str,str] = dict(headers or {})

    # 3) compute effective UA
    effective_ua = useragent

    # 4) compute default URI (you’ll override if profile gives one)
    uri = "/"

    if prof_obj:
        # a) pick a rare header to fingerprint the profile
        rare = [
            "X-Correlation-ID",
            "X-Request-ID",
            "X-Custom-Context",
            "X-Worker-Name",
            "X-Data-Context",
            "X-Trace-ID",
        ]
        inject = random.choice(rare)
        hdrs[inject] = prof_obj.name

        # b) Get top level blocks
        http_get = prof_obj.get_block("http-get") or {}
        http_post = prof_obj.get_block("http-post") or {}
        config = prof_obj.get_block("config") or {}


        # c) Get second level blocks
        client_block = http_get.get("client", {})
        callback_timing = config.get("callback_timing", {})

        # c) override URI if present
        uri = client_block.get("uri", http_get.get("uri", uri))
        uri_post = http_post.get("uri", "/")

        # d) merge in any header directives
        #    (in your loader you might have stored them as a list,
        #     here we assume {'Name':'Value'} dict)
        for hname, hval in client_block.get("headers", {}).items():
            hdrs[hname] = hval

        # e) override UA if profile says so
        if client_block.get("useragent"):
            effective_ua = client_block["useragent"]

        if callback_timing.get("interval") or callback_timing.get("jitter"):
            interval = callback_timing.get("interval") or None
            jitter = callback_timing.get("jitter") or None

    # 5) return a single object containing everything
    return ClientProfileConfig(
        headers = hdrs,
        useragent = effective_ua,
        uri = uri,
        uri_post = uri_post,
        interval = interval,
        jitter = jitter
    )