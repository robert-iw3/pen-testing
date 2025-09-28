from __future__ import annotations
import re, random
from ..registry import register_loader
from ..base import ProfileLoader, EngineProfile
from dataclasses import dataclass
from typing import Dict, Any, Optional
from copy import deepcopy

from core.malleable_c2.malleable_c2 import get_listener_by_port_and_transport, MalleableProfile

_RARE = ["X-Correlation-ID","X-Request-ID","X-Custom-Context","X-Worker-Name","X-Data-Context","X-Trace-ID"]

@dataclass
class ExeCsharpHttpConfig:
    # URIs
    get_uri: str
    post_uri: str
    # UA + headers
    useragent: str
    headers_get: Dict[str,str]
    headers_post: Dict[str,str]
    accept: Optional[str]
    accept_post: Optional[str]
    host: Optional[str]
    host_post: Optional[str]
    byte_range: Optional[int]
    # timing
    interval_ms: Optional[int]
    jitter_pct: Optional[int]
    # mapping (GET response → payload), (POST body ← payload)
    get_server_mapping: Dict[str, Any]
    post_client_mapping: Dict[str, Any]

@register_loader("exe_csharp_https_profile_loader")
class ExeCsharpHttpV1(ProfileLoader):
    NAME = "exe_csharp_https_v1"
    _ABSTRACT = False

    def _ci_pop(self, d: dict, key: str):
        if not d:
            return None

        for k in list(d.keys()):
            if k.lower() == key.lower():
                return d.pop(k)

        return None

    def load(self, prof: MalleableProfile, *, defaults: Dict[str, Any]) -> ExeCsharpHttpConfig:
        # Defaults coming from CLI
        d_headers   = dict(defaults.get("headers") or {})
        d_ua        = defaults.get("useragent")
        d_accept    = defaults.get("accept")
        d_host      = defaults.get("host")
        d_range     = defaults.get("byte_range")
        d_interval  = defaults.get("interval")
        d_jitter    = defaults.get("jitter")
        port        = defaults.get("port")
        transport   = defaults.get("transport") or "http"

        g = deepcopy(prof.get_block("http-get")  or {})
        p = deepcopy(prof.get_block("http-post") or {})
        cfg = deepcopy(prof.get_block("config")   or {})
        ct  = cfg.get("callback_timing", {}) or {}

        get_uri  = g.get("uri", "/")
        post_uri = p.get("uri", "/")

        cget  = deepcopy((g.get("client") or {}))
        cpost = deepcopy((p.get("client") or {}))
        h_get = dict((cget.get("headers") or {}))
        h_post= dict((cpost.get("headers") or {}))

        # Accept/Host/Range precedence: CLI > Profile
        if d_accept:
            accept = d_accept
            accept_post = d_accept 

        else:
            accept = h_get.pop("Accept", None)
            accept_post = self._ci_pop(h_post, "Accept")

        if not accept_post:
            accept_post = ""

        if d_host:
            host = d_host
            host_post = d_host

        else:
            host = self._ci_pop(h_get, "Host")
            host_post = self._ci_pop(h_post, "Host")

        rng = d_range
        if rng is None:
            if "Range" in h_get:
                m = re.search(r"\d+", h_get.pop("Range") or "")
                rng = int(m.group()) if m else None

        if not host_post:
            host_post = ""

        # Merge headers: profile then CLI overrides
        headers_get  = {**h_get,  **d_headers}
        headers_post = {**h_post, **d_headers}

        # Add a fingerprint header with profile name
        headers_get[random.choice(_RARE)] = prof.name
        headers_post[random.choice(_RARE)] = prof.name

        # UA
        ua = cget.get("useragent") or d_ua

        # Mapping: GET response path holding payload
        srv_out = (g.get("server") or {}).get("output") or {}
        get_map = srv_out.get("mapping") or {"cmd":"{{payload}}","DeviceTelemetry":{"Telemetry":"{{payload}}"}}

        # Mapping: POST body wrapping payload
        post_out = (cpost.get("output") or {})
        post_map = post_out.get("mapping") or {"output":"{{payload}}"}

        # Interval/jitter (keep raw ints; generator decides exact sleep usage)
        interval_ms = ct.get("interval", d_interval)
        jitter_pct  = ct.get("jitter",   d_jitter)

        # expose profile on the listener (parity with PS1 path)
        try:
            lst = get_listener_by_port_and_transport(port, transport)
            if lst:
                if not hasattr(lst, "profiles") or lst.profiles is None:
                    lst.profiles = {}
                lst.profiles[prof.name] = prof
        except Exception:
            pass

        return ExeCsharpHttpConfig(
            get_uri=get_uri, post_uri=post_uri,
            useragent=ua,
            headers_get=headers_get, headers_post=headers_post,
            accept=accept, accept_post=accept_post, host=host, host_post=host_post, byte_range=rng,
            interval_ms=interval_ms, jitter_pct=jitter_pct,
            get_server_mapping=get_map, post_client_mapping=post_map
        )
