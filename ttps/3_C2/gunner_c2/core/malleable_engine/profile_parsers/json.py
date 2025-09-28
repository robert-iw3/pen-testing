from __future__ import annotations
import json, os, logging
from typing import Any, Dict, Optional
from ..registry import register_parser
from ..base import ProfileParser
from core.malleable_c2.malleable_c2 import MalleableProfile  # reuse your class

log = logging.getLogger(__name__)

@register_parser("json")
class Json(ProfileParser):
    """Strict JSON profile parser with your current rules."""
    NAME = "json"
    _ABSTRACT = False

    def parse(self, path: str) -> Optional[MalleableProfile]:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("Failed to load JSON profile %r: %s", path, e)
            return None

        if not isinstance(data, dict):
            log.error("Profile JSON must be a top-level object")
            return None

        config = data.get("config", {})
        if not isinstance(config, dict):
            log.error("'config' must be an object")
            return None

        for endpoint in ("http-get", "http-post"):
            ep = data.get(endpoint, {})
            if not isinstance(ep, dict):
                log.error("'%s' must be an object", endpoint)
                return None

            ep.setdefault("uri", "/")
            ep.setdefault("client", {})
            ep.setdefault("server", {})

            client = ep["client"]
            server = ep["server"]
            if not isinstance(client, dict) or not isinstance(server, dict):
                log.error("'%s.client' and '%s.server' must be objects", endpoint, endpoint)
                return None

            client.setdefault("headers", {})
            client.setdefault("metadata", [])
            server.setdefault("headers", {})
            server.setdefault("output", {})

            output = server["output"]
            if "base64-json" not in output:
                output["base64-json"] = {}
            elif not isinstance(output["base64-json"], dict):
                log.error("'%s.server.output.base64-json' must be an object", endpoint)
                return None

            data[endpoint] = ep

        name = os.path.splitext(os.path.basename(path))[0]
        return MalleableProfile(name, data)
