from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import importlib, pkgutil
from pathlib import Path
from typing import Dict, Any, Optional

@dataclass
class EngineProfile:
    """
    Normalized config the generator needs.
    """
    get_uri: str
    post_uri: str
    useragent: str
    client_headers_get: Dict[str, str]
    client_headers_post: Dict[str, str]
    accept: Optional[str]
    host: Optional[str]
    byte_range: Optional[int]
    interval_ms: Optional[int]
    jitter_pct: Optional[int]
    # simple mappings (JSON fragments with {{payload}})
    get_server_mapping: Dict[str, Any]    # for extracting tasking from GET body
    post_client_mapping: Dict[str, Any]   # for wrapping POST result

class ProfileParser(ABC):
    """Turns a profile file into a raw dict / AST."""
    @abstractmethod
    def parse(self, path: str) -> Dict[str, Any]:
        """Load + basic-validate. Return raw dict."""

class ProfileLoader(ABC):
    """
    Converts raw dict to EngineProfile using optional defaults from CLI.
    """
    @abstractmethod
    def load(self, raw: Dict[str, Any], *, defaults: Dict[str, Any]) -> EngineProfile:
        """Return EngineProfile normalized for emitters."""

def _import_all(pkg_name: str):
    pkg = importlib.import_module(pkg_name)
    for _, modname, _ in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        importlib.import_module(modname)

def load_plugins():
    """
    Auto-import all modules under profile_parsers/ and profile_loaders/.
    Classes call @register_* on import, populating registries.
    """
    _import_all("core.malleable_engine.profile_parsers")
    _import_all("core.malleable_engine.profile_loaders")