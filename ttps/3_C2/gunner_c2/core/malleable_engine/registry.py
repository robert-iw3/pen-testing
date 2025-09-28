from __future__ import annotations
from typing import Dict, Type
from .base import ProfileParser, ProfileLoader

PARSERS: Dict[str, Type[ProfileParser]] = {}
LOADERS: Dict[str, Type[ProfileLoader]] = {}

def register_parser(name: str):
    def deco(cls: Type[ProfileParser]):
        PARSERS[name] = cls
        return cls
    return deco

def register_loader(name: str):
    def deco(cls: Type[ProfileLoader]):
        LOADERS[name] = cls
        return cls
    return deco
