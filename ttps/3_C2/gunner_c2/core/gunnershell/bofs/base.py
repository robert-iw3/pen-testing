import logging
logger = logging.getLogger(__name__)

import os
import base64
import pkgutil
import importlib
import argparse
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, Type, Optional, Any, List

# ─── BOF Base ────────────────────────────────────────────────────────────────
class Bof(ABC):
	"""
	Base for all BOF providers.
	Subclasses MUST implement load_bytes() to return the object file bytes.
	You may accept the Gunnershell instance if you need context.
	"""
	def __init__(self, gs=None):
		self.gs = gs

	@abstractmethod
	def help_menu(self):
		"""Print Help menu for BOF"""

	@staticmethod
	def args_inject(p: argparse.ArgumentParser) -> None:
		"""
		Optional: BOF-specific argparse injection.
		Add any custom arguments here, e.g.:
		    p.add_argument('--foo', help='...') 
		"""
		return

	@staticmethod
	def build_remote_args(ns: Any) -> List[str]:
		"""
		Optional: Convert parsed args into a list of strings to append
		to the remote 'bofexec <b64> ...' command. Return [] if none.
		Example return: ['--foo', ns.foo] or ['-i:3389'].
		"""
		return []

	'''@abstractmethod
	def load_bytes(self) -> bytes:
		"""Return the BOF object bytes."""'''

# Registry
BOFS: Dict[str, Type[Bof]] = {}

def register(*names: str):
	"""
	Decorator to register a Bof subclass under one or more names.
	"""
	def deco(cls: Type[Bof]):
		for name in names:
			BOFS[name] = cls
		return cls
	return deco

def get(name: str) -> Type[Bof] | None:
	"""Return the registered Bof class by name, or None."""
	return BOFS.get(name)

def list_bofs() -> list[str]:
	"""Sorted list of registered BOF names."""
	return sorted(BOFS.keys())

def load():
	"""
	Import every .py under core/gunnershell/bofs/** (except .base)
	so that @register hooks can populate BOFS.
	"""
	pkg = importlib.import_module(__package__)  # "core.gunnershell.bofs"
	for _, module_name, _ in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
		if module_name == pkg.__name__ + ".base":
			continue
		logger.debug(f"Loading BOF module {module_name}")
		try:
			importlib.import_module(module_name)
		except Exception:
			logger.exception("Failed to import BOF module %r", module_name)

# ─── Resolver ────────────────────────────────────────────────────────────────
def _resolve_bof_bytes(name_or_path: str, bofarch: str, zargs: List[str] | None = None, Zargs: List[str] | None = None,
	int16: List[int] | None = None, int32: List[int] | None = None) -> Optional[tuple[list[str], str]]:
	"""
	Resolve a BOF by name or filesystem path and return a **base64 string**.

	Search order:
	  1) BOF library (BOFS) — if a class is registered under the given key
		 (or the basename fallback), return CLASS.base64bof. If that attribute
		 doesn't exist, but the class implements load_bytes(), base64-encode its
		 return value and return the string.
	  2) Filesystem — if a file exists at the given path (or path with .o/.obj
		 appended when no extension is provided), read bytes, base64-encode, and
		 return the string.

	Returns:
	  base64-encoded string if resolved, otherwise None.
	"""
	# 1) Library lookup (exact key, then basename fallback)
	if bofarch == "x64":
		key = "base64bof"

	else:
		key = "x86base64bof"

	if not zargs:
		zargs = []

	if not Zargs:
		Zargs = []

	try:
		cls: Optional[Type[Any]] = BOFS.get(name_or_path)
		if not cls:
			basename_key = Path(name_or_path).stem
			cls = BOFS.get(basename_key)
		if cls:
			# Primary: class attribute `base64bof`
			b64 = getattr(cls, key, None)
			argfunc = getattr(cls, "check_args", None)
			if isinstance(b64, str) and b64.strip():
				if argfunc:
					args = cls.check_args(zargs=zargs, Zargs=Zargs, int16=int16, int32=int32)
					logger.debug(f"{args}")
					return args, b64.strip()

				else:
					placeholder = []
					return placeholder, b64.strip()

	except Exception as e:
		logger.debug(f"BOF library resolution error for {name_or_path}: {e}")

	# 2) Filesystem lookup
	try:
		candidates = []
		p = Path(name_or_path)
		if p.is_file():
			candidates.append(p)
		else:
			logger.debug("BOF was not a file!")
			return "BOF was not a file!"

		for cand in candidates:
			if cand.is_file():
				try:
					data = cand.read_bytes()
					placeholder = []
					return placeholder, base64.b64encode(data).decode("ascii")

				except Exception as e:
					logger.debug(f"Failed reading BOF file {cand}: {e}")

	except Exception as e:
		logger.debug(f"BOF filesystem resolution error for {name_or_path}: {e}")

	return None