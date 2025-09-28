# backend/logutil.py
from __future__ import annotations
import json, logging, os, time, hashlib
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager

_STD_KEYS = {
    "name","msg","args","levelname","levelno","pathname","filename","module",
    "exc_info","exc_text","stack_info","lineno","funcName","created","msecs",
    "relativeCreated","thread","threadName","processName","process","asctime"
}

def _ensure_dir(p: str) -> None:
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass

class JSONLFormatter(logging.Formatter):
    """Strict JSON Lines formatter: one compact JSON object per log line."""
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": int(record.created * 1000),  # epoch ms
            "lvl": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
        # Include any non-standard fields that were passed via `extra=...`
        for k, v in record.__dict__.items():
            if k in _STD_KEYS or k.startswith("_"):
                continue
            try:
                json.dumps(v)  # probe JSON-serializability
                base[k] = v
            except Exception:
                base[k] = repr(v)
        return json.dumps(base, separators=(",", ":"), default=str)

class RichFormatter(logging.Formatter):
    """Readable console formatter with short timestamp + level."""
    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        lvl = record.levelname.ljust(5)
        name = record.name
        msg = record.getMessage()
        # Pack common extras compactly for console
        extras = []
        for k, v in record.__dict__.items():
            if k in _STD_KEYS or k.startswith("_"):
                continue
            # Keep short, avoid huge dumps
            s = _safe_preview(v, limit=160)
            extras.append(f"{k}={s}")
        extras_s = (" " + " ".join(extras)) if extras else ""
        return f"{ts} {lvl} [{name}] {msg}{extras_s}"

def get_logger(name: str,
               file_basename: str = "app",
               *,
               level: str | None = None,
               log_dir: str | None = None) -> logging.Logger:
    """
    Create a logger with:
      - JSONL rotating file logs (10MB x 5 by default)
      - human-console logs
    Levels can be controlled via env:
      LOG_LEVEL_FILE, LOG_LEVEL_CONSOLE, LOG_LEVEL (fallback)
      LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT
    """
    logger = logging.getLogger(name)
    if getattr(logger, "_logutil_configured", False):
        return logger

    lv_env = os.getenv("LOG_LEVEL", "DEBUG")
    logger.setLevel(level or lv_env)

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(os.getenv("LOG_LEVEL_CONSOLE", "INFO"))
    ch.setFormatter(RichFormatter())
    logger.addHandler(ch)

    # File (JSONL)
    log_dir = log_dir or os.getenv("LOG_DIR", "logs")
    _ensure_dir(log_dir)
    max_bytes = int(os.getenv("LOG_MAX_BYTES", "10485760"))   # 10MB
    backups   = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    fh = RotatingFileHandler(os.path.join(log_dir, f"{file_basename}.log"),
                             maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    fh.setLevel(os.getenv("LOG_LEVEL_FILE", "DEBUG"))
    fh.setFormatter(JSONLFormatter())
    logger.addHandler(fh)

    logger.propagate = False
    logger._logutil_configured = True  # type: ignore[attr-defined]
    return logger

class ContextAdapter(logging.LoggerAdapter):
    """Allows binding persistent context (e.g., wsid, sid)."""
    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs

def bind(logger: logging.Logger, **ctx) -> ContextAdapter:
    return ContextAdapter(logger, ctx)

def _safe_preview(val, *, limit: int = 256) -> str:
    s = str(val)
    return s if len(s) <= limit else (s[:limit] + "…")

def safe_preview(val, *, limit: int = 256) -> str:
    return _safe_preview(val, limit=limit)

def redacts(s: str | None, show: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= show:
        return "*" * len(s)
    return s[:show] + "…" + "*" * max(0, len(s) - show - 1)

def file_magic(path: str, n: int = 4) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(n).hex()
    except Exception:
        return ""

def sha256_path(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

@contextmanager
def span(logger: logging.Logger | ContextAdapter, event: str, **fields):
    """Log begin/end (and duration ms) around a block."""
    t0 = time.perf_counter()
    logger.info(f"{event}.begin", extra=fields)
    try:
        yield
        dur_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(f"{event}.end", extra={**fields, "dur_ms": dur_ms})
    except Exception:
        logger.exception(f"{event}.error", extra=fields)
        raise
