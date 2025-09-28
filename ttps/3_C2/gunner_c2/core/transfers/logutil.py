# core/transfers/logutil.py
import logging, os

_LOGGER_NAME = "core.transfers"  # package logger all children inherit from
_initialized = False

def setup_once():
    global _initialized
    if _initialized:
        return
    logger = logging.getLogger(_LOGGER_NAME)
    # already installed?
    for h in logger.handlers:
        if hasattr(h, "_is_transfers_log"):
            logger.propagate = False
            _initialized = True
            return

    log_path = os.environ.get("GC2_TRANSFERS_LOG",
                              os.path.join(os.getcwd(), "transfers.log"))
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh._is_transfers_log = True
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    logger.propagate = False   # stop at package boundary (prevents double logging via root)
    logger.debug(f"transfers logger initialized at {log_path}")
    _initialized = True

def get_logger(name: str | None = None) -> logging.Logger:
    """Return the shared package logger or a child logger."""
    base = logging.getLogger(_LOGGER_NAME)
    if not _initialized:
        setup_once()
    return base if not name else logging.getLogger(f"{_LOGGER_NAME}.{name}")
