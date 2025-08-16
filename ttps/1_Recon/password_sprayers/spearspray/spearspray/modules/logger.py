import logging
import re
from datetime import datetime

SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")

def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kwargs)

logging.Logger.success = success

class _ColorStrippingFormatter(logging.Formatter):
    _ansi_re = re.compile(r"\x1b\[[0-9;]*[mK]")

    def format(self, record: logging.LogRecord) -> str:
        return self._ansi_re.sub("", super().format(record))

class Logger:
    def __init__(self, name: str, verbose: bool):
        self.log = logging.getLogger(name)
        self.log.setLevel(logging.DEBUG)

        self.log_file = None

        if not self.log.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

            # Console log

            console_formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(console_formatter)
            self.log.addHandler(console_handler)

            # File log (debug argument)

            if verbose:
                timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
                self.log_file = f"{name}_{timestamp}_debug.log"

                file_handler = logging.FileHandler(self.log_file)
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(_ColorStrippingFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
                self.log.addHandler(file_handler)

    def get_logger(self):
        return self.log
