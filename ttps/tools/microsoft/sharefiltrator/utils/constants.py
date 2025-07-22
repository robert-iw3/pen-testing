from typing import Final

# Search constants
DEFAULT_ROW_LIMIT: Final = 500
DEFAULT_QUERY: Final = (
    "contentclass:STS_Site OR contentclass:STS_Web OR contentclass:STS_ListItem_MySiteDocumentLibrary"
)
DEFAULT_MAX_THREADS: Final = 10
DEFAULT_MAX_SIZE_MB: Final = 20

# File paths
DOWNLOADS_DIR: Final = "downloads"
OUTPUT_DIR: Final = "output"

# HTTP Headers
DEFAULT_HEADERS: Final = {"Accept": "application/json;odata=verbose;charset=utf-8"}

# URL Processing
MAX_FILENAME_LENGTH: Final = 80
SPECIAL_CHARS: Final = set('!@#$%^&*()={}[];:"|/,')
