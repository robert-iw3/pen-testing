# backend/config.py
import os

SECRET_KEY = "CHANGE_ME_SUPER_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90

DB_PATH = os.path.expanduser("~/.gunnerc2/operators.db")