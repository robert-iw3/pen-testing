import json
import argparse
import subprocess


def parse_headers(val):
    """
    Accept either:
      - "Name: Value"
      - '{"Name": "Value", ...}'
    and return a Python dict.
    """
    # try JSON first
    try:
        obj = json.loads(val)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # fallback to single Name: Value
    if ":" in val:
        name, value = val.split(":", 1)
        return { name.strip(): value.strip() }

    raise argparse.ArgumentTypeError(f"Invalid header syntax: {val!r}")