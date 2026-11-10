"""Canonical JSON used for approval bindings and audit records.

Key order, spacing, and non-ASCII escaping are fixed so two processes hash
the same object to the same bytes.
"""

import json


def canonical_json(data: dict) -> bytes:
    if type(data) is not dict:
        raise TypeError("canonical JSON requires a dict")
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
