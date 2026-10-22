from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> bytes:
    """One byte string per value: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()
