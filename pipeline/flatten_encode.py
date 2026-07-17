"""Small normalization helpers shared by dataset adapters."""

from __future__ import annotations

import re
from typing import Any


def normalize_path(value: Any) -> str:
    return str(value or "").replace("/", "\\").lower()


def is_suspicious_path(value: Any) -> int:
    path = normalize_path(value)
    return int(any(token in path for token in ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\")))


def file_extension(value: Any) -> str:
    match = re.search(r"\.([a-z0-9]{1,12})$", normalize_path(value))
    return match.group(1) if match else ""
