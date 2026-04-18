from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


class KeyVaultError(Exception):
    pass


class KeyNotFoundError(KeyVaultError):
    def __init__(self, service: str) -> None:
        super().__init__(f"no key stored for service {service!r}")


class KeyInvalidError(KeyVaultError):
    pass


API_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^sk-[A-Za-z0-9]{20,}$"),
    re.compile(r"^hf_[A-Za-z0-9]{30,}$"),
    re.compile(r"^ghp_[A-Za-z0-9]{36}$"),
    re.compile(r"^AIza[A-Za-z0-9_-]{35}$"),
)


@dataclass(frozen=True)
class KeyEntry:
    service: str
    masked_value: str
    fingerprint: str
    stored_at: float
    last_used_at: float | None = None
    use_count: int = 0

