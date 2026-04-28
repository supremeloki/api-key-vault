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

    @property
    def is_fingerprinted(self) -> bool:
        return len(self.fingerprint) == 16


def mask_key(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 12}{value[-4:]}"


def fingerprint_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def looks_like_api_key(value: str) -> bool:
    if not value or " " in value:
        return False
    return any(pattern.match(value) for pattern in API_KEY_PATTERNS)


@dataclass
class VaultFile:
    version: int = 1
    entries: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "VaultFile":
        if not path.exists():
            return cls()
        payload = json.loads(path.read_text(encoding="utf-8"))
        vault = cls(version=payload.get("version", 1))
        vault.entries = {
