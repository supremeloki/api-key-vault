# key-vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Local API key management: masked storage, SHA-256 fingerprints, usage tracking, environment-variable fallback, pattern-based key detection, and audit reports — never paste a key into code again.

## 🚀 Overview

API keys end up hardcoded, committed, and leaked. `key-vault` keeps them in one JSON store (chmod 600) where only **masked values and fingerprints** are persisted metadata — the secret itself lives in memory or env vars with `VAULT_KEY_<SERVICE>` fallback. Every retrieval is usage-tracked; `verify_fingerprint` confirms a candidate matches without exposing the stored value; `scan_environment` finds unrecognized API keys sitting in your env by pattern (`sk-…`, `hf_…`, `ghp_…`, `AIza…`).

## ✨ Features

- **Masked persistence:** files contain `sk-a1****wxyz`, never raw keys
- **Fingerprints:** 16-hex SHA-256 prefix for verification without exposure
- **Usage tracking:** `use_count` + `last_used_at` updated on every `get()`
- **Env fallback:** missing from memory → resolved from `VAULT_KEY_<SERVICE>` automatically
- **Pattern detection:** recognizes OpenAI/HuggingFace/GitHub/Google key shapes
- **Environment scanner:** lists services with unregistered API keys
- **Durable across instances:** reopen the same path and metadata survives
- **Audit report:** per-service masked value, fingerprint, usage stats
- **Zero dependencies**

## 🚧 Structure

```
api-key-vault/
├── src/key_vault/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/api-key-vault.git
cd api-key-vault
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from pathlib import Path
from key_vault import KeyVault

vault = KeyVault(store_path=Path.home() / ".llm-keys.json")
vault.set("openai", "sk-your-real-key-here")

client_key = vault.get("openai")
print(vault.audit_report())

for service in vault.scan_environment():
    print(f"unregistered key found for: {service}")
```

## 🔧 Error Handling

```text
KeyVaultError
├── KeyNotFoundError     # service never registered (memory + env both miss)
└── KeyInvalidError      # empty service name or key value
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen entries
- Zero comments — names carry the meaning
- Masking verified to hide the middle; fingerprints deterministic; env fallback covered

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi** - [kooroushmasoumi@gmail.com](mailto:kooroushmasoumi@gmail.com)

---

⭐ Star this repo if you find it useful!
