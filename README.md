# MX2 (Mail eXchange 2.0) Reference Daemon & Sandbox

[![MX2 Sandbox CI](https://github.com/EgonRuiter/mx2-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/EgonRuiter/mx2-sandbox/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Welcome to **MX2 (Mail eXchange 2.0)** — the reference implementation for the next-generation federated messaging protocol designed to replace legacy SMTP, IMAP, and POP3.

MX2 replaces plain-text socket states with **structured JSON envelopes**, mandatory **End-to-End Encryption (X25519 / AES-256-GCM)**, **Decentralized Identifiers (W3C DIDs)**, **DNSSEC public key discovery**, **CPU Proof-of-Work spam guarantees**, and **cryptographic non-repudiation delivery receipts**.

---

## ✨ Key Feature Overview

| Feature | Description | Status |
| :--- | :--- | :---: |
| 🔒 **Real Cryptography** | X25519 Diffie-Hellman, HKDF-SHA256, AES-256-GCM envelope encryption & Ed25519 signatures | ✅ Production Ready |
| 🔑 **Decentralized Identifiers** | Native W3C DID support (`did:mx2`, `did:key`, `did:web`) with in-memory TTL LRU caching | ✅ Production Ready |
| 🌐 **DNSSEC & SRV Resolution** | DNS TXT public key discovery (`_mx2key`) & SRV gateway routing (`_mx2._tcp`) | ✅ Production Ready |
| 🗄️ **SQLite Persistent Storage** | Thread-safe atomic persistence for holding queues, whitelists, social graphs & CAS metadata | ✅ Production Ready |
| ⚡ **Proof-of-Work Anti-Spam** | CPU Hashcash challenge verification for Grade D senders to guarantee zero-cost spam protection | ✅ Production Ready |
| 🖥️ **Web Admin Dashboard** | Single-page dark-mode Web UI served at `http://localhost:8000/admin` | ✅ Production Ready |
| 🔄 **SMTP / IMAP Proxy** | Drop-in loopback proxy (`10025` SMTP / `10143` IMAP) for standard email clients (Thunderbird, Outlook) | ✅ Production Ready |
| ⏱️ **Undo Send Revocation** | 30-second key-hold invalidation endpoint (`POST /api/revoke`) | ✅ Production Ready |
| 🔒 **TLS & ACME Manager** | Modern TLS 1.3/1.2 SSLContext wrapper & Let's Encrypt `http-01` challenge hooks | ✅ Production Ready |

---

## 📂 Repository Architecture Map

```
mx2-sandbox/
├── .github/             # CI/CD GitHub Actions multi-version Python workflows
├── schema/              # JSON Schema definitions for MX2 envelopes
│   └── message.json     # MX2 message payload validation schema
├── dns/                 # DNS Zone specifications (BIND9 format)
│   └── zone.dns
├── docs/                # Protocol specifications (IETF draft format)
│   └── draft-ruiter-mx2-protocol-specification.txt
├── config/              # Production configuration files
│   └── mx2.conf         # INI configuration parameters (daemon, production, resolvers, tls)
├── src/                 # Core MX2 protocol engines
│   ├── gateway.py       # Bilingual SMTP-to-MX2 E2EE translation gateway
│   ├── anti_spam.py     # 5-Tiered Trust Grading (A-E) & Proof-of-Work engine
│   ├── storage.py       # SQLite persistent storage manager (tables & transactions)
│   ├── dns_resolver.py   # DNSSEC TXT public key & SRV endpoint resolver
│   ├── did_resolver.py   # W3C DID Document resolver with TTL caching
│   ├── tls_manager.py    # SSL/TLS 1.3 Context & ACME certificate manager
│   ├── metrics.py        # Prometheus telemetry metrics engine
│   ├── legacy_proxy.py   # Asynchronous SMTP (10025) & IMAP (10143) loopback proxies
│   ├── web_ui.py         # Embedded single-page HTML5/CSS3 Web Admin Console
│   ├── web_server.py    # Main REST API daemon & HTTP handler
│   ├── cas.py           # Content-Addressable Storage (CAS) engine
│   └── logger.py        # Structured JSON logging utility
├── tests/               # Unit testing suite (41+ tests)
│   ├── test_gateway.py
│   ├── test_anti_spam.py
│   ├── test_storage.py
│   ├── test_resolvers.py
│   ├── test_tls_metrics.py
│   ├── test_legacy_proxy.py
│   └── test_web_server.py
├── mx2ctl.py            # CLI administration & telemetry utility
├── run_sandbox.py       # Interactive end-to-end sandbox simulator
├── qol_migration_roadmap.md # Quality-of-Life features & legacy migration strategy
├── setup.ps1 / setup.sh # 1-Click developer onboarding scripts
├── LICENSE              # MIT License
└── CONTRIBUTING.md      # Guidelines for code style, docstrings & PRs
```

---

## 🚀 Quickstart Guide

MX2 runs with **zero mandatory external runtime dependencies** beyond standard Python `cryptography`.

### 1. Run the Interactive Sandbox Demo
Experience version negotiations, DID key lookups, E2EE envelope wrapping, HPKE decryptions, delivery receipts, and Proof-of-Work challenges:
```bash
python run_sandbox.py
```

### 2. Start the Daemon & Open Web Admin Console
Launch the daemon:
```bash
python src/web_server.py
```
Open your browser and navigate to **`http://localhost:8000/admin`** to launch the **Dark-Mode Web Admin Dashboard**:
- Monitor live API calls, PoWs, and quarantine metrics.
- Approve or discard Grade E quarantined emails with 1 click.
- Test E2EE envelope translations interactively in your browser!

### 3. Connect Legacy Email Clients (Thunderbird / Outlook)
Run the local loopback SMTP and IMAP proxies:
```bash
python mx2ctl.py proxy
```
- **SMTP Proxy**: Point your email client's outgoing server to `127.0.0.1:10025` (No SSL, Plain Auth).
- **IMAP Proxy**: Point your incoming server to `127.0.0.1:10143`.
- Raw emails sent through port `10025` are automatically translated to encrypted MX2 envelopes!

### 4. CLI Administration (`mx2ctl`)

```bash
# Query daemon health and capabilities
python mx2ctl.py status

# View live Prometheus telemetry counters in terminal
python mx2ctl.py stats

# Cryptographically resolve a DID key or domain public key
python mx2ctl.py resolve did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327

# Test trust grade routing with mock sender
python mx2ctl.py test --sender notifications@github.com --subject "Security Alert"

# Test spoofing detection (Grade E quarantine)
python mx2ctl.py test --sender billing@github.com --subject "Update Payment" --spoof

# List and approve quarantined emails
python mx2ctl.py queue list
python mx2ctl.py queue approve <message_id>

# Solve and verify a CPU Proof-of-Work challenge
python mx2ctl.py pow --bits 10 --solve
```

---

## 🧪 Running Unit Tests

Run the complete 41-test suite locally:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

To run linter and formatter checks:
```bash
python -m ruff check .
python -m ruff format --check .
```

---

## 🤝 Contributor Onboarding Guide

We welcome all contributors! Whether you want to fix a bug, improve documentation, or build a new feature, getting started is fast and simple:

### ⚡ 1-Step Developer Environment Setup
Automated setup scripts create a Python virtual environment, install dev tools (`ruff`), and register pre-commit hooks:

- **Windows (PowerShell)**:
  ```powershell
  ./setup.ps1
  ```
- **macOS / Linux (Bash)**:
  ```bash
  chmod +x setup.sh
  ./setup.sh
  ```

### 🏷️ How to Pick Up a Task
1. Check out our open issues labeled **[good first issue](https://github.com/EgonRuiter/mx2-sandbox/issues)** on GitHub.
2. Review **[qol_migration_roadmap.md](qol_migration_roadmap.md)** for planned QoL migration features.
3. Review **[CONTRIBUTING.md](CONTRIBUTING.md)** for our coding standards (Google-style docstrings, Ruff linter compliance).

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
