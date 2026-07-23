# MX2 (Mail eXchange 2.0) Local Sandbox

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Welcome to the **MX2** (Mail eXchange 2.0) local development sandbox. This repository contains the reference implementation package for the next-generation federated messaging protocol designed to replace SMTP, IMAP, and POP3. 

MX2 replaces raw line-command socket states with structured JSON-based exchanges multiplexed over **HTTP/3 (QUIC) on port 443**, utilizing DNSSEC-signed identity keys, mandatory End-to-End Encryption (HPKE), and automated cryptographic trust grading for anti-spam.

---

## 📂 Repository Structure

```
mx2-sandbox/
├── .github/             # CI/CD workflows and configs
├── schema/              # Strict JSON Payload Schemas
│   └── message.json     # MX2 message validation schema
├── dns/                 # DNS Zone specs (BIND9 formatting)
│   └── zone.dns
├── docs/                # Protocol specifications (IETF draft format)
│   └── draft-ruiter-mx2-protocol-specification.txt
├── config/              # Daemon configuration
│   └── mx2.conf         # INI configuration parameters
├── src/                 # Core Python engine code
│   ├── anti_spam.py     # Cryptographic trust & anti-spam engine
│   ├── gateway.py       # SMTP-to-MX2 bilingual translation gateway
│   ├── cas.py           # Content-Addressable Storage (CAS) engine
│   ├── logger.py        # Structured JSON logging utility
│   └── web_server.py    # Headless REST API daemon
├── tests/               # Unit testing suite
├── mx2ctl.py            # Unix-style CLI administration utility
├── run_sandbox.py       # End-to-end integration CLI simulator
├── LICENSE              # MIT License
└── CONTRIBUTING.md      # Development and style guidelines
```

---

## 🚀 Quickstart Guide

The MX2 sandbox runs with **zero external dependencies** using Python's standard library.

### 1. Run the End-to-End Simulator
To simulate version negotiations, DID-based E2EE envelope wrapping, HPKE decryptions, and trust grade evaluations:
```bash
python run_sandbox.py
```

### 2. Run the Headless Gateway Daemon

**Option A: Native Python**
Start the background REST gateway daemon:
```bash
python src/web_server.py
```

**Option B: Docker Compose**
Launch the gateway daemon inside a container with mapped persistent volumes:
```bash
docker compose up -d --build
```

### 3. Use the CLI Admin Utility (`mx2ctl`)
With the daemon running, open another terminal to administer the gateway:
```bash
# Query gateway daemon status and negotiated SemVer capabilities
python mx2ctl.py status

# List quarantined Grade E spoofed messages
python mx2ctl.py queue list

# Cryptographically resolve a DID key
python mx2ctl.py resolve did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327

# Test the bilingual gateway translation with a mock email
python mx2ctl.py test --sender alice@example.com --recipient bob@example.com --subject "CLI Test" --body "Hello MX2!"
```

---

## 🧪 Running Unit Tests

Unit tests verify E2EE translation envelopes, spam grade routing, rate limiting, and CAS deduplication:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📜 Contributing & Code Quality

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) to understand our coding standards:
- Conform strictly to **PEP 8** style guidelines.
- Write **Google-style docstrings** for all code blocks.
- Keep the core libraries dependency-free.
- Ensure unit tests are provided for all modifications.

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
