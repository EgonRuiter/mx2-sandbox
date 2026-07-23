# MX2 (Mail eXchange 2.0) Local Sandbox

[![MX2 Sandbox CI](https://github.com/EgonRuiter/mx2-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/EgonRuiter/mx2-sandbox/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
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
With the daemon running (locally or on Render/Docker), open a terminal to administer and test the gateway.

#### Configure API Target (Optional)
By default, `mx2ctl` targets `http://127.0.0.1:8000`. To point to a remote daemon (like Render):
```bash
# Windows PowerShell
$env:MX2_URL="https://mx2-sandbox.onrender.com"

# Linux / macOS
export MX2_URL="https://mx2-sandbox.onrender.com"
```

#### Run Basic Administration Commands
```bash
# Query gateway daemon status and negotiated SemVer capabilities
python mx2ctl.py status

# Cryptographically resolve a DID key
python mx2ctl.py resolve did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327
```

#### 🧪 Testing Trust Grade Routing (Inbox vs. Junk vs. Quarantine)
MX2 implements a 5-tiered Automated Trust Grading system (A-E) inside `src/anti_spam.py`. You can test these paths using special flags on the `test` command:

##### 🟢 Grade A (Inbox) — Reputable Domains
Emails from established domains (like `github.com` or `google.com`) are routed directly to the recipient's **Inbox**:
```bash
python mx2ctl.py test --sender notifications@github.com --subject "GitHub Alert"
# Result: Status = INBOX, Trust Grade = A
```

##### 🟡 Grade D (Junk) — Unknown Senders
Emails from unknown, un-vouched senders with valid cryptographic signatures go directly to **Junk**:
```bash
python mx2ctl.py test --sender newsletter@marketing.com --subject "Weekly Offer"
# Result: Status = JUNK, Trust Grade = D
```

##### 🔴 Grade E (Quarantine) — Spoofed Identities
Emails that fail cryptographic signature verification (such as domain spoofing attempts) are diverted to the **Quarantine Queue** on the gateway:
```bash
python mx2ctl.py test --sender billing@github.com --subject "Account Suspended" --spoof
# Result: Status = QUARANTINE, Trust Grade = E
```

#### 📥 Resolving Quarantined Messages
When a message goes to quarantine, it is held in the gateway inbox holding queue. You can list, approve, or discard it:
```bash
# 1. List all currently quarantined messages
python mx2ctl.py queue list

# 2. Approve a quarantined message (whitelists the sender and releases the mail to Inbox)
python mx2ctl.py queue approve <message_id>

# 3. Discard a quarantined message (deletes the mail from the holding queue)
python mx2ctl.py queue reject <message_id>
```

---

## 🧪 Running Unit Tests

Unit tests verify E2EE translation envelopes, spam grade routing, rate limiting, and CAS deduplication:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📜 Contributing & Developer Onboarding

Contributions are welcome! We want to make it as easy as possible for developers to get started:

### ⚡ 1-Step Local Developer Setup
We provide automated scripts to set up a virtual environment, install dev dependencies (Ruff, Pre-commit), register git hooks, and run all validation tests:

* **Windows (PowerShell)**:
  ```powershell
  ./setup.ps1
  ```
* **macOS / Linux (Bash)**:
  ```bash
  chmod +x setup.sh
  ./setup.sh
  ```

### 🏷️ Good First Issues
Check out our open issues labeled **[good first issue](https://github.com/EgonRuiter/mx2-sandbox/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)** on GitHub to start contributing!

### 🗺️ Future Development Roadmap
If you want to contribute but don't know where to start, here are some high-priority roadmap goals we are looking to build:
1. **Dynamic CPU Hash Challenges**: Implement actual cryptographic Proof-of-Work verification for Grade D senders (using hashcash-style algorithms).
2. **True HTTP/3 (QUIC) Transport**: Integrate a Python QUIC library (e.g. `aioquic`) to replace the basic HTTP/1.1 handler and match the MX2 specifications.
3. **Automated BIND9 Zone Exports**: Write a utility to export resolved DID public keys directly into BIND9 or CoreDNS compatible zone records.

Please review our **[CONTRIBUTING.md](CONTRIBUTING.md)** file for guidelines on coding standards, docstrings, and formatting.

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
