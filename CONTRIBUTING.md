# Contributing to MX2 (Mail eXchange 2.0)

Thank you for your interest in contributing to **MX2**! We want to make contributing to this next-generation protocol simple, rewarding, and accessible to developers of all skill levels.

---

## 🌟 Code of Conduct & Core Philosophy

1. **Protocol Simplicity First**: MX2's core protocol engine must remain lightweight, 0-dependency, clean, and straightforward to implement.
2. **Zero Mandatory External Core Dependencies**: Core logic (`gateway.py`, `anti_spam.py`, `storage.py`, `did_resolver.py`) relies exclusively on Python standard libraries plus the `cryptography` package.
3. **High Code Quality**: All contributions must pass linters (`ruff`), include Google-style docstrings, and maintain 100% test suite pass rates.

---

## 🛠️ Step-by-Step Development Workflow

### 1. Fork & Clone
```bash
git clone https://github.com/YOUR-USERNAME/mx2-sandbox.git
cd mx2-sandbox
```

### 2. Run Automated Developer Setup
Set up virtual environment, install dev dependencies (`ruff`), and verify test baseline:

- **Windows (PowerShell)**:
  ```powershell
  ./setup.ps1
  ```
- **macOS / Linux (Bash)**:
  ```bash
  chmod +x setup.sh
  ./setup.sh
  ```

### 3. Run the Unit Test Suite
Ensure all 41+ unit tests pass locally before making changes:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

### 4. Code Formatting & Linting
We use **Ruff** for high-speed Python linting and formatting:
```bash
# Check for linting errors
python -m ruff check .

# Automatically fix lint errors
python -m ruff check --fix .

# Auto-format all Python code
python -m ruff format .
```

---

## 📝 Documenting Your Work

- Every module, class, and method must have a **Google-style docstring**:
  ```python
  def verify_proof_of_work(challenge: str, nonce: str, difficulty_bits: int = 10) -> bool:
      """Verifies a Hashcash CPU Proof-of-Work solution nonce against a challenge string.

      Args:
          challenge (str): The challenge payload.
          nonce (str): The calculated nonce solution.
          difficulty_bits (int): Required zero-bit prefix count.

      Returns:
          bool: True if valid, False otherwise.
      """
  ```
- If you add or modify a REST API route in `src/web_server.py`, add a corresponding unit test in `tests/test_web_server.py`.

---

## 🚀 Submitting a Pull Request (PR)

1. Create a feature branch: `git checkout -b feat/my-new-feature`.
2. Commit your changes with a conventional commit message (e.g. `feat(storage): add PostgreSQL backend support`).
3. Push to your fork and submit a Pull Request targeting `main`.
4. GitHub Actions CI will automatically run unit tests and Ruff linter checks across Python 3.9, 3.10, 3.11, and 3.12.

Thank you for helping build the future of open, secure, decentralized email! 🚀
