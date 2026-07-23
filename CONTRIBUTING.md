# Contributing to MX2

Thank you for your interest in contributing to MX2 (Mail eXchange 2.0)! This document outlines the standards and procedures for contributing to keep the project clean, refactored, and thoroughly documented.

## Code Quality Standards

We hold the MX2 codebase to a high standard. To keep the project maintainable, please follow these principles:

1. **PEP 8 Compliance**: All Python code must conform to the PEP 8 style guide.
2. **Strict Docstrings**: Every module, class, method, and function must have a Google-style docstring explaining its behavior, arguments, return values, and raised exceptions.
3. **No External Dependencies in Core**: The core libraries (`anti_spam.py`, `gateway.py`, `cas.py`) must remain dependency-free, utilizing Python's robust standard libraries to ease integration and keep the code lightweight.
4. **Refactoring First**: Before adding features, refactor existing code if it improves readability or structure. Avoid duplicate logic.

## Documentation Guidelines

- Always update the official IETF-style draft at `docs/draft-ruiter-mx2-protocol-specification.txt` when modifying protocol mechanics.
- If payload definitions change, ensure the schema at `schema/message.json` is updated and remains valid.

## Testing Guidelines

- Every new feature or bug fix **must** be accompanied by comprehensive unit tests.
- Place tests in the `tests/` folder with filenames starting with `test_`.
- Run tests locally using:
  ```bash
  python -m unittest discover -s tests -p "test_*.py"
  ```
- Code coverage should target 90%+ for core components.

## Development Sandbox Workflow

1. Fork the repository and clone it locally.
2. Run unit tests to verify the baseline: `python -m unittest discover -s tests -p "test_*.py"`.
3. Launch the headless daemon locally: `python src/web_server.py`.
4. Administer the daemon and check status using the CLI utility: `python mx2ctl.py status`.
5. Implement your changes, refactor as necessary, and ensure all tests pass.
6. Create a descriptive Pull Request outlining the changes and verification steps.
