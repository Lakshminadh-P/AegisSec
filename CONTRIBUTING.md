# Contributing to AegisSec

Thank you for your interest in contributing to AegisSec! As an educational DevSecOps portfolio project, we welcome contributions that improve the code, documentation, or security features.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development Setup

1. Ensure you have Python 3.9+ installed.
2. Clone your fork and create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run tests before submitting changes:
   ```bash
   pytest
   ```

## Code Style

- Follow PEP 8 guidelines for Python code.
- Ensure all tests pass.
- Write docstrings for new functions and classes.
- Comment complex logic, especially security-related decisions.

## Pull Request Process

- Ensure your PR description clearly describes the problem and solution.
- Link relevant issues if applicable.
- All CI/CD checks (GitHub Actions) must pass before a PR can be merged.
- Do not include sensitive information or real credentials in your commits.

## Security Vulnerability Reporting

If you find a security vulnerability in this project, DO NOT open a public issue. Please refer to `SECURITY.md` for our responsible disclosure policy.
