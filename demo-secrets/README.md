# 🔑 Demo Secrets — For Secret Scanning Demonstration

## ⚠️ DISCLAIMER

**All credentials in this directory are INTENTIONALLY FAKE.**

They exist to demonstrate how Gitleaks and other secret scanning tools detect hardcoded credentials.

## How to Test

```bash
# Run Gitleaks against this directory
gitleaks detect --source . --no-git -v

# Expected: Gitleaks will report findings for the fake credentials
```

## Why Secret Scanning Matters

Hardcoded secrets in source code are one of the most common security vulnerabilities:
- If code is pushed to a public repository, secrets are exposed
- Attackers scan GitHub for accidentally committed credentials
- Once a secret is in git history, it's very hard to remove completely

## Best Practices

1. Use environment variables for secrets
2. Use `.env` files (and add `.env` to `.gitignore`)
3. Use secret management tools (AWS Secrets Manager, HashiCorp Vault)
4. Run secret scanning in CI/CD pipelines
5. Use pre-commit hooks to prevent secret commits
