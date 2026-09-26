# ⚠️ Vulnerable Lab — INTENTIONALLY INSECURE

## WARNING

This application is **INTENTIONALLY VULNERABLE** and designed for **LOCAL EDUCATIONAL SECURITY TESTING ONLY**.

- **DO NOT** deploy this to any public server
- **DO NOT** use this to attack real systems
- **DO NOT** expose this on a public network

## Purpose

This lab demonstrates OWASP Top 10 vulnerabilities for testing with OWASP ZAP (DAST).

## Vulnerabilities

| # | Vulnerability | OWASP | Endpoint |
|---|--------------|-------|----------|
| 1 | SQL Injection | A03:2021 | /search?q= |
| 2 | XSS (Reflected) | A03:2021 | /greet?name= |
| 3 | Missing Security Headers | A05:2021 | All pages |
| 4 | Weak Authentication | A07:2021 | /login |
| 5 | IDOR | A01:2021 | /note/{id} |

## Running Locally

```bash
pip install flask
python app.py
# Open http://localhost:8080
```

## DAST Testing with OWASP ZAP

```bash
# Start the vulnerable lab
python vulnerable-lab/app.py

# Run ZAP against it
zap-cli quick-scan http://localhost:8080
```

All credentials in this application are fake and for demonstration only.
