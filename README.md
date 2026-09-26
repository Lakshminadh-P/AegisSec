# 🛡️ AegisSec — Automated DevSecOps Security & Vulnerability Management Platform

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Manifests-326CE5?logo=kubernetes)
![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?logo=terraform)
![License](https://img.shields.io/badge/License-MIT-green)

> **An educational DevSecOps portfolio project demonstrating security automation, vulnerability management, and CI/CD security integration.**

---

## 📋 Overview

AegisSec is a web-based security automation platform that integrates multiple security scanning tools into a unified vulnerability management system. It demonstrates how DevSecOps practices — embedding security into every stage of the development lifecycle — can be implemented in a real-world application.

**This is a student portfolio project** built to demonstrate practical understanding of cybersecurity, DevSecOps, and modern development practices.

## 🎯 Problem Statement

Modern software development involves many security challenges. Typically, security tools are fragmented, generating their own specific outputs and requiring developers to manage vulnerabilities across disparate systems. Often, security testing is pushed to the late stages of development, making vulnerabilities expensive and difficult to remediate. There is a strong need for centralized vulnerability management and automated security checks directly in the development pipeline.

## 🎯 Objectives

1. Integrate multiple security tools into one platform
2. Normalize findings into a unified format
3. Automate vulnerability detection through CI/CD
4. Provide risk-based prioritization
5. Demonstrate DevSecOps best practices

## ✨ Features

### Security Scanning
- **SAST** — Semgrep & Bandit (static code analysis)
- **SCA** — Trivy (dependency vulnerability scanning)
- **DAST** — OWASP ZAP (dynamic application testing)
- **Secret Scanning** — Gitleaks (hardcoded credential detection)
- **Container Scanning** — Trivy (Docker image vulnerabilities)
- **IaC Security** — Checkov (Terraform/K8s misconfigurations)

### Vulnerability Management
- Unified vulnerability dashboard
- Severity classification (Critical/High/Medium/Low)
- Status tracking (Open → In Progress → Fixed)
- Risk scoring engine
- Remediation guidance

### DevSecOps Pipeline
- GitHub Actions CI/CD with security gates
- Automated scan on every commit
- Pipeline fails on critical vulnerabilities

### Infrastructure
- Docker containerization
- Kubernetes deployment manifests
- Terraform IaC examples
- Prometheus/Grafana monitoring (optional)

## 🏗️ Architecture

```text
Developer ──(Push)──> GitHub Repository ──(Trigger)──> GitHub Actions CI/CD
                                                             │
                                                             ▼
                                                    Security Scanners
                                               (Semgrep, Bandit, Trivy, etc.)
                                                             │
                                                             ▼
                                                 Python Processing Engine
                                                (Parses & Normalizes JSON)
                                                             │
                                                             ▼
                                                       SQLite Database
                                                             │
                                                             ▼
                                                      FastAPI REST API
                                                             │
                                                             ▼
                                                 Security Dashboard (UI)
```

## 🛠️ Technology Stack

| Category | Technology |
|----------|------------|
| Backend | Python 3.11, FastAPI, SQLAlchemy |
| Frontend | HTML, CSS, JavaScript, Bootstrap 5, Chart.js |
| Database | SQLite |
| Auth | JWT, bcrypt |
| Scanning | Semgrep, Bandit, Trivy, Gitleaks, OWASP ZAP, Checkov |
| CI/CD | GitHub Actions |
| Container | Docker, Docker Compose |
| Orchestration | Kubernetes |
| IaC | Terraform |
| Monitoring | Prometheus, Grafana |

## 📁 Project Structure

```text
aegissec-devsecops/
├── .github/workflows/      # CI/CD pipelines
├── app/                    # Backend application code
│   ├── api/                # API routes
│   ├── models/             # Database models
│   ├── scanners/           # Scanner integration modules
│   └── services/           # Business logic and scoring
├── docs/                   # Documentation
├── infrastructure/         # K8s and Terraform files
├── tests/                  # Pytest test suite
├── vulnerable-lab/         # Test target app (Intentionally vulnerable)
└── requirements.txt        # Python dependencies
```

## 🚀 Installation

### Prerequisites
- Python 3.9+
- pip
- Git
- Docker (optional but recommended)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/aegissec-devsecops.git
cd aegissec-devsecops

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env

# Run the application
python -m uvicorn app.main:app --reload

# Open http://localhost:8000
```

### Demo Credentials
| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| Analyst | analyst | analyst123 |
| Developer | developer | dev123 |

## Running with Docker
```bash
docker-compose up --build
```

## Running Security Scans
You can trigger security scans manually via the dashboard or using the provided API endpoints. Ensure that the corresponding tools (like Semgrep or Bandit) are installed locally or available in the environment to perform live scans.

## GitHub Actions CI/CD
The repository includes a `.github/workflows/security-pipeline.yml` file. This action automatically runs all configured security scanners on every push and pull request, acting as a security gate that blocks deployments if critical vulnerabilities are discovered.

## Kubernetes Deployment
Deployment manifests are located in the `infrastructure/k8s/` directory. They include configurations for Deployments, Services, and RBAC to demonstrate secure deployment practices in a K8s cluster.

## Terraform Security
Checkov scans are integrated to analyze the Terraform configurations in `infrastructure/terraform/` to ensure cloud infrastructure is provisioned securely without misconfigurations like open ports or missing encryption.

## Prometheus/Grafana
Monitoring is configured to collect application metrics. You can spin up Prometheus and Grafana using the provided Docker Compose configurations to visualize the security score and application health over time.

## 📊 Sample Security Findings
| ID | Title | Severity | Source | Status |
|----|-------|----------|--------|--------|
| V-01 | SQL Injection | Critical | Semgrep | Open |
| V-02 | Hardcoded Secret | High | Gitleaks | In Progress |
| V-03 | Outdated OpenSSL | Medium | Trivy | Fixed |

## 🔟 OWASP Top 10 Coverage
| OWASP Category | AegisSec Coverage | Tool |
|----------------|-------------------|------|
| A01: Broken Access Control | API authorization checks | SAST (Semgrep) |
| A02: Cryptographic Failures | Hardcoded secrets detection | Gitleaks |
| A03: Injection | Code analysis for SQLi/XSS | Bandit/Semgrep |
| A04: Insecure Design | Threat modeling guidance | Documentation |
| A05: Security Misconfiguration | IaC scanning | Checkov |
| A06: Vulnerable Components | Dependency scanning | Trivy |

## 🚀 Future Enhancements
- SBOM generation
- Real-time notifications (Slack, MS Teams)
- Integration with JIRA/ticketing
- More scanner integrations
- Machine learning anomaly detection

## ⚠️ Limitations
- This is an educational project, not production-ready
- SQLite is used for simplicity (not suitable for production)
- The vulnerable lab is for local testing only
- Not all security tools may be available in every environment

## ⚠️ Disclaimer

This project is an **educational portfolio project** developed for learning DevSecOps and cybersecurity concepts. The intentionally vulnerable application (`vulnerable-lab/`) is designed for **local testing only** and should NEVER be deployed to a public server.

All demo credentials, fake secrets, and sample data are for demonstration purposes only.

## 📄 License

MIT License — see [LICENSE](LICENSE)
