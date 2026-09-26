# AegisSec - Interview Preparation Guide

This guide is designed to help you prepare for technical interviews by explaining the AegisSec project and DevSecOps concepts.

## Project Explanations

### Project explanation — 30 seconds
AegisSec is a web-based DevSecOps platform I built to demonstrate how security can be automated and integrated into the software development lifecycle. It aggregates findings from six security tools (Semgrep, Bandit, Gitleaks, Trivy, OWASP ZAP, Checkov), normalizes them into a unified format, scores them by risk, and displays everything on a security dashboard with vulnerability management capabilities.

### Project explanation — 2 minutes
AegisSec is a comprehensive DevSecOps portfolio project that I developed to address the challenge of fragmented security tooling in modern development. Traditionally, developers have to look at multiple different reports to find security issues. AegisSec solves this by integrating six different industry-standard security scanners into a single platform.

The system handles Static Application Security Testing (SAST) with Semgrep and Bandit, Software Composition Analysis (SCA) and container scanning with Trivy, secret scanning with Gitleaks, Dynamic Application Security Testing (DAST) with OWASP ZAP, and Infrastructure as Code (IaC) scanning with Checkov.

I built the backend using Python and FastAPI, storing normalized vulnerability data in a SQLite database via SQLAlchemy. The platform calculates a custom risk score based on severity, exploitability, and context to prioritize remediation efforts. I also implemented a GitHub Actions CI/CD pipeline that acts as a security gate, automatically running scans on every commit and failing the build if critical vulnerabilities are detected. The entire application is containerized with Docker and includes Kubernetes deployment manifests to demonstrate secure infrastructure practices.

### Architecture explanation
The architecture follows a typical modern DevSecOps flow:
1. **Developer Commits Code:** Developer pushes code to GitHub.
2. **GitHub Actions CI/CD:** Triggers automated workflows on commit.
3. **Security Scanners:** The pipeline runs various scanners (Semgrep, Bandit, Trivy, etc.) against the codebase.
4. **Python Processing Engine:** The AegisSec backend (FastAPI) ingests the raw JSON output from these scanners, parses them, and normalizes them into a standard format.
5. **Database Layer:** The normalized vulnerabilities, along with their calculated risk scores, are stored in a SQLite database (via SQLAlchemy).
6. **API & Web Dashboard:** The FastAPI REST API serves this data to a frontend dashboard built with HTML/CSS/JS (Bootstrap/Chart.js), where security analysts and developers can manage, filter, and remediate the vulnerabilities.

## Core DevSecOps Concepts

### Why DevSecOps?
Traditional security is done AFTER development, often just before release. This creates bottlenecks and makes fixing bugs expensive. DevSecOps integrates security INTO the development process. "Shift left" means finding vulnerabilities earlier in the software development lifecycle (SDLC) when they're cheaper and easier to fix.

### Why SAST?
Static Application Security Testing (SAST) analyzes source code or binaries without executing the application (white-box testing). It finds vulnerabilities early in development (e.g., SQL injection, XSS) before the code is even deployed.

### SAST vs DAST
- **SAST (Static):** White-box testing. Analyzes source code. Finds issues early. Prone to false positives. Cannot detect runtime issues.
- **DAST (Dynamic):** Black-box testing. Tests the running application from the outside, like an attacker. Finds runtime issues and misconfigurations. Done later in the cycle. Both are needed for comprehensive security.

### SCA explanation
Software Composition Analysis (SCA) scans third-party dependencies (open-source libraries) for known vulnerabilities (CVEs) and licensing issues. Most modern applications are built using many open-source libraries, making SCA crucial.

### What is OWASP Top 10?
The OWASP Top 10 is a globally recognized standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications, such as Broken Access Control, Cryptographic Failures, Injection, and Insecure Design.

### Why use Trivy?
Trivy is a comprehensive, versatile, and fast vulnerability scanner. It can scan container images, file systems, and Git repositories for OS packages and language-specific dependencies. It's widely adopted because it's easy to integrate into CI/CD pipelines.

### Why use Gitleaks?
Gitleaks detects hardcoded secrets like passwords, API keys, and tokens in git repositories. Hardcoded credentials are one of the most common and dangerous security mistakes, often leading to immediate compromise if leaked.

### Why use Docker?
Docker ensures consistent environments across development, testing, and production. It simplifies deployment. From a security perspective, it allows for container scanning, isolating applications, and applying least privilege principles (e.g., running as non-root).

### Why Kubernetes?
Kubernetes orchestrates containers in production. Understanding K8s security is vital for DevSecOps. Key concepts include Role-Based Access Control (RBAC), Security Contexts (restricting pod privileges), Network Policies (controlling traffic between pods), and Resource Limits (preventing DoS).

### Why Terraform?
Terraform manages Infrastructure as Code (IaC). IaC security scanning (using tools like Checkov) allows teams to detect cloud misconfigurations (like open S3 buckets or overly permissive IAM roles) before the infrastructure is even provisioned.

### What is CI/CD?
Continuous Integration and Continuous Deployment (CI/CD) automates building, testing, and deploying code. Adding automated security testing to CI/CD pipelines ensures that insecure code is caught before reaching production.

### What is a security gate?
A checkpoint in the CI/CD pipeline that evaluates security scan results against predefined policies. If critical security issues are found, the gate "fails" and blocks the deployment.

### How does vulnerability prioritization work?
Not all vulnerabilities are equal. Risk Score is often calculated as: `Severity × Exploitability × Exposure × Asset Criticality`. Higher scores require immediate attention, helping teams focus on what matters most.

### What happens when a critical vulnerability is detected?
The CI/CD pipeline fails at the security gate. The team is alerted via notifications. The vulnerability is logged in a vulnerability management system (like AegisSec), and remediation guidance is provided to developers.

## Project Specifics

### What challenges did you face?
- **Tool integration:** Different scanners output data in vastly different JSON formats. Building parsers to normalize this data reliably was complex.
- **Environment Handling:** Gracefully handling environments where certain scanners might not be installed or available.
- **Balancing Security and Usability:** Designing a risk scoring system that provides meaningful prioritization without overwhelming the user with false positives.

### What would you improve?
- Add more scanner integrations (e.g., SonarQube, DefectDojo integration).
- Implement real-time notifications (Slack/Teams integration) using Webhooks.
- Add Software Bill of Materials (SBOM) generation and tracking.
- Integrate with ticketing systems like Jira to automatically create issues for vulnerabilities.
- Transition from SQLite to PostgreSQL for production readiness.

## 30 Likely Technical Interview Questions

1. **What is DevSecOps and how does it differ from traditional security?** (Shift left, integration into SDLC vs bolt-on security).
2. **Explain the difference between SAST and DAST.** (Static/white-box vs Dynamic/black-box).
3. **What is SCA and why is it important?** (Scanning dependencies for known CVEs).
4. **Name 3 vulnerabilities from the OWASP Top 10 and how to prevent them.** (e.g., Injection -> Parameterized queries; Broken Auth -> MFA).
5. **How would you prevent SQL Injection in Python?** (Using ORMs like SQLAlchemy or parameterized queries).
6. **What is Cross-Site Scripting (XSS) and how do you mitigate it?** (Escaping/encoding output, using frameworks that auto-escape).
7. **Explain how JWT authentication works.** (Stateless tokens, signing, payload, expiration).
8. **What is the purpose of hashing passwords, and why use salt?** (Preventing plaintext storage, defending against rainbow tables/dictionary attacks).
9. **Why is hardcoding secrets dangerous and how do you prevent it?** (Use environment variables, secret managers like HashiCorp Vault; detect with Gitleaks).
10. **What is a Docker container?** (Standardized unit of software packaging code and dependencies).
11. **What are some Docker security best practices?** (Use minimal base images, run as non-root, scan for vulnerabilities, read-only filesystems).
12. **Explain Kubernetes RBAC.** (Role-Based Access Control, defining who can do what within the cluster).
13. **What is a Kubernetes Security Context?** (Defining privilege and access control settings for a Pod/Container).
14. **What is Infrastructure as Code (IaC)?** (Managing infrastructure through machine-readable definition files).
15. **Why scan IaC templates (like Terraform)?** (Catching misconfigurations like open ports before deployment).
16. **Explain what a CI/CD pipeline is.** (Automated integration, testing, and deployment).
17. **What is a security gate in a pipeline?** (Automated check that blocks deployment if security policies are violated).
18. **How do you handle false positives from security scanners?** (Tuning rules, marking as false positive in the management tool, adding exceptions).
19. **What is a CVE?** (Common Vulnerabilities and Exposures, a standardized identifier for known vulnerabilities).
20. **Explain how CVSS works.** (Common Vulnerability Scoring System, assessing severity based on exploitability and impact).
21. **How did you normalize data from different scanners in AegisSec?** (Creating custom parser classes for each tool's JSON output to map to a unified schema).
22. **What is FastAPI and why did you choose it?** (Modern, fast Python web framework, automatic OpenAPI docs, asynchronous support).
23. **Explain the purpose of SQLAlchemy in your project.** (Object Relational Mapper, abstracting database interactions and preventing SQL injection).
24. **How would you scale AegisSec for a large enterprise?** (Use PostgreSQL, implement message queues like Celery/RabbitMQ for async scanning, microservices architecture).
25. **What is Cross-Site Request Forgery (CSRF)?** (Attacker forces authenticated user to execute unwanted actions).
26. **How does HTTPS/TLS protect data in transit?** (Encryption, authentication, integrity).
27. **What is the principle of least privilege?** (Giving a user/process only the bare minimum permissions needed to perform its task).
28. **How do you securely manage API keys in a production environment?** (Using a dedicated secrets management service, injecting at runtime).
29. **What is threat modeling?** (Identifying, evaluating, and mitigating potential threats to a system during design).
30. **Walk me through what happens when you type a URL into a browser.** (DNS lookup, TCP handshake, TLS handshake, HTTP request/response, rendering).
