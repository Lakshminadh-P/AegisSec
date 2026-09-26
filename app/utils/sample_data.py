"""
Sample Data Loader

Creates realistic demo vulnerability data so the dashboard isn't empty.
All data is clearly fake and for demonstration purposes only.

IMPORTANT: This is DEMO DATA — not real vulnerability findings.
"""
from app.database import SessionLocal
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan, SecurityEvent
from app.security.auth import hash_password
from app.services.risk_scoring import calculate_risk_score
from datetime import datetime, timezone, timedelta
import random


def load_sample_data():
    """Load sample data into the database for demonstration."""
    db = SessionLocal()
    
    try:
        # Only load if database is empty
        if db.query(User).count() > 0:
            return
        
        # --- Create demo users ---
        users = [
            User(
                username="admin",
                email="admin@aegissec.local",
                hashed_password=hash_password("admin123"),
                role="ADMIN",
            ),
            User(
                username="analyst",
                email="analyst@aegissec.local",
                hashed_password=hash_password("analyst123"),
                role="SECURITY_ANALYST",
            ),
            User(
                username="developer",
                email="dev@aegissec.local",
                hashed_password=hash_password("dev123"),
                role="DEVELOPER",
            ),
        ]
        db.add_all(users)
        db.commit()
        
        # --- Create demo scans ---
        now = datetime.now(timezone.utc)
        scans = [
            Scan(scan_type="SAST", scanner="Semgrep", target=".", status="COMPLETED",
                 started_at=now - timedelta(hours=2), completed_at=now - timedelta(hours=1, minutes=55),
                 findings_count=5, critical_count=1, high_count=2, medium_count=1, low_count=1),
            Scan(scan_type="SAST", scanner="Bandit", target=".", status="COMPLETED",
                 started_at=now - timedelta(hours=1, minutes=30), completed_at=now - timedelta(hours=1, minutes=28),
                 findings_count=4, critical_count=0, high_count=1, medium_count=2, low_count=1),
            Scan(scan_type="SECRET", scanner="Gitleaks", target=".", status="COMPLETED",
                 started_at=now - timedelta(hours=1), completed_at=now - timedelta(minutes=58),
                 findings_count=2, critical_count=2, high_count=0, medium_count=0, low_count=0),
            Scan(scan_type="SCA", scanner="Trivy", target=".", status="COMPLETED",
                 started_at=now - timedelta(minutes=45), completed_at=now - timedelta(minutes=43),
                 findings_count=3, critical_count=0, high_count=1, medium_count=1, low_count=1),
            Scan(scan_type="DAST", scanner="OWASP ZAP", target="http://localhost:8080", status="COMPLETED",
                 started_at=now - timedelta(minutes=30), completed_at=now - timedelta(minutes=20),
                 findings_count=4, critical_count=1, high_count=1, medium_count=1, low_count=1),
            Scan(scan_type="IAC", scanner="Checkov", target="terraform/", status="COMPLETED",
                 started_at=now - timedelta(minutes=15), completed_at=now - timedelta(minutes=14),
                 findings_count=3, critical_count=0, high_count=2, medium_count=1, low_count=0),
        ]
        db.add_all(scans)
        db.commit()
        
        # --- Create demo vulnerabilities ---
        # These represent realistic findings from each scanner
        vulnerabilities = [
            # Critical findings
            Vulnerability(
                title="Hardcoded AWS Access Key Detected",
                severity="CRITICAL",
                source="Gitleaks",
                component="config/settings.py:42",
                description="AWS access key found hardcoded in source code. Hardcoded credentials can be extracted by attackers who gain access to the codebase.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("CRITICAL", "easy", "internet"),
                remediation="Remove the hardcoded key and use environment variables or AWS IAM roles instead.",
                scan_id=3,
            ),
            Vulnerability(
                title="SQL Injection in User Search",
                severity="CRITICAL",
                source="Semgrep",
                component="app/routes/users.py:78",
                description="User input is directly concatenated into SQL query without parameterization. This allows attackers to execute arbitrary SQL commands.",
                cve="CWE-89",
                status="OPEN",
                risk_score=calculate_risk_score("CRITICAL", "easy", "internet"),
                remediation="Use parameterized queries or an ORM like SQLAlchemy instead of string concatenation.",
                scan_id=1,
            ),
            Vulnerability(
                title="Hardcoded Database Password",
                severity="CRITICAL",
                source="Gitleaks",
                component="docker-compose.yml:15",
                description="Database password found in docker-compose configuration file committed to version control.",
                cve=None,
                status="IN_PROGRESS",
                risk_score=calculate_risk_score("CRITICAL", "easy", "internal"),
                remediation="Use Docker secrets or environment variables from a .env file (add .env to .gitignore).",
                scan_id=3,
            ),
            Vulnerability(
                title="Cross-Site Scripting (XSS) — Reflected",
                severity="CRITICAL",
                source="OWASP ZAP",
                component="http://localhost:8080/search?q=<script>",
                description="The search parameter is reflected in the page without proper encoding, allowing script injection.",
                cve="CWE-79",
                status="OPEN",
                risk_score=calculate_risk_score("CRITICAL", "easy", "internet"),
                remediation="Encode all user input before rendering in HTML. Use Content-Security-Policy headers.",
                scan_id=5,
            ),
            
            # High findings
            Vulnerability(
                title="Vulnerable Dependency: requests 2.25.0",
                severity="HIGH",
                source="Trivy",
                component="requirements.txt - requests",
                description="The installed version of the requests library has a known vulnerability (CVE-2023-32681) allowing CRLF injection.",
                cve="CVE-2023-32681",
                status="OPEN",
                risk_score=calculate_risk_score("HIGH"),
                remediation="Upgrade requests to version 2.31.0 or later.",
                scan_id=4,
            ),
            Vulnerability(
                title="Missing Authorization Check on Admin Endpoint",
                severity="HIGH",
                source="Semgrep",
                component="app/routes/admin.py:23",
                description="The /admin/users endpoint does not verify the user's role before returning sensitive data (IDOR vulnerability).",
                cve="CWE-862",
                status="OPEN",
                risk_score=calculate_risk_score("HIGH", "easy", "internet"),
                remediation="Add role-based authorization check using the require_role() dependency.",
                scan_id=1,
            ),
            Vulnerability(
                title="Use of eval() with User Input",
                severity="HIGH",
                source="Bandit",
                component="app/utils/calculator.py:15",
                description="eval() is called with user-supplied input. This allows arbitrary code execution.",
                cve="CWE-95",
                status="OPEN",
                risk_score=calculate_risk_score("HIGH", "easy"),
                remediation="Replace eval() with ast.literal_eval() or a safe expression parser.",
                scan_id=2,
            ),
            Vulnerability(
                title="S3 Bucket Public Access Not Blocked",
                severity="HIGH",
                source="Checkov",
                component="terraform/main.tf",
                description="S3 bucket does not have public access block configured. This could expose sensitive data to the internet.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("HIGH", "easy", "internet"),
                remediation="Add aws_s3_bucket_public_access_block resource to block public access.",
                scan_id=6,
            ),
            Vulnerability(
                title="Missing HTTPS Redirect",
                severity="HIGH",
                source="OWASP ZAP",
                component="http://localhost:8080",
                description="Application does not redirect HTTP to HTTPS, allowing man-in-the-middle attacks.",
                cve="CWE-319",
                status="IN_PROGRESS",
                risk_score=calculate_risk_score("HIGH", "moderate", "internet"),
                remediation="Configure HTTPS redirect in the web server or load balancer.",
                scan_id=5,
            ),
            Vulnerability(
                title="EC2 Instance Without Encryption",
                severity="HIGH",
                source="Checkov",
                component="terraform/main.tf",
                description="EBS volumes attached to EC2 instance are not encrypted at rest.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("HIGH"),
                remediation="Enable EBS encryption by setting encrypted = true in the aws_ebs_volume resource.",
                scan_id=6,
            ),
            
            # Medium findings
            Vulnerability(
                title="Missing X-Content-Type-Options Header",
                severity="MEDIUM",
                source="OWASP ZAP",
                component="http://localhost:8080",
                description="The response does not include the X-Content-Type-Options: nosniff header, which prevents MIME type sniffing.",
                cve="CWE-16",
                status="OPEN",
                risk_score=calculate_risk_score("MEDIUM"),
                remediation="Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
                scan_id=5,
            ),
            Vulnerability(
                title="Insecure Random Number Generator",
                severity="MEDIUM",
                source="Bandit",
                component="app/utils/tokens.py:8",
                description="Using random.random() for token generation. The random module is not cryptographically secure.",
                cve="CWE-330",
                status="OPEN",
                risk_score=calculate_risk_score("MEDIUM"),
                remediation="Use secrets.token_hex() or os.urandom() for cryptographic randomness.",
                scan_id=2,
            ),
            Vulnerability(
                title="Deprecated TLS Configuration",
                severity="MEDIUM",
                source="Trivy",
                component="nginx.conf",
                description="Server supports TLS 1.0 which has known vulnerabilities.",
                cve="CVE-2011-3389",
                status="OPEN",
                risk_score=calculate_risk_score("MEDIUM", "moderate"),
                remediation="Configure minimum TLS version to 1.2 in the server configuration.",
                scan_id=4,
            ),
            Vulnerability(
                title="Incomplete Error Handling",
                severity="MEDIUM",
                source="Semgrep",
                component="app/services/payment.py:45",
                description="Generic exception handler catches all exceptions, potentially hiding security errors.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("MEDIUM"),
                remediation="Use specific exception types and log security-relevant errors.",
                scan_id=1,
            ),
            Vulnerability(
                title="Missing Logging for Security Events",
                severity="MEDIUM",
                source="Bandit",
                component="app/routes/auth.py:34",
                description="Failed authentication attempts are not logged, making it harder to detect brute-force attacks.",
                cve=None,
                status="FIXED",
                risk_score=calculate_risk_score("MEDIUM"),
                remediation="Log all failed authentication attempts with timestamp and source IP.",
                scan_id=2,
            ),
            Vulnerability(
                title="Terraform State Not Encrypted",
                severity="MEDIUM",
                source="Checkov",
                component="terraform/main.tf",
                description="Terraform state file may contain secrets and should be stored encrypted.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("MEDIUM"),
                remediation="Use S3 backend with server-side encryption for remote state storage.",
                scan_id=6,
            ),
            
            # Low findings
            Vulnerability(
                title="Server Version Disclosed in Headers",
                severity="LOW",
                source="OWASP ZAP",
                component="http://localhost:8080",
                description="The Server header reveals the web server version, aiding attacker reconnaissance.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("LOW"),
                remediation="Remove or mask the Server header in production.",
                scan_id=5,
            ),
            Vulnerability(
                title="Debug Mode Enabled",
                severity="LOW",
                source="Semgrep",
                component="app/config.py:12",
                description="Debug mode is enabled by default. This may expose detailed error messages in production.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("LOW"),
                remediation="Set DEBUG=False in production environment variables.",
                scan_id=1,
            ),
            Vulnerability(
                title="Outdated Python Package: setuptools",
                severity="LOW",
                source="Trivy",
                component="requirements.txt - setuptools",
                description="setuptools version has a low-severity vulnerability with no known exploit.",
                cve="CVE-2022-40897",
                status="FALSE_POSITIVE",
                risk_score=calculate_risk_score("LOW"),
                remediation="Update setuptools to the latest version.",
                scan_id=4,
            ),
            Vulnerability(
                title="Missing robots.txt",
                severity="LOW",
                source="OWASP ZAP",
                component="http://localhost:8080/robots.txt",
                description="No robots.txt file was found. This may allow search engines to index sensitive pages.",
                cve=None,
                status="OPEN",
                risk_score=calculate_risk_score("LOW"),
                remediation="Create a robots.txt file that restricts crawling of sensitive endpoints.",
                scan_id=5,
            ),
            Vulnerability(
                title="Unused Import in Security Module",
                severity="LOW",
                source="Bandit",
                component="app/security/crypto.py:3",
                description="Unused import of hashlib.md5. While not directly vulnerable, it suggests MD5 might be used.",
                cve=None,
                status="FIXED",
                risk_score=calculate_risk_score("LOW"),
                remediation="Remove unused imports. If MD5 is needed, only use it for non-security purposes.",
                scan_id=2,
            ),
        ]
        db.add_all(vulnerabilities)
        db.commit()
        
        # --- Create demo security events ---
        events = [
            SecurityEvent(event_type="SYSTEM_START", description="AegisSec platform started", severity="INFO"),
            SecurityEvent(event_type="USER_REGISTERED", description="Admin user created", severity="INFO", user_id=1),
            SecurityEvent(event_type="SCAN_COMPLETED", description="Semgrep SAST scan completed — 5 findings", severity="INFO"),
            SecurityEvent(event_type="SCAN_COMPLETED", description="Bandit scan completed — 4 findings", severity="INFO"),
            SecurityEvent(event_type="SCAN_COMPLETED", description="Gitleaks secret scan completed — 2 critical findings", severity="WARNING"),
            SecurityEvent(event_type="VULN_DETECTED", description="Critical: Hardcoded AWS key detected", severity="CRITICAL"),
            SecurityEvent(event_type="SCAN_COMPLETED", description="Trivy SCA scan completed — 3 findings", severity="INFO"),
            SecurityEvent(event_type="SCAN_COMPLETED", description="OWASP ZAP DAST scan completed — 4 findings", severity="WARNING"),
            SecurityEvent(event_type="VULN_DETECTED", description="Critical: SQL Injection found in user search", severity="CRITICAL"),
            SecurityEvent(event_type="SCAN_COMPLETED", description="Checkov IaC scan completed — 3 findings", severity="INFO"),
        ]
        db.add_all(events)
        db.commit()
        
        print("[AegisSec] Sample data loaded successfully.")
        print("[AegisSec] Demo credentials:")
        print("  Admin:    admin / admin123")
        print("  Analyst:  analyst / analyst123")
        print("  Developer: developer / dev123")
        
    finally:
        db.close()
