"""
OWASP ZAP Scanner — DAST (Dynamic Application Security Testing)

Unlike SAST, DAST tests a running application by sending actual requests.
OWASP ZAP is the most popular open-source DAST tool.

DAST finds vulnerabilities like:
- SQL injection (by sending malicious payloads)
- XSS (by injecting scripts)
- Missing security headers
- Insecure cookies

SAST vs DAST:
- SAST analyzes source code (white-box)
- DAST tests running applications (black-box)
- Both are needed for comprehensive security testing
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class ZapScanner(BaseScanner):
    name = "zap"
    display_name = "OWASP ZAP"
    scan_type = "DAST"
    tool_command = "zap-cli"
    description = "Dynamic Application Security Testing — tests running applications for vulnerabilities"
    
    RISK_MAP = {
        "3": "HIGH",     # High risk in ZAP
        "2": "MEDIUM",   # Medium risk
        "1": "LOW",      # Low risk
        "0": "LOW",      # Informational
    }
    
    def scan(self, target: str) -> List[dict]:
        """Run OWASP ZAP baseline scan.
        
        Note: ZAP needs a URL target, not a directory.
        For demo purposes, target should be a URL like http://localhost:8080
        """
        command = [
            "zap-cli", "quick-scan",
            "--self-contained",
            "--output-format", "json",
            target
        ]
        output = self.run_command(command, timeout=600)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse ZAP JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            alerts = data if isinstance(data, list) else data.get("alerts", [])
            
            for alert in alerts:
                risk = str(alert.get("risk", "1"))
                severity = self.RISK_MAP.get(risk, "LOW")
                
                findings.append({
                    "title": alert.get("name", alert.get("alert", "Unknown ZAP Finding")),
                    "severity": severity,
                    "source": "OWASP ZAP",
                    "component": alert.get("url", "unknown"),
                    "description": alert.get("description", ""),
                    "cve": alert.get("cweid", None),
                    "status": "OPEN",
                    "risk_score": calculate_risk_score(severity, "easy", "internet"),
                })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
