"""
Bandit Scanner — Python Security Analysis

Bandit is a SAST tool specifically designed for Python code.
It finds common security issues like:
- Use of eval()
- Hardcoded passwords
- SQL injection in Python
- Insecure use of subprocess
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class BanditScanner(BaseScanner):
    name = "bandit"
    display_name = "Bandit"
    scan_type = "SAST"
    tool_command = "bandit"
    description = "Python-specific security linter — finds vulnerabilities in Python code"
    
    SEVERITY_MAP = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    
    CONFIDENCE_MAP = {
        "HIGH": "easy",
        "MEDIUM": "moderate",
        "LOW": "difficult",
    }
    
    def scan(self, target: str) -> List[dict]:
        """Run Bandit scan on Python files."""
        command = [
            "bandit", "-r", target,
            "-f", "json", "-q"
        ]
        output = self.run_command(command)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse Bandit JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            for result in data.get("results", []):
                severity = self.SEVERITY_MAP.get(result.get("issue_severity", "LOW"), "LOW")
                confidence = result.get("issue_confidence", "MEDIUM")
                exploitability = self.CONFIDENCE_MAP.get(confidence, "moderate")
                
                findings.append({
                    "title": result.get("issue_text", "Unknown Bandit Finding"),
                    "severity": severity,
                    "source": "Bandit",
                    "component": f"{result.get('filename', 'unknown')}:{result.get('line_number', 0)}",
                    "description": f"Test ID: {result.get('test_id', 'N/A')} - {result.get('issue_text', '')}",
                    "cve": None,
                    "status": "OPEN",
                    "risk_score": calculate_risk_score(severity, exploitability),
                })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
