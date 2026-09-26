"""
Semgrep Scanner — SAST (Static Application Security Testing)

Semgrep scans source code for security patterns without executing the code.
It uses pattern-matching rules to find vulnerabilities like:
- SQL injection
- XSS
- Insecure deserialization
- Hardcoded secrets
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    display_name = "Semgrep"
    scan_type = "SAST"
    tool_command = "semgrep"
    description = "Static Application Security Testing — scans source code for security vulnerabilities"
    
    # Map Semgrep severity to our severity levels
    SEVERITY_MAP = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    
    def scan(self, target: str) -> List[dict]:
        """Run Semgrep scan on the target directory."""
        command = [
            "semgrep", "--config", "auto",
            "--json", "--quiet",
            target
        ]
        output = self.run_command(command)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse Semgrep JSON output into normalized format."""
        findings = []
        try:
            data = json.loads(raw_output)
            for result in data.get("results", []):
                severity = self.SEVERITY_MAP.get(
                    result.get("extra", {}).get("severity", "INFO"), "LOW"
                )
                findings.append({
                    "title": result.get("check_id", "Unknown Semgrep Finding"),
                    "severity": severity,
                    "source": "Semgrep",
                    "component": result.get("path", "unknown"),
                    "description": result.get("extra", {}).get("message", ""),
                    "cve": None,
                    "status": "OPEN",
                    "risk_score": calculate_risk_score(severity),
                })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
