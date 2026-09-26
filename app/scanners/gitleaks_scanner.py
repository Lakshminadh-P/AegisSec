"""
Gitleaks Scanner — Secret Detection

Gitleaks scans git repositories for hardcoded secrets such as:
- API keys
- AWS credentials
- Private keys
- Database passwords

Hardcoded secrets are one of the most common security mistakes.
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    display_name = "Gitleaks"
    scan_type = "SECRET"
    tool_command = "gitleaks"
    description = "Scans git repositories for hardcoded secrets and credentials"
    
    def scan(self, target: str) -> List[dict]:
        """Run Gitleaks scan on target directory."""
        command = [
            "gitleaks", "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-git",
        ]
        output = self.run_command(command)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse Gitleaks JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            if not isinstance(data, list):
                data = [data]
            
            for leak in data:
                findings.append({
                    "title": f"Hardcoded Secret: {leak.get('RuleID', 'unknown-secret')}",
                    "severity": "CRITICAL",  # Secrets are always critical
                    "source": "Gitleaks",
                    "component": f"{leak.get('File', 'unknown')}:{leak.get('StartLine', 0)}",
                    "description": f"Secret detected matching rule: {leak.get('Description', leak.get('RuleID', ''))}",
                    "cve": None,
                    "status": "OPEN",
                    "risk_score": calculate_risk_score("CRITICAL", "easy", "internet"),
                })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
