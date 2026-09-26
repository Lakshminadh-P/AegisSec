"""
Checkov Scanner — IaC Security

Checkov scans Infrastructure-as-Code files for misconfigurations:
- Terraform files (.tf)
- Kubernetes manifests
- Dockerfiles
- CloudFormation templates

Why IaC security matters:
- Misconfigured cloud resources are a leading cause of data breaches
- Scanning IaC before deployment prevents insecure infrastructure
- "Shift left" — find issues before they reach production
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class CheckovScanner(BaseScanner):
    name = "checkov"
    display_name = "Checkov"
    scan_type = "IAC"
    tool_command = "checkov"
    description = "Infrastructure-as-Code security scanner for Terraform, Kubernetes, and Docker"
    
    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    
    def scan(self, target: str) -> List[dict]:
        """Run Checkov scan on IaC files."""
        command = [
            "checkov", "-d", target,
            "--output", "json", "--quiet", "--compact"
        ]
        output = self.run_command(command)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse Checkov JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            # Checkov can return a list or a dict
            if isinstance(data, list):
                results_list = data
            else:
                results_list = [data]
            
            for result_block in results_list:
                failed = result_block.get("results", {}).get("failed_checks", [])
                for check in failed:
                    severity = self.SEVERITY_MAP.get(
                        check.get("severity", "MEDIUM"), "MEDIUM"
                    )
                    findings.append({
                        "title": f"{check.get('check_id', 'CKV_UNKNOWN')}: {check.get('check_name', 'Unknown Check')}",
                        "severity": severity,
                        "source": "Checkov",
                        "component": check.get("file_path", "unknown"),
                        "description": f"IaC misconfiguration: {check.get('check_name', '')} in {check.get('resource', 'unknown resource')}",
                        "cve": None,
                        "status": "OPEN",
                        "risk_score": calculate_risk_score(severity),
                    })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
