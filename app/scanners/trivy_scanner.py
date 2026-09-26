"""
Trivy Scanner — SCA / Container Scanning

Trivy scans for:
- Vulnerabilities in OS packages and application dependencies (SCA)
- Misconfigurations in Dockerfiles and Kubernetes manifests
- Known CVEs in container images
"""
import json
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.services.risk_scoring import calculate_risk_score


class TrivyScanner(BaseScanner):
    name = "trivy"
    display_name = "Trivy"
    scan_type = "SCA"
    tool_command = "trivy"
    description = "Vulnerability scanner for containers, filesystems, and dependencies"
    
    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }
    
    def scan(self, target: str) -> List[dict]:
        """Run Trivy filesystem scan."""
        command = [
            "trivy", "fs", target,
            "--format", "json", "--quiet"
        ]
        output = self.run_command(command)
        if output is None:
            return []
        return self.parse_output(output)
    
    def parse_output(self, raw_output: str) -> List[dict]:
        """Parse Trivy JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            for result in data.get("Results", []):
                target_name = result.get("Target", "unknown")
                for vuln in result.get("Vulnerabilities", []):
                    severity = self.SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "LOW")
                    cve_id = vuln.get("VulnerabilityID", None)
                    
                    findings.append({
                        "title": f"{cve_id}: {vuln.get('Title', 'Unknown vulnerability')}",
                        "severity": severity,
                        "source": "Trivy",
                        "component": f"{target_name} - {vuln.get('PkgName', 'unknown')}",
                        "description": vuln.get("Description", ""),
                        "cve": cve_id,
                        "status": "OPEN",
                        "risk_score": calculate_risk_score(severity),
                    })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
