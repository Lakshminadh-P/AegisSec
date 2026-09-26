"""
Security Scanner Framework

This module provides a unified interface for running different security tools.
Key design principle: The application must NOT crash if a tool is unavailable.
Each scanner checks if its tool is installed before executing.
"""
import shutil
from typing import Dict, List
from app.scanners.base_scanner import BaseScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.bandit_scanner import BanditScanner
from app.scanners.trivy_scanner import TrivyScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.zap_scanner import ZapScanner
from app.scanners.checkov_scanner import CheckovScanner

# Registry of all scanners
SCANNER_REGISTRY: Dict[str, BaseScanner] = {
    "semgrep": SemgrepScanner(),
    "bandit": BanditScanner(),
    "trivy": TrivyScanner(),
    "gitleaks": GitleaksScanner(),
    "zap": ZapScanner(),
    "checkov": CheckovScanner(),
}


def get_available_scanners() -> List[dict]:
    """List all scanners and their availability status."""
    result = []
    for name, scanner in SCANNER_REGISTRY.items():
        result.append({
            "name": name,
            "display_name": scanner.display_name,
            "scan_type": scanner.scan_type,
            "available": scanner.is_available(),
            "description": scanner.description,
        })
    return result


def run_scanner(scan_id: int, scanner_name: str, target: str = "."):
    """Run a specific scanner. Called as a background task."""
    from app.database import SessionLocal
    from app.services.scan_service import update_scan_status
    from app.services.vulnerability_service import create_vulnerability
    from app.schemas.vulnerability import VulnerabilityCreate
    
    db = SessionLocal()
    try:
        scanner = SCANNER_REGISTRY.get(scanner_name)
        if not scanner:
            update_scan_status(db, scan_id, "FAILED", error_message=f"Unknown scanner: {scanner_name}")
            return
        
        if not scanner.is_available():
            update_scan_status(
                db, scan_id, "FAILED",
                error_message=f"{scanner.display_name} is not installed. Install it to run this scan."
            )
            return
        
        # Run the scan
        update_scan_status(db, scan_id, "RUNNING")
        findings = scanner.scan(target)
        
        # Store findings as vulnerabilities
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            finding["scan_id"] = scan_id
            vuln = VulnerabilityCreate(**finding)
            create_vulnerability(db, vuln)
            sev = finding.get("severity", "LOW").upper()
            if sev in counts:
                counts[sev] += 1
        
        update_scan_status(
            db, scan_id, "COMPLETED",
            findings_count=len(findings),
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
        )
    except Exception as e:
        update_scan_status(db, scan_id, "FAILED", error_message=str(e))
    finally:
        db.close()
