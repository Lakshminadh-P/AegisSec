"""
Scanner Framework Tests

Tests scanner availability detection and output parsing.
"""
from app.scanners.base_scanner import BaseScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.bandit_scanner import BanditScanner
from app.scanners import get_available_scanners


def test_scanner_registry():
    """Test that all scanners are registered."""
    scanners = get_available_scanners()
    names = [s["name"] for s in scanners]
    assert "semgrep" in names
    assert "bandit" in names
    assert "trivy" in names
    assert "gitleaks" in names
    assert "zap" in names
    assert "checkov" in names


def test_scanner_has_required_fields():
    """Test each scanner provides required metadata."""
    scanners = get_available_scanners()
    for scanner in scanners:
        assert "name" in scanner
        assert "display_name" in scanner
        assert "scan_type" in scanner
        assert "available" in scanner
        assert isinstance(scanner["available"], bool)


def test_semgrep_parse_output():
    """Test Semgrep output parsing with sample data."""
    scanner = SemgrepScanner()
    sample_output = '''{"results": [{"check_id": "python.lang.security.audit.eval", "path": "app/utils.py", "extra": {"severity": "WARNING", "message": "Use of eval() detected"}}]}'''
    findings = scanner.parse_output(sample_output)
    assert len(findings) == 1
    assert findings[0]["source"] == "Semgrep"
    assert findings[0]["severity"] == "MEDIUM"


def test_bandit_parse_output():
    """Test Bandit output parsing with sample data."""
    scanner = BanditScanner()
    sample_output = '''{"results": [{"issue_text": "Use of eval", "issue_severity": "HIGH", "issue_confidence": "HIGH", "filename": "app/test.py", "line_number": 10, "test_id": "B307"}]}'''
    findings = scanner.parse_output(sample_output)
    assert len(findings) == 1
    assert findings[0]["source"] == "Bandit"
    assert findings[0]["severity"] == "HIGH"


def test_parse_empty_output():
    """Test parsers handle empty output gracefully."""
    scanner = SemgrepScanner()
    assert scanner.parse_output("") == []
    assert scanner.parse_output("{}") == []
    assert scanner.parse_output("invalid json") == []
