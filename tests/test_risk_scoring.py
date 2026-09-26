"""
Risk Scoring Tests

Tests the risk scoring engine produces correct scores.
"""
from app.services.risk_scoring import (
    calculate_risk_score, get_risk_level, calculate_security_score
)


def test_critical_severity_high_score():
    """Critical severity with easy exploitability should score high."""
    score = calculate_risk_score("CRITICAL", "easy", "internet", "critical")
    assert score >= 8.0
    assert score <= 10.0


def test_low_severity_low_score():
    """Low severity with difficult exploitability should score low."""
    score = calculate_risk_score("LOW", "difficult", "isolated", "normal")
    assert score < 3.0


def test_risk_level_mapping():
    """Test risk score to risk level mapping."""
    assert get_risk_level(9.0) == "CRITICAL"
    assert get_risk_level(7.0) == "HIGH"
    assert get_risk_level(4.0) == "MEDIUM"
    assert get_risk_level(1.0) == "LOW"


def test_security_score_no_vulns():
    """No vulnerabilities should give a perfect score."""
    score = calculate_security_score([])
    assert score == 100.0


def test_security_score_decreases_with_vulns():
    """Security score should decrease with open vulnerabilities."""
    class MockVuln:
        def __init__(self, severity, status="OPEN"):
            self.severity = severity
            self.status = status
    
    vulns = [
        MockVuln("CRITICAL"),
        MockVuln("HIGH"),
        MockVuln("MEDIUM"),
    ]
    score = calculate_security_score(vulns)
    assert score < 100.0
    assert score > 0.0


def test_fixed_vulns_dont_affect_score():
    """Fixed vulnerabilities should not reduce the security score."""
    class MockVuln:
        def __init__(self, severity, status="OPEN"):
            self.severity = severity
            self.status = status
    
    vulns = [
        MockVuln("CRITICAL", "FIXED"),
        MockVuln("HIGH", "FIXED"),
    ]
    score = calculate_security_score(vulns)
    assert score == 100.0
