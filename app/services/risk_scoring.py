"""
Risk Scoring Engine

A simple, explainable risk scoring system.
NOT machine learning — just weighted factors that are easy to understand.

Formula:
    Risk Score = Severity × Exploitability × Exposure × Asset Criticality
    (All weights normalized to produce a 0-10 score)

Risk Levels:
    0-3  = Low
    3-6  = Medium  
    6-8  = High
    8-10 = Critical

Why this approach?
- Easy to explain in an interview
- Transparent scoring (no black box)
- Aligned with industry practices like CVSS
"""

# Severity weights — based on CVSS severity ratings
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}

# Exploitability — how easy is it to exploit?
EXPLOITABILITY_WEIGHTS = {
    "easy": 1.0,      # Public exploit available
    "moderate": 0.7,  # Requires some skill
    "difficult": 0.4, # Requires significant expertise
}

# Exposure — is the component internet-facing?
EXPOSURE_WEIGHTS = {
    "internet": 1.0,   # Directly accessible from internet
    "internal": 0.6,   # Only accessible internally
    "isolated": 0.3,   # Air-gapped or sandboxed
}

# Asset Criticality — how important is the affected system?
ASSET_CRITICALITY_WEIGHTS = {
    "critical": 1.0,   # Core business system
    "important": 0.7,  # Important but not critical
    "normal": 0.4,     # Standard component
}


def calculate_risk_score(
    severity: str,
    exploitability: str = "moderate",
    exposure: str = "internal",
    asset_criticality: str = "normal"
) -> float:
    """Calculate risk score for a vulnerability.
    
    Args:
        severity: CRITICAL, HIGH, MEDIUM, or LOW
        exploitability: easy, moderate, or difficult
        exposure: internet, internal, or isolated
        asset_criticality: critical, important, or normal
    
    Returns:
        Risk score between 0.0 and 10.0
    """
    sev = SEVERITY_WEIGHTS.get(severity.upper(), 5.0)
    exp = EXPLOITABILITY_WEIGHTS.get(exploitability.lower(), 0.7)
    expos = EXPOSURE_WEIGHTS.get(exposure.lower(), 0.6)
    asset = ASSET_CRITICALITY_WEIGHTS.get(asset_criticality.lower(), 0.4)

    # Calculate and cap at 10.0
    score = round(min(sev * exp * expos * asset, 10.0), 1)
    return score


def get_risk_level(score: float) -> str:
    """Map a numeric risk score to a risk level."""
    if score >= 8.0:
        return "CRITICAL"
    elif score >= 6.0:
        return "HIGH"
    elif score >= 3.0:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_security_score(vulnerabilities: list) -> float:
    """Calculate an overall security score (0-100) from vulnerability list.
    
    Higher score = more secure. Deducts points based on open vulnerabilities.
    """
    if not vulnerabilities:
        return 100.0

    score = 100.0
    for vuln in vulnerabilities:
        status = getattr(vuln, 'status', 'OPEN')
        if status in ('FIXED', 'FALSE_POSITIVE'):
            continue  # Fixed vulnerabilities don't affect score

        severity = getattr(vuln, 'severity', 'LOW')
        # Deduct points based on severity
        deductions = {
            "CRITICAL": 15,
            "HIGH": 8,
            "MEDIUM": 3,
            "LOW": 1,
        }
        score -= deductions.get(severity, 1)

    return max(0.0, round(score, 1))
