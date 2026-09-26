"""
Vulnerability Management Tests

Tests CRUD operations, filtering, and authorization for vulnerabilities.
"""


def test_create_vulnerability(client, auth_headers):
    """Test creating a new vulnerability."""
    response = client.post("/api/vulnerabilities/", json={
        "title": "SQL Injection in Login",
        "severity": "CRITICAL",
        "source": "Semgrep",
        "component": "app/auth.py:42",
        "description": "User input not sanitized",
        "status": "OPEN",
        "risk_score": 9.0,
    }, headers=auth_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "SQL Injection in Login"
    assert data["severity"] == "CRITICAL"


def test_list_vulnerabilities(client, auth_headers, sample_vulnerability):
    """Test listing vulnerabilities returns results."""
    response = client.get("/api/vulnerabilities/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1


def test_get_vulnerability_by_id(client, auth_headers, sample_vulnerability):
    """Test getting a specific vulnerability by ID."""
    vuln_id = sample_vulnerability["id"]
    response = client.get(f"/api/vulnerabilities/{vuln_id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["id"] == vuln_id


def test_update_vulnerability(client, auth_headers, sample_vulnerability):
    """Test updating a vulnerability's fields."""
    vuln_id = sample_vulnerability["id"]
    response = client.put(f"/api/vulnerabilities/{vuln_id}", json={
        "status": "IN_PROGRESS",
        "remediation": "Use parameterized queries",
    }, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "IN_PROGRESS"
    assert data["remediation"] == "Use parameterized queries"


def test_change_vulnerability_status(client, auth_headers, sample_vulnerability):
    """Test changing vulnerability status via dedicated endpoint."""
    vuln_id = sample_vulnerability["id"]
    response = client.put(
        f"/api/vulnerabilities/{vuln_id}/status?new_status=FIXED",
        headers=auth_headers,
    )
    assert response.status_code == 200


def test_filter_by_severity(client, auth_headers, sample_vulnerability):
    """Test filtering vulnerabilities by severity."""
    response = client.get(
        "/api/vulnerabilities/?severity=CRITICAL",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    for vuln in data:
        assert vuln["severity"] == "CRITICAL"


def test_developer_cannot_create_vulnerability(client, developer_headers):
    """Test that developers cannot create vulnerabilities (authorization)."""
    response = client.post("/api/vulnerabilities/", json={
        "title": "Test",
        "severity": "LOW",
        "source": "Test",
    }, headers=developer_headers)
    assert response.status_code == 403
