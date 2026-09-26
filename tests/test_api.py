"""
API Endpoint Tests

Tests dashboard, scans, reports, and events endpoints.
"""


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_dashboard_stats(client, auth_headers):
    """Test dashboard statistics endpoint."""
    response = client.get("/api/dashboard/stats", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_vulnerabilities" in data
    assert "security_score" in data
    assert "critical_count" in data


def test_list_scans(client, auth_headers):
    """Test listing security scans."""
    response = client.get("/api/scans/", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_available_tools(client):
    """Test listing available scanning tools (no auth required for tool list)."""
    response = client.get("/api/scans/tools")
    assert response.status_code == 200
    tools = response.json()
    assert len(tools) >= 6


def test_get_json_report(client, auth_headers):
    """Test JSON report generation."""
    response = client.get("/api/reports/json", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "report_title" in data
    assert "security_score" in data
    assert "severity_breakdown" in data


def test_get_html_report(client, auth_headers):
    """Test HTML report generation."""
    response = client.get("/api/reports/html", headers=auth_headers)
    assert response.status_code == 200
    assert "AegisSec" in response.text


def test_security_events(client, auth_headers):
    """Test security events endpoint."""
    response = client.get("/api/events/", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
