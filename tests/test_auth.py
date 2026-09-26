"""
Authentication Tests

Tests user registration, login, JWT token validation, and role-based access.
"""


def test_register_user(client):
    """Test user registration creates a new account."""
    response = client.post("/api/auth/register", json={
        "username": "newuser",
        "email": "new@test.com",
        "password": "securepass123",
        "role": "DEVELOPER",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["role"] == "DEVELOPER"
    assert "hashed_password" not in data  # Password must not be exposed


def test_register_duplicate_username(client):
    """Test that duplicate usernames are rejected."""
    user_data = {
        "username": "duplicate",
        "email": "dup1@test.com",
        "password": "pass123",
        "role": "DEVELOPER",
    }
    client.post("/api/auth/register", json=user_data)
    
    response = client.post("/api/auth/register", json={
        **user_data,
        "email": "dup2@test.com",
    })
    assert response.status_code == 400


def test_login_success(client):
    """Test successful login returns a JWT token."""
    client.post("/api/auth/register", json={
        "username": "logintest",
        "email": "login@test.com",
        "password": "mypassword",
        "role": "DEVELOPER",
    })
    
    response = client.post("/api/auth/login", json={
        "username": "logintest",
        "password": "mypassword",
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    """Test login with wrong password is rejected."""
    client.post("/api/auth/register", json={
        "username": "wrongpass",
        "email": "wrong@test.com",
        "password": "correctpassword",
        "role": "DEVELOPER",
    })
    
    response = client.post("/api/auth/login", json={
        "username": "wrongpass",
        "password": "incorrectpassword",
    })
    assert response.status_code == 401


def test_get_current_user(client, auth_headers):
    """Test GET /api/auth/me returns the authenticated user."""
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testadmin"
    assert data["role"] == "ADMIN"


def test_unauthorized_access(client):
    """Test accessing protected endpoint without token returns 401."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401
