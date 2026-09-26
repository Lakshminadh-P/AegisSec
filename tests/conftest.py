"""
Pytest Configuration and Fixtures

Shared test fixtures used across all test files.
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test environment BEFORE importing app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["APP_ENV"] = "testing"

from app.main import app
from app.database import Base, get_db

# Test database
TEST_DATABASE_URL = "sqlite:///./test.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    # Clean up test database file
    if os.path.exists("test.db"):
        try:
            os.remove("test.db")
        except:
            pass


@pytest.fixture
def client():
    """Test client for making API requests."""
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Get authentication headers by registering and logging in."""
    # Register a test user
    client.post("/api/auth/register", json={
        "username": "testadmin",
        "email": "test@aegissec.local",
        "password": "testpass123",
        "role": "ADMIN",
    })
    
    # Login
    response = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "testpass123",
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(client):
    """Get auth headers for a security analyst user."""
    client.post("/api/auth/register", json={
        "username": "testanalyst",
        "email": "analyst@aegissec.local",
        "password": "testpass123",
        "role": "SECURITY_ANALYST",
    })
    response = client.post("/api/auth/login", json={
        "username": "testanalyst",
        "password": "testpass123",
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def developer_headers(client):
    """Get auth headers for a developer user."""
    client.post("/api/auth/register", json={
        "username": "testdev",
        "email": "dev@aegissec.local",
        "password": "testpass123",
        "role": "DEVELOPER",
    })
    response = client.post("/api/auth/login", json={
        "username": "testdev",
        "password": "testpass123",
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_vulnerability(client, auth_headers):
    """Create a sample vulnerability for testing."""
    response = client.post("/api/vulnerabilities/", json={
        "title": "Test SQL Injection",
        "severity": "CRITICAL",
        "source": "Semgrep",
        "component": "test/app.py:10",
        "description": "SQL injection found in test",
        "status": "OPEN",
        "risk_score": 9.5,
    }, headers=auth_headers)
    return response.json()
