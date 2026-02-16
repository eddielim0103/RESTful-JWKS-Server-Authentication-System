import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_jwks_endpoint():
    """Test if JWKS returns only valid keys"""
    response = client.get("/jwks")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    # Ensure at least one key is returned (from our initial setup)
    assert len(data["keys"]) >= 1

def test_auth_valid_token():
    """Test /auth returns a token for valid request"""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()

def test_auth_expired_token():
    """Test /auth returns a token when expired=true is requested"""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "token" in response.json()

def test_well_known_jwks():
    """Test the standard .well-known path"""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200