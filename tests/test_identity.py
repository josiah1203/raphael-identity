"""Identity tests."""

from fastapi.testclient import TestClient

from raphael_identity.app import app


def test_health() -> None:
    client = TestClient(app)
    assert client.get("/health").json()["service"] == "raphael-identity"


def test_dev_seed_login() -> None:
    client = TestClient(app)
    res = client.post("/v1/identity/login", json={"email": "dev@raphael.app", "password": "raphaeldev1"})
    assert res.status_code == 200
    assert "access_token" in res.json()


def test_register_login() -> None:
    import uuid

    client = TestClient(app)
    email = f"test-{uuid.uuid4().hex[:8]}@raphael.app"
    reg = client.post("/v1/identity/register", json={"email": email, "password": "securepass12"})
    assert reg.status_code == 200
    assert "access_token" in reg.json()
    login = client.post("/v1/identity/login", json={"email": email, "password": "securepass12"})
    assert login.status_code == 200


def test_profile_phone_patch() -> None:
    client = TestClient(app)
    login = client.post("/v1/identity/login", json={"email": "dev@raphael.app", "password": "raphaeldev1"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    profile = client.get("/v1/identity/profile", headers=headers)
    assert profile.status_code == 200
    assert "phone" in profile.json()

    updated = client.patch("/v1/identity/profile", headers=headers, json={"phone": "+15555550123"})
    assert updated.status_code == 200
    assert updated.json()["phone"] == "+15555550123"
    assert updated.json()["phone_verified"] is False


def test_oauth_start_unconfigured() -> None:
    client = TestClient(app)
    res = client.get("/v1/identity/oauth/google/start", params={"redirect_uri": "http://localhost/callback"})
    assert res.status_code == 400
