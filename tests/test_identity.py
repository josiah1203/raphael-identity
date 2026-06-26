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
    client = TestClient(app)
    reg = client.post("/v1/identity/register", json={"email": "test@raphael.app", "password": "securepass1"})
    assert reg.status_code == 200
    assert "access_token" in reg.json()
    login = client.post("/v1/identity/login", json={"email": "test@raphael.app", "password": "securepass1"})
    assert login.status_code == 200
