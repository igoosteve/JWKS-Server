import time

import jwt

from app import app
from keys import ACTIVE_KEY, EXPIRED_KEY


def test_jwks_returns_active_key():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == ACTIVE_KEY["kid"]
    assert data["keys"][0]["kid"] != EXPIRED_KEY["kid"]


def test_auth_returns_valid_token():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    payload = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False
        }
    )

    assert header["kid"] == ACTIVE_KEY["kid"]
    assert header["alg"] == "RS256"

    assert payload["sub"] == "fake-user"
    assert payload["exp"] > int(time.time())


def test_auth_expired_returns_expired_token():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    payload = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False
        }
    )

    assert header["kid"] == EXPIRED_KEY["kid"]
    assert header["alg"] == "RS256"

    assert payload["sub"] == "fake-user"
    assert payload["exp"] < int(time.time())