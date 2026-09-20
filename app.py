import time
import jwt

from flask import Flask, jsonify, request
from keys import ACTIVE_KEY, EXPIRED_KEY, key_to_jwk


app = Flask(__name__)


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all public keys that have not expired."""

    current_time = int(time.time())

    all_keys = [ACTIVE_KEY, EXPIRED_KEY]

    valid_keys = []

    for key in all_keys:
        if key["expires_at"] > current_time:
            valid_keys.append(key_to_jwk(key))

    return jsonify({
        "keys": valid_keys
    })

@app.route("/auth", methods=["POST"])
def auth():
    """Return a signed JWT."""

    current_time = int(time.time())

    if "expired" in request.args: # check if  the "expired" parameter was provided
        key = EXPIRED_KEY

        payload = {
            "sub": "fake-user",
            "iat": key["expires_at"] - 3600,
            "exp": key["expires_at"]
        }

    else:
        key = ACTIVE_KEY

        payload = {
            "sub": "fake-user",
            "iat": current_time,
            "exp": current_time + 3600
        }

    token = jwt.encode(
        payload,
        key["private_key"],
        algorithm="RS256",
        headers={
            "kid": key["kid"]
        }
    )

    return token


if __name__ == "__main__":
    app.run(port=8080)