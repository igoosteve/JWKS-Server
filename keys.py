import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa


def base64url_encode(number):
    """Convert an integer into Base64 URL format."""
    byte_length = (number.bit_length() + 7) // 8
    number_bytes = number.to_bytes(byte_length, byteorder="big")

    return (
        base64.urlsafe_b64encode(number_bytes)
        .rstrip(b"=")
        .decode("utf-8")
    )


def generate_key(expired=False):
    """Generate an RSA key with a unique ID and expiration time."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    kid = str(uuid.uuid4())

    current_time = int(time.time())

    if expired:
        expires_at = current_time - 3600
    else:
        expires_at = current_time + 3600

    return {
        "kid": kid,
        "private_key": private_key,
        "expires_at": expires_at
    }

def key_to_jwk(key):
    """Convert an RSA key into JWKS format."""

    public_key = key["private_key"].public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": key["kid"],
        "use": "sig",
        "alg": "RS256",
        "n": base64url_encode(public_numbers.n),
        "e": base64url_encode(public_numbers.e)
    }


ACTIVE_KEY = generate_key(expired=False)
EXPIRED_KEY = generate_key(expired=True)