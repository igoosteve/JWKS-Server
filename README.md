# JWKS Server

A JWKS server implemented in Python using Flask.

## Features

- Generates RSA key pairs
- Assigns each key a unique `kid`
- Supports key expiration
- Serves public keys in JWKS format
- Issues RS256 signed JWTs
- Supports issuance of expired JWTs
- Includes automated tests

## Endpoints

### GET /.well-known/jwks.json

Returns all non-expired public keys in JWKS format.

### POST /auth

Returns a JWT signed using the active RSA private key.

### POST /auth?expired=true

Returns an expired JWT signed using the expired RSA private key.

## Installation

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
