from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


TOKEN_TTL_SECONDS = 3600
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: int
    username: str


def hash_password(password: str, salt: bytes | None = None) -> str:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=actual_salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64encode(actual_salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected_digest = encoded_hash.split("$", maxsplit=5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(_b64encode(digest), expected_digest)


class JwtService:
    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret or os.environ.get("INFOSEC_JWT_SECRET") or secrets.token_urlsafe(32)

    def issue(self, user_id: int, username: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "username": username,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=TOKEN_TTL_SECONDS)).timestamp()),
        }
        return self._encode({"alg": "HS256", "typ": "JWT"}, payload)

    def verify(self, token: str) -> AuthenticatedUser | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_part, payload_part, signature_part = parts
        try:
            signed_part = f"{header_part}.{payload_part}".encode("ascii")
        except UnicodeEncodeError:
            return None
        expected_signature = self._sign(signed_part)
        if not hmac.compare_digest(expected_signature, signature_part):
            return None
        try:
            header = json.loads(_b64decode(header_part))
            payload = json.loads(_b64decode(payload_part))
            expires_at = int(payload["exp"])
            user_id = int(payload["sub"])
            username = str(payload["username"])
        except (binascii.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            return None
        if expires_at <= int(datetime.now(timezone.utc).timestamp()):
            return None
        return AuthenticatedUser(user_id=user_id, username=username)

    def _encode(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        header_part = _b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_part = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature_part = self._sign(f"{header_part}.{payload_part}".encode("ascii"))
        return f"{header_part}.{payload_part}.{signature_part}"

    def _sign(self, message: bytes) -> str:
        digest = hmac.new(self.secret.encode("utf-8"), message, hashlib.sha256).digest()
        return _b64encode(digest)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")
