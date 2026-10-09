"""Password hashing/policy and JWT handling."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from app.config import Settings

_hasher = PasswordHasher()  # argon2id, library defaults (RFC 9106 low-memory profile)
# Verified against when the account does not exist so response time does not reveal valid emails.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

_COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator",
    "passwordpassword", "iloveyou1234", "welcome12345", "changeme1234",
}  # fmt: skip


class PasswordPolicyError(ValueError):
    pass


def validate_password(password: str, email: str = "") -> None:
    """Length-first policy (NIST SP 800-63B): 12-128 chars, not trivially common, not the email."""
    if len(password) < 12:
        raise PasswordPolicyError("Password must be at least 12 characters")
    if len(password) > 128:
        raise PasswordPolicyError("Password must be at most 128 characters")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(lowered)) < 5:
        raise PasswordPolicyError("Password is too common or too repetitive")
    local = email.split("@")[0].lower()
    if local and len(local) >= 4 and local in lowered:
        raise PasswordPolicyError("Password must not contain your email name")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    try:
        return _hasher.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    pass


@dataclass(frozen=True)
class TokenClaims:
    sub: uuid.UUID
    org_id: uuid.UUID
    jti: str
    fam: str
    typ: TokenType
    exp: datetime


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._alg = settings.jwt_algorithm
        if self._alg == "HS256":
            if settings.jwt_secret is None:
                raise RuntimeError("JWT_SECRET missing")
            self._sign_key: Any = settings.jwt_secret.get_secret_value()
            self._verify_key: Any = self._sign_key
        else:
            if not (settings.jwt_private_key_pem and settings.jwt_public_key_pem):
                raise RuntimeError("RS256 keys missing")
            self._sign_key = settings.jwt_private_key_pem.get_secret_value()
            self._verify_key = settings.jwt_public_key_pem

    def issue(self, user_id: uuid.UUID, org_id: uuid.UUID, typ: TokenType, fam: str) -> tuple[str, TokenClaims]:
        ttl = self._s.access_token_ttl_seconds if typ == "access" else self._s.refresh_token_ttl_seconds
        now = datetime.now(UTC)
        exp = now + timedelta(seconds=ttl)
        jti = secrets.token_urlsafe(24)
        payload = {
            "iss": self._s.jwt_issuer,
            "aud": self._s.jwt_audience,
            "sub": str(user_id),
            "org_id": str(org_id),
            "jti": jti,
            "fam": fam,
            "typ": typ,
            "iat": now,
            "nbf": now,
            "exp": exp,
        }
        token = jwt.encode(payload, self._sign_key, algorithm=self._alg, headers={"kid": self._s.jwt_key_id})
        return token, TokenClaims(user_id, org_id, jti, fam, typ, exp)

    def decode(self, token: str, expected: TokenType) -> TokenClaims:
        try:
            data = jwt.decode(
                token,
                self._verify_key,
                algorithms=[self._alg],  # pinned: no alg confusion, no "none"
                audience=self._s.jwt_audience,
                issuer=self._s.jwt_issuer,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]},
            )
            if data.get("typ") != expected:
                raise TokenError("wrong token type")
            return TokenClaims(
                sub=uuid.UUID(data["sub"]),
                org_id=uuid.UUID(data["org_id"]),
                jti=data["jti"],
                fam=data["fam"],
                typ=data["typ"],
                exp=datetime.fromtimestamp(data["exp"], UTC),
            )
        except (jwt.PyJWTError, KeyError, ValueError) as exc:
            raise TokenError(str(exc)) from exc

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        if self._alg != "RS256":
            return {"keys": []}
        key = serialization.load_pem_public_key((self._s.jwt_public_key_pem or "").encode())
        if not isinstance(key, RSAPublicKey):
            raise RuntimeError("JWT_PUBLIC_KEY_PEM is not an RSA key")
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key, as_dict=True)
        return {"keys": [{**jwk, "kid": self._s.jwt_key_id, "use": "sig", "alg": "RS256"}]}
