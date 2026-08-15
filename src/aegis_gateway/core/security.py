import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt

API_KEY_PREFIX = "agk_live_"
KEY_ID_BYTES = 8  # 16 hex chars, indexable, not secret on its own
SECRET_BYTES = 24  # 32 urlsafe-b64 chars, the actual bearer secret

# argon2id is for LOW-ENTROPY HUMAN SECRETS (admin passwords) — its deliberate slowness
# defends against offline brute force of guessable passwords. API keys below use HMAC
# instead: a 256-bit random key is already unbrute-forceable, argon2's slowness would
# only add attacker-irrelevant latency, and unlike argon2's per-row salt, HMAC produces
# a deterministic digest we can index for O(1) lookup instead of iterating every row.
_password_hasher = PasswordHasher()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key_to_show_once, key_id, secret_part).

    full_key_to_show_once: what the caller puts in Authorization: Bearer <this>.
    key_id: indexable prefix, stored in plaintext, used for DB lookup.
    secret_part: never stored — only its HMAC digest is (see hash_api_key_secret).
    """
    key_id = secrets.token_hex(KEY_ID_BYTES)
    secret_part = secrets.token_urlsafe(SECRET_BYTES)
    full_key = f"{API_KEY_PREFIX}{key_id}.{secret_part}"
    return full_key, key_id, secret_part


def parse_api_key(full_key: str) -> tuple[str, str] | None:
    """Splits a presented bearer token into (key_id, secret_part). None if malformed."""
    if not full_key.startswith(API_KEY_PREFIX):
        return None
    remainder = full_key[len(API_KEY_PREFIX) :]
    key_id, _, secret_part = remainder.partition(".")
    if not key_id or not secret_part:
        return None
    return key_id, secret_part


def hash_api_key_secret(secret_part: str, pepper: str) -> str:
    """HMAC-SHA256 keyed by a server-side pepper (held only in app config, never in the
    DB) so a DB dump alone doesn't let an attacker precompute/verify guesses offline."""
    return hmac.new(pepper.encode(), secret_part.encode(), hashlib.sha256).hexdigest()


def verify_api_key_secret(secret_part: str, pepper: str, expected_hash: str) -> bool:
    computed = hash_api_key_secret(secret_part, pepper)
    return hmac.compare_digest(computed, expected_hash)


def hash_password(plain_password: str) -> str:
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False


def create_admin_jwt(*, subject: str, secret: str, algorithm: str, expire_minutes: int) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
        "scope": "admin",
    }
    encoded: str = jwt.encode(payload, secret, algorithm=algorithm)
    return encoded


def decode_admin_jwt(token: str, *, secret: str, algorithm: str) -> dict[str, Any] | None:
    try:
        payload: dict[str, Any] = jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError:
        return None
    if payload.get("scope") != "admin":
        return None
    return payload
