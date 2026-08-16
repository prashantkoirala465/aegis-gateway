from aegis_gateway.core.security import (
    create_admin_jwt,
    decode_admin_jwt,
    generate_api_key,
    hash_api_key_secret,
    hash_password,
    parse_api_key,
    verify_api_key_secret,
    verify_password,
)

PEPPER = "test-pepper"


def test_api_key_round_trip_verifies() -> None:
    full_key, key_id, secret_part = generate_api_key()
    hashed = hash_api_key_secret(secret_part, PEPPER)

    parsed = parse_api_key(full_key)
    assert parsed == (key_id, secret_part)
    assert verify_api_key_secret(secret_part, PEPPER, hashed)


def test_api_key_wrong_pepper_fails() -> None:
    _, _, secret_part = generate_api_key()
    hashed = hash_api_key_secret(secret_part, PEPPER)
    assert not verify_api_key_secret(secret_part, "wrong-pepper", hashed)


def test_parse_api_key_rejects_malformed() -> None:
    assert parse_api_key("not-a-valid-key") is None
    assert parse_api_key("agk_live_missing-dot-separator") is None


def test_password_hash_round_trip() -> None:
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong password", hashed)


_TEST_SECRET = "jwt-secret-at-least-32-bytes-long-for-hs256"  # gitleaks:allow


def test_admin_jwt_round_trip() -> None:
    token = create_admin_jwt(
        subject="admin-id-123", secret=_TEST_SECRET, algorithm="HS256", expire_minutes=5
    )
    payload = decode_admin_jwt(token, secret=_TEST_SECRET, algorithm="HS256")
    assert payload is not None
    assert payload["sub"] == "admin-id-123"


def test_admin_jwt_rejects_wrong_secret() -> None:
    token = create_admin_jwt(
        subject="admin-id-123", secret=_TEST_SECRET, algorithm="HS256", expire_minutes=5
    )
    assert (
        decode_admin_jwt(token, secret="wrong-secret-also-32-bytes-long!", algorithm="HS256")
        is None
    )
