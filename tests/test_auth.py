import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import text

from tests.conftest import PASSWORD, login, next_ip


async def test_register_creates_org_and_admin(client, new_org):
    org = await new_org()
    r = await client.get("/api/v1/users/me", headers=org.admin.h)
    assert r.status_code == 200
    assert r.json()["role"] == "admin" and r.json()["org_id"] == org.org_id
    assert "hashed_password" not in r.text


@pytest.mark.parametrize("pw", ["short", "aaaaaaaaaaaa", "password1234", "x" * 129])
async def test_weak_passwords_rejected(client, pw):
    r = await client.post(
        "/api/v1/auth/register",
        headers={"X-Forwarded-For": next_ip()},
        json={
            "organization_name": "Weak",
            "organization_slug": f"weak-{uuid.uuid4().hex[:8]}",
            "email": f"w{uuid.uuid4().hex[:6]}@example.com",
            "password": pw,
        },
    )
    assert r.status_code == 422


async def test_duplicate_slug_and_email_conflict(client, new_org):
    org = await new_org()
    r = await client.post(
        "/api/v1/auth/register",
        headers={"X-Forwarded-For": next_ip()},
        json={
            "organization_name": "Dup",
            "organization_slug": f"x-{uuid.uuid4().hex[:8]}",
            "email": org.admin.email.upper(),
            "password": PASSWORD,
        },
    )
    assert r.status_code == 409


async def test_login_failure_is_generic_and_does_not_enumerate(client, new_org):
    org = await new_org()
    wrong_pw = await login(client, org.admin.email, "definitely-wrong-password")
    unknown = await login(client, f"nobody-{uuid.uuid4().hex[:6]}@example.com")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


async def test_login_rate_limited_per_ip(client, new_org):
    org = await new_org()
    ip = {"X-Forwarded-For": next_ip()}
    codes = []
    for _ in range(7):
        r = await client.post(
            "/api/v1/auth/login",
            headers=ip,
            json={"email": org.admin.email, "password": "wrong-wrong-wrong"},
        )
        codes.append(r.status_code)
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429, 429]
    r = await client.post(
        "/api/v1/auth/login",
        headers={"X-Forwarded-For": next_ip()},
        json={"email": org.admin.email, "password": PASSWORD},
    )
    assert r.status_code == 200  # another IP is unaffected


async def test_spoofed_forwarded_for_does_not_evade_limit(client, new_org):
    """trusted_proxy_count=1: only the right-most entry (added by our proxy) counts."""
    org = await new_org()
    real = next_ip()
    codes = []
    for i in range(7):
        r = await client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": f"10.9.9.{i}, {real}"},
            json={"email": org.admin.email, "password": "wrong-wrong-wrong"},
        )
        codes.append(r.status_code)
    assert codes[-1] == 429


async def test_account_lockout_after_repeated_failures(app, client, new_org):
    org = await new_org()
    for _ in range(10):
        await client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": next_ip()},
            json={"email": org.admin.email, "password": "wrong-wrong-wrong"},
        )
    r = await login(client, org.admin.email)  # correct password, different IP, still locked
    assert r.status_code == 429


async def test_protected_routes_require_token(client):
    for path in ("/api/v1/users/me", "/api/v1/documents", "/api/v1/audit"):
        r = await client.get(path)
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"


async def test_refresh_rotation_and_reuse_detection(client, new_org):
    org = await new_org()
    first = (await login(client, org.admin.email)).json()
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first["refresh_token"]},
        headers={"X-Forwarded-For": next_ip()},
    )
    assert r.status_code == 200
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]
    # replaying the already-rotated token = theft signal: whole family is revoked
    replay = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first["refresh_token"]},
        headers={"X-Forwarded-For": next_ip()},
    )
    assert replay.status_code == 401
    dead = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": second["refresh_token"]},
        headers={"X-Forwarded-For": next_ip()},
    )
    assert dead.status_code == 401
    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {second['access_token']}"})
    assert me.status_code == 401
    audit = await client.get("/api/v1/audit", headers=org.admin.h, params={"action": "auth.refresh_reuse_detected"})
    assert audit.json()["total"] == 1


async def test_access_token_cannot_be_used_as_refresh_and_vice_versa(client, new_org):
    org = await new_org()
    tok = (await login(client, org.admin.email)).json()
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tok["access_token"]},
        headers={"X-Forwarded-For": next_ip()},
    )
    assert r.status_code == 401
    r = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tok['refresh_token']}"})
    assert r.status_code == 401


async def test_logout_revokes_session(client, new_org):
    org = await new_org()
    tok = (await login(client, org.admin.email)).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert (await client.post("/api/v1/auth/logout", headers=h)).status_code == 204
    assert (await client.get("/api/v1/users/me", headers=h)).status_code == 401
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tok["refresh_token"]},
        headers={"X-Forwarded-For": next_ip()},
    )
    assert r.status_code == 401


async def test_concurrent_refresh_only_one_wins(client, new_org):
    org = await new_org()
    tok = (await login(client, org.admin.email)).json()
    results = await asyncio.gather(
        *[
            client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": tok["refresh_token"]},
                headers={"X-Forwarded-For": next_ip()},
            )
            for _ in range(8)
        ]
    )
    assert sorted(r.status_code for r in results).count(200) == 1


def _forge(app, **overrides):
    s = app.state.settings
    now = datetime.now(UTC)
    claims = {
        "iss": s.jwt_issuer,
        "aud": s.jwt_audience,
        "sub": str(uuid.uuid4()),
        "org_id": str(uuid.uuid4()),
        "jti": "x",
        "fam": "f",
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    return claims


async def test_forged_expired_and_wrong_audience_tokens_rejected(app, client, new_org):
    org = await new_org()
    s = app.state.settings
    secret = s.jwt_secret.get_secret_value()
    good = _forge(app, sub=org.admin.id, org_id=org.org_id)
    bad = {
        "expired": jwt.encode({**good, "exp": datetime.now(UTC) - timedelta(seconds=5)}, secret, "HS256"),
        "wrong_aud": jwt.encode({**good, "aud": "other"}, secret, "HS256"),
        "wrong_iss": jwt.encode({**good, "iss": "https://evil"}, secret, "HS256"),
        "wrong_secret": jwt.encode(good, "z" * 40, "HS256"),
        "none_alg": jwt.encode(good, None, algorithm="none"),
        "missing_exp": jwt.encode({k: v for k, v in good.items() if k != "exp"}, secret, "HS256"),
        "wrong_org": jwt.encode({**good, "org_id": str(uuid.uuid4())}, secret, "HS256"),
        "garbage": "not.a.jwt",
    }
    assert (
        await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {jwt.encode(good, secret, 'HS256')}"},
        )
    ).status_code == 200
    for name, token in bad.items():
        r = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401, name


async def test_deactivated_user_loses_access_immediately(client, new_org):
    org = await new_org()
    editor = await org.add_user("editor")
    assert (await client.get("/api/v1/users/me", headers=editor.h)).status_code == 200
    r = await client.patch(f"/api/v1/users/{editor.id}", headers=org.admin.h, json={"is_active": False})
    assert r.status_code == 200
    assert (await client.get("/api/v1/users/me", headers=editor.h)).status_code == 401
    assert (await login(client, editor.email)).status_code == 401


async def test_oauth2_token_endpoint_password_and_refresh_grants(client, new_org):
    org = await new_org()
    r = await client.post(
        "/api/v1/auth/token",
        headers={"X-Forwarded-For": next_ip()},
        data={"grant_type": "password", "username": org.admin.email, "password": PASSWORD},
    )
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"
    r2 = await client.post(
        "/api/v1/auth/token",
        headers={"X-Forwarded-For": next_ip()},
        data={"grant_type": "refresh_token", "refresh_token": r.json()["refresh_token"]},
    )
    assert r2.status_code == 200
    bad = await client.post(
        "/api/v1/auth/token",
        headers={"X-Forwarded-For": next_ip()},
        data={"grant_type": "client_credentials"},
    )
    assert bad.status_code == 422


async def test_passwords_are_stored_as_argon2id(owner_engine, new_org):
    org = await new_org()
    async with owner_engine.connect() as c:
        h = (await c.execute(text("SELECT hashed_password FROM users WHERE id=:i"), {"i": org.admin.id})).scalar_one()
    assert h.startswith("$argon2id$") and PASSWORD not in h


async def test_login_is_audited(client, new_org):
    org = await new_org()
    await login(client, org.admin.email, "wrong-wrong-wrong")
    await login(client, org.admin.email)
    actions = [i["action"] for i in (await client.get("/api/v1/audit", headers=org.admin.h)).json()["items"]]
    assert "auth.login_failed" in actions and "auth.login" in actions and "org.register" in actions
