"""E5.1 JSON authentication test against isolated HTTPS and SQLite."""

import secrets
import time
import urllib.parse
import uuid

import e1_smoke as e1
from e2_users_smoke import ApiBrowser


e1.DATABASE = e1.SERVER / "Data" / f"e51-auth-api-{uuid.uuid4().hex}.db"


def run():
    assert e1.APP.exists(), "Build the solution before running the E5.1 smoke test"
    assert not e1.DATABASE.exists()
    admin_email = f"admin-{uuid.uuid4().hex}@example.invalid"
    admin_password = "Aa9!" + secrets.token_urlsafe(24)
    email = f"api-user-{uuid.uuid4().hex}@example.invalid"
    password = "Aa9!" + secrets.token_urlsafe(24)
    process = None
    limits = {
        "RateLimiting__Login__PermitLimit": "5",
        "RateLimiting__Login__WindowSeconds": "2",
        "RateLimiting__Registration__PermitLimit": "3",
        "RateLimiting__Registration__WindowSeconds": "2",
    }
    try:
        process, base = e1.start_server(
            e1.available_port(), admin_email, admin_password, True, limits)
        browser = ApiBrowser(base)
        payload = {
            "email": email,
            "password": password,
            "confirmPassword": password,
        }

        assert browser.api("POST", "api/auth/register", payload)[0] == 400
        token = public_csrf(browser)
        status, _, body = browser.api("POST", "api/auth/register", payload, token)
        assert status == 200 and body["email"] == email and body["confirmationRequired"] is True

        with e1.database() as db:
            user_id, confirmed = db.execute(
                "select Id,EmailConfirmed from AspNetUsers where Email=?", (email,)
            ).fetchone()
            roles = db.execute(
                "select r.Name from AspNetRoles r "
                "join AspNetUserRoles ur on ur.RoleId=r.Id where ur.UserId=?",
                (user_id,),
            ).fetchall()
            assert confirmed == 0 and roles == [("User",)]
        print("JSON registration requires CSRF and assigns only User: ok")

        login_payload = {"email": email, "password": password, "rememberMe": False}
        assert browser.api("POST", "api/auth/login", login_payload, public_csrf(browser))[0] == 401

        status, _, _, page, _ = browser.request(
            "Account/RegisterConfirmation?" + urllib.parse.urlencode({"email": email})
        )
        assert status == 200
        confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
        assert browser.request(confirmation)[0] == 200

        status, headers, _ = browser.api(
            "POST", "api/auth/login", login_payload, public_csrf(browser)
        )
        assert status == 200 and headers.get_all("Set-Cookie")
        status, _, me = browser.api("GET", "api/auth/me")
        assert status == 200 and me["email"] == email and me["roles"] == ["User"]
        assert browser.api("GET", "api/admin/overview")[0] == 403
        print("confirmed JSON login emits cookie; session is 200 and RBAC remains 403: ok")

        assert browser.api("POST", "api/auth/logout")[0] == 400
        assert browser.api("GET", "api/auth/me")[0] == 200
        assert browser.api("POST", "api/auth/logout", token=public_csrf(browser))[0] == 204
        assert browser.api("GET", "api/auth/me")[0] == 401
        print("JSON logout requires CSRF and invalidates the cookie: ok")

        time.sleep(2.2)
        registration_limited = ApiBrowser(base)
        registration_token = public_csrf(registration_limited)
        for attempt in range(4):
            attempt_email = f"limited-{attempt}-{uuid.uuid4().hex}@example.invalid"
            status, headers, _ = registration_limited.api(
                "POST",
                "api/auth/register",
                {
                    "email": attempt_email,
                    "password": password,
                    "confirmPassword": password,
                },
                registration_token,
            )
            assert status == (200 if attempt < 3 else 429), (attempt, status)
            if attempt == 3:
                assert int(headers.get("Retry-After", "0")) > 0

        login_limited = ApiBrowser(base)
        login_token = public_csrf(login_limited)
        for attempt in range(6):
            status, headers, _ = login_limited.api(
                "POST",
                "api/auth/login",
                {"email": email, "password": "Wrong9!Password", "rememberMe": False},
                login_token,
            )
            assert status == (401 if attempt < 5 else 429), (attempt, status)
            if attempt == 5:
                assert int(headers.get("Retry-After", "0")) > 0
        print("JSON register/login enforce independent 3/5 IP limits and Retry-After: ok")

        with e1.database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
        print("isolated SQLite remains integral after JSON authentication: ok")
    finally:
        if process is not None and process.poll() is None:
            e1.stop_server(process)
        assert e1.DATABASE.resolve().is_relative_to((e1.SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            e1.DATABASE.with_name(e1.DATABASE.name + suffix).unlink(missing_ok=True)


def public_csrf(browser):
    status, _, body = browser.api("GET", "api/auth/antiforgery")
    assert status == 200 and body["token"]
    return body["token"]


if __name__ == "__main__":
    run()
