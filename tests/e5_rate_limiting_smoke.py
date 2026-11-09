"""E5 rate-limiting integration test against an isolated HTTPS server and SQLite database."""

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import e1_smoke as e1
from e2_users_smoke import ApiBrowser


e1.DATABASE = e1.SERVER / "Data" / f"e5-smoke-{uuid.uuid4().hex}.db"


def post_form(browser, path, fields, forwarded_for):
    request = urllib.request.Request(
        urllib.parse.urljoin(browser.base, path),
        data=urllib.parse.urlencode(fields).encode(),
        headers={"X-Forwarded-For": forwarded_for},
        method="POST",
    )
    try:
        response = browser.opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read().decode("utf-8")
        page = e1.Page()
        page.feed(body)
        return response.status, urllib.parse.urlsplit(response.url).path, response.headers, page, body


def registration_form(browser):
    status, _, _, page, _ = browser.request("Account/Register")
    assert status == 200
    return next(form for form in page.forms if form["action"] == "/Account/Register")


def login_with_form(browser, email, password):
    status, _, _, page, _ = browser.request("Account/Login")
    assert status == 200
    form = next(form for form in page.forms if form["action"] == "/Account/Login")
    return post_form(browser, form["action"], {
        **form["fields"], "Input.Email": email, "Input.Password": password
    }, "198.51.100.200")


def run():
    assert e1.APP.exists(), "Build the solution before running the E5 smoke test"
    assert not e1.DATABASE.exists()
    admin_email = f"admin-{uuid.uuid4().hex}@example.invalid"
    admin_password = "Aa9!" + secrets.token_urlsafe(24)
    user_password = "Aa9!" + secrets.token_urlsafe(24)
    registered = []
    process = None
    short_limits = {
        "RateLimiting__Login__PermitLimit": "5",
        "RateLimiting__Login__WindowSeconds": "2",
        "RateLimiting__Registration__PermitLimit": "3",
        "RateLimiting__Registration__WindowSeconds": "2",
        "RateLimiting__AdministrativeRead__PermitLimit": "2",
        "RateLimiting__AdministrativeRead__WindowSeconds": "2",
        "RateLimiting__AdministrativeMutation__PermitLimit": "1",
        "RateLimiting__AdministrativeMutation__WindowSeconds": "2",
    }
    try:
        process, base = e1.start_server(
            e1.available_port(), admin_email, admin_password, True, short_limits)

        registration = ApiBrowser(base)
        initial_users = e1.counts()[0]
        for attempt in range(4):
            email = f"rate-register-{attempt}-{uuid.uuid4().hex}@example.invalid"
            form = registration_form(registration)
            status, path, headers, page, _ = post_form(registration, form["action"], {
                **form["fields"],
                "Input.Email": email,
                "Input.Password": user_password,
                "Input.ConfirmPassword": user_password,
            }, f"203.0.113.{10 + attempt}")
            if attempt < 3:
                assert status == 200 and path == "/Account/RegisterConfirmation", (attempt, status, path)
                registered.append(email)
                if attempt == 0:
                    confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
                    assert registration.request(confirmation)[0] == 200
            else:
                assert status == 429, status
                assert int(headers.get("Retry-After", "0")) > 0
        assert e1.counts()[0] == initial_users + 3
        print("registration: three accepted, fourth 429; spoofed X-Forwarded-For ignored: ok")

        login_limited = ApiBrowser(base)
        for attempt in range(6):
            status, _, _, page, _ = login_limited.request("Account/Login")
            assert status == 200
            form = next(form for form in page.forms if form["action"] == "/Account/Login")
            status, _, headers, _, _ = post_form(login_limited, form["action"], {
                **form["fields"],
                "Input.Email": registered[0],
                "Input.Password": "Wrong9!Password",
            }, f"198.51.100.{20 + attempt}")
            assert status == (200 if attempt < 5 else 429), (attempt, status)
            if attempt == 5:
                assert int(headers.get("Retry-After", "0")) > 0
        print("login: five accepted, sixth 429 with independent counter and Retry-After: ok")

        time.sleep(2.2)
        with e1.database() as db:
            user_id = db.execute(
                "select Id from AspNetUsers where Email=?", (registered[0],)).fetchone()[0]
            admin_role_id = db.execute(
                "select Id from AspNetRoles where NormalizedName='ADMIN'").fetchone()[0]
            db.execute(
                "insert into AspNetUserRoles(UserId,RoleId) values (?,?)", (user_id, admin_role_id))

        first_admin = ApiBrowser(base)
        status, path, _, _, _ = login_with_form(first_admin, admin_email, admin_password)
        assert status == 200 and path == "/"
        second_admin = ApiBrowser(base)
        status, path, _, _, _ = login_with_form(second_admin, registered[0], user_password)
        assert status == 200 and path == "/"

        assert first_admin.api("GET", "api/users")[0] == 200
        assert first_admin.api("GET", "api/roles")[0] == 200
        status, headers, body = first_admin.api("GET", "api/permissions")
        assert status == 429 and int(headers.get("Retry-After", "0")) > 0
        assert headers.get_content_type() == "application/json"
        assert body["status"] == 429 and "solicitudes" in body["title"].lower()
        assert second_admin.api("GET", "api/users")[0] == 200
        print("administrative reads: shared policy per user, separate users, JSON 429: ok")

        first_code = f"rate.first{uuid.uuid4().hex}"
        rejected_code = f"rate.rejected{uuid.uuid4().hex}"
        second_code = f"rate.second{uuid.uuid4().hex}"
        assert first_admin.mutate("POST", "api/permissions", {
            "code": first_code, "name": "Primer límite", "description": None
        })[0] == 201
        status, headers, body = first_admin.mutate("POST", "api/permissions", {
            "code": rejected_code, "name": "Debe rechazarse", "description": None
        })
        assert status == 429 and int(headers.get("Retry-After", "0")) > 0
        with e1.database() as db:
            assert db.execute(
                "select count(*) from Permissions where Code=?", (rejected_code,)).fetchone() == (0,)
        assert second_admin.mutate("POST", "api/permissions", {
            "code": second_code, "name": "Segundo usuario", "description": None
        })[0] == 201
        print("administrative mutations: independent policy/user counters; rejected write not executed: ok")

        time.sleep(2.2)
        recovered_code = f"rate.recovered{uuid.uuid4().hex}"
        assert first_admin.api("GET", "api/users")[0] == 200
        assert first_admin.mutate("POST", "api/permissions", {
            "code": recovered_code, "name": "Ventana recuperada", "description": None
        })[0] == 201
        print("fixed windows replenish and application continues after throttling: ok")

        with e1.database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
        print("isolated SQLite integrity after rate-limit scenarios: ok")
    finally:
        if process is not None and process.poll() is None:
            e1.stop_server(process)
        assert e1.DATABASE.resolve().is_relative_to((e1.SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            e1.DATABASE.with_name(e1.DATABASE.name + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    run()
