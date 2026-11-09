"""E2 user CRUD integration test using an isolated SQLite database."""

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import e1_smoke as e1


e1.DATABASE = e1.SERVER / "Data" / f"e2-smoke-{uuid.uuid4().hex}.db"


class ApiBrowser(e1.Browser):
    def api(self, method, path, payload=None, token=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        if token is not None:
            headers["X-CSRF-TOKEN"] = token
        request = urllib.request.Request(
            urllib.parse.urljoin(self.base, path), data=data, headers=headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read().decode("utf-8")
            parsed = json.loads(content) if content and "json" in response.headers.get("Content-Type", "") else content
            return response.status, response.headers, parsed

    def csrf(self):
        status, _, body = self.api("GET", "api/security/antiforgery")
        assert status == 200 and body["token"]
        return body["token"]

    def mutate(self, method, path, payload=None):
        return self.api(method, path, payload, self.csrf())


def run():
    assert e1.APP.exists(), "Build the solution before running the E2 smoke test"
    assert not e1.DATABASE.exists()
    admin_email = f"admin-{uuid.uuid4().hex}@example.invalid"
    admin_password = "Aa9!" + secrets.token_urlsafe(24)
    user_email = f"user-{uuid.uuid4().hex}@example.invalid"
    user_password = "Aa9!" + secrets.token_urlsafe(24)
    process = None
    try:
        process, base = e1.start_server(e1.available_port(), admin_email, admin_password, True)
        anonymous = ApiBrowser(base)
        for method, path, payload in (
            ("GET", "api/users", None),
            ("GET", "api/users/missing", None),
            ("POST", "api/users", {"email": user_email, "password": user_password, "confirmPassword": user_password}),
            ("PUT", "api/users/missing", {"email": user_email}),
            ("DELETE", "api/users/missing", None),
        ):
            observed, _, response_body = anonymous.api(method, path, payload)
            assert observed == 401, (method, path, observed, response_body)
        assert anonymous.api("GET", "api/security/antiforgery")[0] == 401
        print("anonymous CRUD and antiforgery token: 401")

        user = ApiBrowser(base)
        _, _, _, page, _ = user.request("Account/Register")
        form = next(form for form in page.forms if form["action"] == "/Account/Register")
        status, path, _, page, _ = user.request(form["action"], {
            **form["fields"], "Input.Email": user_email,
            "Input.Password": user_password, "Input.ConfirmPassword": user_password,
            "Role": "Admin", "Input.Role": "Admin"
        })
        assert status == 200 and path == "/Account/RegisterConfirmation"
        confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
        user.request(confirmation)
        user.login(user_email, user_password)
        with e1.database() as db:
            normal_id = db.execute("select Id from AspNetUsers where Email=?", (user_email,)).fetchone()[0]
            assert db.execute("select r.Name from AspNetRoles r join AspNetUserRoles ur on ur.RoleId=r.Id where ur.UserId=?", (normal_id,)).fetchall() == [("User",)]
        for method, path, payload in (
            ("GET", "api/users", None),
            ("GET", f"api/users/{normal_id}", None),
            ("POST", "api/users", {"email": "other@example.invalid", "password": user_password, "confirmPassword": user_password}),
            ("PUT", f"api/users/{normal_id}", {"email": "other@example.invalid"}),
            ("DELETE", f"api/users/{normal_id}", None),
        ):
            assert user.mutate(method, path, payload)[0] == 403, (method, path)
        print("public registration remains User-only; ordinary User CRUD: 403")

        admin = ApiBrowser(base)
        admin.login(admin_email, admin_password)
        admin_id = admin.api("GET", "api/auth/me")[2]["id"]
        assert admin.api("GET", "api/users")[0] == 200
        assert admin.api("GET", "api/users?page=1&pageSize=1")[2]["totalCount"] == 2
        assert admin.api("GET", "api/users?page=0&pageSize=10")[0] == 400
        assert admin.api("GET", "api/users?page=1&pageSize=51")[0] == 400
        assert admin.api("GET", "api/users/missing")[0] == 404
        assert admin.api("GET", f"api/users/{normal_id}")[2]["roles"] == ["User"]

        target_email = f"created-{uuid.uuid4().hex}@example.invalid"
        target_password = "Aa9!" + secrets.token_urlsafe(24)
        create = {"email": target_email, "password": target_password, "confirmPassword": target_password}
        assert admin.api("POST", "api/users", create)[0] == 400  # No CSRF token.
        assert admin.api("POST", "api/users", create, "invalid-token")[0] == 400
        status, headers, result = admin.mutate("POST", "api/users", create)
        assert status == 201, (status, result)
        target_id = result["user"]["id"]
        assert headers.get("Location", "").endswith(target_id)
        assert result["user"]["roles"] == ["User"] and not result["user"]["emailConfirmed"]
        assert "password" not in json.dumps(result).lower()
        with e1.database() as db:
            assert db.execute("select EmailConfirmed from AspNetUsers where Id=?", (target_id,)).fetchone() == (0,)
            assert db.execute("select r.Name from AspNetRoles r join AspNetUserRoles ur on ur.RoleId=r.Id where ur.UserId=?", (target_id,)).fetchall() == [("User",)]
        assert admin.mutate("POST", "api/users", create)[0] == 409
        assert admin.mutate("POST", "api/users", {**create, "email": "invalid"})[0] == 400
        assert admin.mutate("POST", "api/users", {**create, "email": "weak@example.invalid", "password": "x", "confirmPassword": "x"})[0] == 400
        assert admin.mutate("POST", "api/users", {**create, "email": "forged@example.invalid", "role": "Admin"})[0] == 400
        print("CREATE 201, duplicate 409, validation 400, forged role 400, CSRF 400")

        status, _, page_result = admin.api("GET", "api/users?page=1&pageSize=1")
        assert status == 200 and len(page_result["items"]) == 1 and page_result["totalCount"] == 3
        assert admin.api("GET", "api/users?page=2&pageSize=1")[2]["items"][0]["id"] != page_result["items"][0]["id"]
        assert admin.api("GET", "api/users?search=" + urllib.parse.quote(target_email))[2]["totalCount"] == 1
        detail = admin.api("GET", f"api/users/{target_id}")[2]
        assert detail["email"] == target_email and set(detail) == {"id", "email", "emailConfirmed", "roles"}
        print("READ pagination, search, detail DTO and 404: ok")

        new_email = f"changed-{uuid.uuid4().hex}@example.invalid"
        assert admin.api("PUT", f"api/users/{target_id}", {"email": new_email})[0] == 400
        assert admin.mutate("PUT", f"api/users/{target_id}", {"email": "invalid"})[0] == 400
        assert admin.mutate("PUT", f"api/users/{target_id}", {"email": admin_email})[0] == 409
        assert admin.mutate("PUT", "api/users/missing", {"email": new_email})[0] == 404
        assert admin.mutate("PUT", f"api/users/{target_id}", {"email": new_email, "emailConfirmed": True})[0] == 400
        status, _, updated = admin.mutate("PUT", f"api/users/{target_id}", {"email": new_email})
        assert status == 200 and updated["user"]["email"] == new_email
        assert not updated["user"]["emailConfirmed"]
        with e1.database() as db:
            assert db.execute("select Email,UserName,NormalizedEmail,NormalizedUserName,EmailConfirmed from AspNetUsers where Id=?", (target_id,)).fetchone() == (new_email, new_email, new_email.upper(), new_email.upper(), 0)
        _, _, _, page, _ = admin.request("Account/RegisterConfirmation?email=" + urllib.parse.quote(new_email))
        confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
        admin.request(confirmation)
        with e1.database() as db:
            assert db.execute("select EmailConfirmed from AspNetUsers where Id=?", (target_id,)).fetchone() == (1,)
        print("UPDATE validation, duplicate, mass assignment, atomic email/username, reconfirmation: ok")

        assert admin.mutate("DELETE", f"api/users/{admin_id}")[0] == 409
        assert admin.mutate("DELETE", "api/users/missing")[0] == 404
        assert admin.api("DELETE", f"api/users/{target_id}")[0] == 400  # No CSRF token.
        assert admin.api("DELETE", f"api/users/{target_id}", token="invalid-token")[0] == 400
        assert admin.mutate("DELETE", f"api/users/{target_id}")[0] == 204
        assert admin.api("GET", f"api/users/{target_id}")[0] == 404
        with e1.database() as db:
            assert db.execute("select count(*) from AspNetUsers where Id=?", (target_id,)).fetchone() == (0,)
            assert db.execute("select count(*) from AspNetUserRoles where UserId=?", (target_id,)).fetchone() == (0,)
            db.execute("pragma foreign_keys=on")
            user_role_id = db.execute("select Id from AspNetRoles where Name='User'").fetchone()[0]
            delete_permission_id = db.execute("select Id from Permissions where Code='users.delete'").fetchone()[0]
            db.execute("insert into RolePermissions(RoleId,PermissionId) values (?,?)", (user_role_id, delete_permission_id))
        assert user.mutate("DELETE", f"api/users/{admin_id}")[0] == 409
        assert admin.api("GET", f"api/users/{admin_id}")[0] == 200
        with e1.database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
        print("DELETE 204/404, self-delete and last Admin 409, referential integrity: ok")
    finally:
        if process is not None and process.poll() is None:
            e1.stop_server(process)
        assert e1.DATABASE.resolve().is_relative_to((e1.SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            e1.DATABASE.with_name(e1.DATABASE.name + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    run()
