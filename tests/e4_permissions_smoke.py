"""E4 permission and role-permission integration test using an isolated SQLite database."""

import secrets
import urllib.parse
import uuid

import e1_smoke as e1
from e2_users_smoke import ApiBrowser


e1.DATABASE = e1.SERVER / "Data" / f"e4-smoke-{uuid.uuid4().hex}.db"


SYSTEM_CODES = {
    "users.create", "users.read", "users.update", "users.delete",
    "roles.create", "roles.read", "roles.update", "roles.delete",
    "permissions.create", "permissions.read", "permissions.update", "permissions.delete",
}


def register_user(base, email, password):
    browser = ApiBrowser(base)
    _, _, _, page, _ = browser.request("Account/Register")
    form = next(form for form in page.forms if form["action"] == "/Account/Register")
    status, path, _, page, _ = browser.request(form["action"], {
        **form["fields"], "Input.Email": email,
        "Input.Password": password, "Input.ConfirmPassword": password,
    })
    assert status == 200 and path == "/Account/RegisterConfirmation"
    confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
    browser.request(confirmation)
    browser.login(email, password)
    status, _, me = browser.api("GET", "api/auth/me")
    assert status == 200
    return browser, me["id"]


def create_role(admin, name):
    status, _, body = admin.mutate("POST", "api/roles", {"name": name})
    assert status == 201, (name, status, body)
    return body


def grant_direct(role_id, *codes):
    with e1.database() as db:
        for code in codes:
            permission_id = db.execute(
                "select Id from Permissions where Code=?", (code,)).fetchone()[0]
            db.execute(
                "insert into RolePermissions(RoleId,PermissionId) values (?,?)",
                (role_id, permission_id),
            )


def run():
    assert e1.APP.exists(), "Build the solution before running the E4 smoke test"
    assert not e1.DATABASE.exists()
    admin_email = f"admin-{uuid.uuid4().hex}@example.invalid"
    admin_password = "Aa9!" + secrets.token_urlsafe(24)
    user_email = f"user-{uuid.uuid4().hex}@example.invalid"
    user_password = "Aa9!" + secrets.token_urlsafe(24)
    operator_email = f"operator-{uuid.uuid4().hex}@example.invalid"
    operator_password = "Aa9!" + secrets.token_urlsafe(24)
    process = None
    try:
        process, base = e1.start_server(e1.available_port(), admin_email, admin_password, True)
        anonymous = ApiBrowser(base)
        for method, path, payload in (
            ("GET", "api/permissions", None),
            ("GET", "api/permissions/1", None),
            ("POST", "api/permissions", {"code": "anonymous.read", "name": "Anonymous"}),
            ("PUT", "api/permissions/1", {"name": "Anonymous"}),
            ("DELETE", "api/permissions/1", None),
            ("GET", "api/roles/missing/permissions", None),
            ("POST", "api/roles/missing/permissions/1", None),
            ("DELETE", "api/roles/missing/permissions/1", None),
        ):
            assert anonymous.api(method, path, payload)[0] == 401, (method, path)
        print("anonymous permission and role-permission APIs: 401")

        user, user_id = register_user(base, user_email, user_password)
        operator, operator_id = register_user(base, operator_email, operator_password)
        for method, path, payload in (
            ("GET", "api/permissions", None),
            ("POST", "api/permissions", {"code": "forbidden.read", "name": "Forbidden"}),
            ("GET", "api/roles/missing/permissions", None),
            ("POST", "api/roles/missing/permissions/1", None),
        ):
            assert user.mutate(method, path, payload)[0] == 403, (method, path)
        print("ordinary authenticated User permission APIs: 403")

        admin = ApiBrowser(base)
        admin.login(admin_email, admin_password)
        status, _, first_page = admin.api("GET", "api/permissions?page=1&pageSize=5")
        assert status == 200 and first_page["totalCount"] == 12 and len(first_page["items"]) == 5
        assert admin.api("GET", "api/permissions?page=0&pageSize=10")[0] == 400
        assert admin.api("GET", "api/permissions?page=1&pageSize=51")[0] == 400
        assert admin.api("GET", "api/permissions/999999")[0] == 404
        system_permissions = admin.api("GET", "api/permissions?page=1&pageSize=50")[2]["items"]
        assert {item["code"] for item in system_permissions} == SYSTEM_CODES
        assert all(item["isSystem"] for item in system_permissions)
        users_read = next(item for item in system_permissions if item["code"] == "users.read")

        create_payload = {
            "code": "Reports.Read",
            "name": "Consultar reportes",
            "description": "Permite consultar reportes del sistema.",
        }
        assert admin.api("POST", "api/permissions", create_payload)[0] == 400
        assert admin.api("POST", "api/permissions", create_payload, "invalid-token")[0] == 400
        assert admin.mutate("POST", "api/permissions", {"code": "single", "name": "Invalid"})[0] == 400
        assert admin.mutate("POST", "api/permissions", {"code": "bad..code", "name": "Invalid"})[0] == 400
        assert admin.mutate("POST", "api/permissions", {"code": "valid.code", "name": ""})[0] == 400
        assert admin.mutate("POST", "api/permissions", {
            "code": "valid.code", "name": "Valid", "description": "x" * 501,
        })[0] == 400
        assert admin.mutate("POST", "api/permissions", {
            "code": "USERS.READ", "name": "Reserved",
        })[0] == 409
        assert admin.mutate("POST", "api/permissions", {
            **create_payload, "roles": ["Admin"],
        })[0] == 400

        status, headers, custom = admin.mutate("POST", "api/permissions", create_payload)
        assert status == 201, (status, custom)
        assert headers.get("Location", "").endswith(str(custom["id"]))
        assert custom == {
            "id": custom["id"],
            "code": "reports.read",
            "name": "Consultar reportes",
            "description": "Permite consultar reportes del sistema.",
            "isSystem": False,
            "roleCount": 0,
        }
        assert admin.mutate("POST", "api/permissions", {
            "code": "reports.read", "name": "Duplicate",
        })[0] == 409
        assert admin.api("GET", "api/permissions?search=report")[2]["totalCount"] == 1
        assert admin.api("GET", f"api/permissions/{custom['id']}")[2] == custom

        assert admin.api("PUT", f"api/permissions/{custom['id']}", {"name": "No CSRF"})[0] == 400
        assert admin.mutate("PUT", f"api/permissions/{custom['id']}", {
            "name": "Changed", "code": "changed.code",
        })[0] == 400
        assert admin.mutate("PUT", f"api/permissions/{custom['id']}", {"name": ""})[0] == 400
        status, _, updated = admin.mutate("PUT", f"api/permissions/{custom['id']}", {
            "name": "Consultar reportes actualizados", "description": "Descripción actualizada",
        })
        assert status == 200 and updated["code"] == "reports.read"
        assert updated["name"] == "Consultar reportes actualizados"
        assert admin.mutate("PUT", f"api/permissions/{users_read['id']}", {
            "name": "Changed", "description": "Changed",
        })[0] == 409
        assert admin.mutate("DELETE", f"api/permissions/{users_read['id']}")[0] == 409

        disposable_status, _, disposable = admin.mutate("POST", "api/permissions", {
            "code": "temporary.delete", "name": "Temporal",
        })
        assert disposable_status == 201
        assert admin.mutate("DELETE", f"api/permissions/{disposable['id']}")[0] == 204
        assert admin.api("GET", f"api/permissions/{disposable['id']}")[0] == 404
        print("permission CRUD, normalization, mass assignment, system protection and CSRF: ok")

        roles = admin.api("GET", "api/roles?page=1&pageSize=50")[2]["items"]
        admin_role = next(role for role in roles if role["name"] == "Admin")
        user_role = next(role for role in roles if role["name"] == "User")
        target_role = create_role(admin, "E4Target")
        status, _, matrix = admin.api("GET", f"api/roles/{target_role['id']}/permissions")
        assert status == 200 and matrix["roleId"] == target_role["id"]
        assert len(matrix["permissions"]) == 13
        assert not next(item for item in matrix["permissions"] if item["id"] == custom["id"])["assigned"]
        assert admin.api("GET", "api/roles/missing/permissions")[0] == 404
        assert admin.mutate("POST", f"api/roles/missing/permissions/{custom['id']}")[0] == 404
        assert admin.mutate("POST", f"api/roles/{target_role['id']}/permissions/999999")[0] == 404
        assert admin.api("POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 400
        assert admin.api(
            "POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}", token="invalid-token"
        )[0] == 400
        status, _, matrix = admin.mutate(
            "POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}")
        assert status == 200
        assert next(item for item in matrix["permissions"] if item["id"] == custom["id"])["assigned"]
        assert admin.mutate(
            "POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 409
        assert admin.api("GET", f"api/permissions/{custom['id']}")[2]["roleCount"] == 1
        assert admin.mutate("DELETE", f"api/permissions/{custom['id']}")[0] == 409
        assert admin.mutate(
            "DELETE", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 200
        assert admin.mutate(
            "DELETE", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 409

        admin_matrix = admin.api("GET", f"api/roles/{admin_role['id']}/permissions")[2]
        base_admin = [item for item in admin_matrix["permissions"] if item["isSystem"]]
        assert len(base_admin) == 12 and all(item["assigned"] and item["locked"] for item in base_admin)
        assert admin.mutate(
            "DELETE", f"api/roles/{admin_role['id']}/permissions/{users_read['id']}")[0] == 409
        assert admin.mutate(
            "POST", f"api/roles/{user_role['id']}/permissions/{users_read['id']}")[0] == 409
        assert admin.mutate(
            "POST", f"api/roles/{admin_role['id']}/permissions/{custom['id']}")[0] == 200
        assert admin.mutate(
            "DELETE", f"api/roles/{admin_role['id']}/permissions/{custom['id']}")[0] == 200
        print("role-permission CRUD, missing resources, duplicate/revoke conflicts and protected roles: ok")

        roles_read_role = create_role(admin, "E4RolesRead")
        permissions_read_role = create_role(admin, "E4PermissionsRead")
        grant_direct(roles_read_role["id"], "roles.read")
        grant_direct(permissions_read_role["id"], "permissions.read")
        assert admin.mutate(
            "POST", f"api/users/{user_id}/roles/{roles_read_role['id']}")[0] == 200
        assert user.api("GET", f"api/roles/{target_role['id']}/permissions")[0] == 403
        assert admin.mutate(
            "POST", f"api/users/{user_id}/roles/{permissions_read_role['id']}")[0] == 200
        assert user.api("GET", f"api/roles/{target_role['id']}/permissions")[0] == 200

        roles_update_role = create_role(admin, "E4RolesUpdate")
        permissions_update_role = create_role(admin, "E4PermissionsUpdate")
        grant_direct(roles_update_role["id"], "roles.update")
        grant_direct(permissions_update_role["id"], "permissions.update")
        assert admin.mutate(
            "POST", f"api/users/{operator_id}/roles/{roles_update_role['id']}")[0] == 200
        assert operator.mutate(
            "POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 403
        assert admin.mutate(
            "POST", f"api/users/{operator_id}/roles/{permissions_update_role['id']}")[0] == 200
        assert operator.mutate(
            "POST", f"api/roles/{target_role['id']}/permissions/{custom['id']}")[0] == 409
        print("combined policies require both permissions and a live Admin operator: ok")

        dynamic_role = create_role(admin, "E4Dynamic")
        assert admin.mutate("POST", f"api/users/{user_id}/roles/{dynamic_role['id']}")[0] == 200
        assert admin.mutate(
            "POST", f"api/roles/{dynamic_role['id']}/permissions/{custom['id']}")[0] == 200
        capabilities = user.api("GET", "api/security/capabilities")[2]
        assert "reports.read" in capabilities
        assert user.api("GET", "api/users")[0] == 403
        assert admin.mutate(
            "POST", f"api/roles/{dynamic_role['id']}/permissions/{users_read['id']}")[0] == 200
        assert user.api("GET", "api/users")[0] == 200
        assert admin.mutate(
            "DELETE", f"api/roles/{dynamic_role['id']}/permissions/{users_read['id']}")[0] == 200
        assert user.api("GET", "api/users")[0] == 403
        assert admin.mutate(
            "DELETE", f"api/roles/{dynamic_role['id']}/permissions/{custom['id']}")[0] == 200
        assert "reports.read" not in user.api("GET", "api/security/capabilities")[2]
        print("dynamic grant/revoke takes effect on the next request without a new login: ok")

        assert admin.mutate("DELETE", f"api/permissions/{custom['id']}")[0] == 204
        with e1.database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("select count(*) from Permissions").fetchone() == (12,)
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []

        e1.stop_server(process)
        process = None
        process, _ = e1.start_server(e1.available_port(), admin_email, admin_password, False)
        with e1.database() as db:
            admin_system_count = db.execute(
                """select count(*) from RolePermissions rp
                   join AspNetRoles r on r.Id=rp.RoleId
                   join Permissions p on p.Id=rp.PermissionId
                   where r.NormalizedName='ADMIN'"""
            ).fetchone()[0]
            dynamic_users_read = db.execute(
                """select count(*) from RolePermissions rp
                   join Permissions p on p.Id=rp.PermissionId
                   where rp.RoleId=? and p.Code='users.read'""",
                (dynamic_role["id"],),
            ).fetchone()[0]
            assert admin_system_count == 12 and dynamic_users_read == 0
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
        print("RBAC initialization is idempotent and does not restore custom-role assignments: ok")
    finally:
        if process is not None and process.poll() is None:
            e1.stop_server(process)
        assert e1.DATABASE.resolve().is_relative_to((e1.SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            e1.DATABASE.with_name(e1.DATABASE.name + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    run()
