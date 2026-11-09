"""E3 role and user-role integration test using an isolated SQLite database."""

import secrets
import urllib.parse
import uuid

import e1_smoke as e1
from e2_users_smoke import ApiBrowser


e1.DATABASE = e1.SERVER / "Data" / f"e3-smoke-{uuid.uuid4().hex}.db"


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


def grant_permission(role_id, code):
    with e1.database() as db:
        permission_id = db.execute("select Id from Permissions where Code=?", (code,)).fetchone()[0]
        db.execute("insert into RolePermissions(RoleId,PermissionId) values (?,?)", (role_id, permission_id))


def remove_role_permissions(role_id):
    with e1.database() as db:
        db.execute("delete from RolePermissions where RoleId=?", (role_id,))


def run():
    assert e1.APP.exists(), "Build the solution before running the E3 smoke test"
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
            ("GET", "api/roles", None),
            ("GET", "api/roles/missing", None),
            ("POST", "api/roles", {"name": "AnonymousRole"}),
            ("PUT", "api/roles/missing", {"name": "AnonymousRole"}),
            ("DELETE", "api/roles/missing", None),
            ("GET", "api/users/missing/roles", None),
            ("POST", "api/users/missing/roles/missing", None),
            ("DELETE", "api/users/missing/roles/missing", None),
        ):
            assert anonymous.api(method, path, payload)[0] == 401, (method, path)
        print("anonymous role and user-role APIs: 401")

        user, user_id = register_user(base, user_email, user_password)
        operator, operator_id = register_user(base, operator_email, operator_password)
        for method, path, payload in (
            ("GET", "api/roles", None),
            ("POST", "api/roles", {"name": "NoAccess"}),
            ("GET", f"api/users/{user_id}/roles", None),
            ("POST", f"api/users/{user_id}/roles/missing", None),
        ):
            assert user.mutate(method, path, payload)[0] == 403, (method, path)
        print("ordinary authenticated User role APIs: 403")

        admin = ApiBrowser(base)
        admin.login(admin_email, admin_password)
        admin_id = admin.api("GET", "api/auth/me")[2]["id"]
        status, _, role_page = admin.api("GET", "api/roles?page=1&pageSize=1")
        assert status == 200 and role_page["totalCount"] == 2 and len(role_page["items"]) == 1
        protected = admin.api("GET", "api/roles?page=1&pageSize=10")[2]["items"]
        admin_role = next(role for role in protected if role["name"] == "Admin")
        user_role = next(role for role in protected if role["name"] == "User")
        assert admin_role["isProtected"] and user_role["isProtected"]
        assert admin.api("GET", f"api/roles/{admin_role['id']}")[2]["userCount"] == 1
        assert admin.api("GET", "api/roles/missing")[0] == 404

        assert admin.api("POST", "api/roles", {"name": "NoCsrf"})[0] == 400
        assert admin.api("POST", "api/roles", {"name": "NoCsrf"}, "invalid-token")[0] == 400
        assert admin.mutate("POST", "api/roles", {"name": ""})[0] == 400
        assert admin.mutate("POST", "api/roles", {"name": "bad role"})[0] == 400
        assert admin.mutate("POST", "api/roles", {"name": "ADMIN"})[0] == 409
        assert admin.mutate("POST", "api/roles", {"name": "user"})[0] == 409
        assert admin.mutate("POST", "api/roles", {"name": "Forged", "permissions": ["users.read"]})[0] == 400

        temporary = create_role(admin, "Temporary")
        assert temporary["userCount"] == 0 and not temporary["isProtected"]
        assert admin.mutate("POST", "api/roles", {"name": "temporary"})[0] == 409
        assert admin.api("GET", "api/roles?search=tempor")[2]["totalCount"] == 1
        renamed_status, _, renamed = admin.mutate(
            "PUT", f"api/roles/{temporary['id']}", {"name": "TemporaryRenamed"})
        assert renamed_status == 200 and renamed["name"] == "TemporaryRenamed"
        assert admin.mutate("PUT", f"api/roles/{temporary['id']}", {"name": "Admin"})[0] == 409
        for protected_role in (admin_role, user_role):
            assert admin.mutate("PUT", f"api/roles/{protected_role['id']}", {"name": "Changed"})[0] == 409
            assert admin.mutate("DELETE", f"api/roles/{protected_role['id']}")[0] == 409
        assert admin.mutate("DELETE", f"api/roles/{temporary['id']}")[0] == 204
        assert admin.api("GET", f"api/roles/{temporary['id']}")[0] == 404
        print("role CRUD, validation, normalization, protected roles, CSRF and safe delete: ok")

        assigned_role = create_role(admin, "AssignedRole")
        status, _, assignments = admin.api("GET", f"api/users/{user_id}/roles")
        assert status == 200 and next(r for r in assignments["roles"] if r["name"] == "User")["assigned"]
        assert admin.api("GET", "api/users/missing/roles")[0] == 404
        assert admin.mutate("POST", f"api/users/{user_id}/roles/missing")[0] == 404
        assert admin.api("POST", f"api/users/{user_id}/roles/{assigned_role['id']}")[0] == 400
        status, _, assignments = admin.mutate(
            "POST", f"api/users/{user_id}/roles/{assigned_role['id']}")
        assert status == 200 and next(r for r in assignments["roles"] if r["id"] == assigned_role["id"])["assigned"]
        assert admin.mutate("POST", f"api/users/{user_id}/roles/{assigned_role['id']}")[0] == 409
        assert admin.mutate("DELETE", f"api/roles/{assigned_role['id']}")[0] == 409
        renamed_status, _, renamed = admin.mutate(
            "PUT", f"api/roles/{assigned_role['id']}", {"name": "AssignedRenamed"})
        assert renamed_status == 200
        assignments = admin.api("GET", f"api/users/{user_id}/roles")[2]
        assert next(r for r in assignments["roles"] if r["id"] == assigned_role["id"])["name"] == "AssignedRenamed"
        assert admin.mutate("DELETE", f"api/users/{user_id}/roles/{assigned_role['id']}")[0] == 200
        assert admin.mutate("DELETE", f"api/users/{user_id}/roles/{assigned_role['id']}")[0] == 409
        assert admin.mutate("DELETE", f"api/roles/{assigned_role['id']}")[0] == 204
        print("user-role query, assign, duplicate, rename consistency, revoke and assigned-role delete conflict: ok")

        permission_role = create_role(admin, "PermissionBound")
        grant_permission(permission_role["id"], "users.read")
        assert admin.mutate("DELETE", f"api/roles/{permission_role['id']}")[0] == 409
        remove_role_permissions(permission_role["id"])
        assert admin.mutate("DELETE", f"api/roles/{permission_role['id']}")[0] == 204
        print("role deletion rejects RolePermission relations without deleting Permission: ok")

        users_read = create_role(admin, "DynamicUsersRead")
        roles_read = create_role(admin, "DynamicRolesRead")
        grant_permission(users_read["id"], "users.read")
        grant_permission(roles_read["id"], "roles.read")
        assert user.api("GET", "api/users")[0] == 403
        assert admin.mutate("POST", f"api/users/{user_id}/roles/{users_read['id']}")[0] == 200
        assert user.api("GET", "api/users")[0] == 200
        assert user.api("GET", f"api/users/{user_id}/roles")[0] == 403
        assert admin.mutate("POST", f"api/users/{user_id}/roles/{roles_read['id']}")[0] == 200
        assert user.api("GET", f"api/users/{user_id}/roles")[0] == 200
        assert admin.mutate("DELETE", f"api/users/{user_id}/roles/{users_read['id']}")[0] == 200
        assert user.api("GET", "api/users")[0] == 403
        assert user.api("GET", "api/roles")[0] == 200
        assert user.api("GET", f"api/users/{user_id}/roles")[0] == 403
        print("dynamic grants/revocation without new login and union across roles: ok")

        users_update = create_role(admin, "OperatorUsersUpdate")
        roles_update = create_role(admin, "OperatorRolesUpdate")
        grant_permission(users_update["id"], "users.update")
        grant_permission(roles_update["id"], "roles.update")
        assert admin.mutate("POST", f"api/users/{operator_id}/roles/{users_update['id']}")[0] == 200
        assert operator.mutate("POST", f"api/users/{user_id}/roles/{assigned_role['id']}")[0] == 403
        assert admin.mutate("POST", f"api/users/{operator_id}/roles/{roles_update['id']}")[0] == 200
        non_admin_role = create_role(admin, "CombinedPermissionTarget")
        assert operator.mutate("POST", f"api/users/{user_id}/roles/{non_admin_role['id']}")[0] == 200
        assert operator.mutate("DELETE", f"api/users/{user_id}/roles/{non_admin_role['id']}")[0] == 200
        assert operator.mutate("POST", f"api/users/{operator_id}/roles/{admin_role['id']}")[0] == 409
        assert operator.mutate("POST", f"api/users/{user_id}/roles/{admin_role['id']}")[0] == 409
        print("combined users.update + roles.update and live Admin-operator verification: ok")

        assert admin.mutate("POST", f"api/users/{admin_id}/roles/{admin_role['id']}")[0] == 409
        assert admin.mutate("DELETE", f"api/users/{admin_id}/roles/{admin_role['id']}")[0] == 409
        assert admin.mutate("POST", f"api/users/{user_id}/roles/{admin_role['id']}")[0] == 200
        assert admin.mutate("DELETE", f"api/users/{user_id}/roles/{admin_role['id']}")[0] == 200
        assert admin.api("GET", "api/admin/overview")[0] == 200
        print("Admin self-assignment/revocation blocked; controlled Admin grant/revoke preserves continuity: ok")

        with e1.database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
            assert db.execute("select count(*) from Permissions").fetchone() == (12,)
        print("SQLite integrity and unchanged permission catalog: ok")
    finally:
        if process is not None and process.poll() is None:
            e1.stop_server(process)
        assert e1.DATABASE.resolve().is_relative_to((e1.SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            e1.DATABASE.with_name(e1.DATABASE.name + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    run()
