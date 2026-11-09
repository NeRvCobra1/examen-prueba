"""End-to-end E1 smoke test against a disposable local SQLite database."""

import http.cookiejar
import json
import os
import secrets
import socket
import sqlite3
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "ExamenPrueba"
DATABASE = SERVER / "Data" / f"e1-smoke-{uuid.uuid4().hex}.db"
APP = SERVER / "bin" / "Debug" / "net10.0" / "ExamenPrueba.dll"
CONTEXT = ssl._create_unverified_context()  # TLS trust is checked separately with curl.


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self.current = {"action": attributes.get("action", ""), "fields": {}}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            if attributes.get("name") and attributes.get("type") == "hidden":
                self.current["fields"][attributes["name"]] = attributes.get("value", "")
        elif tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def start_server(port, admin_email, admin_password, bootstrap, extra_environment=None):
    environment = os.environ.copy()
    environment.update(
        ASPNETCORE_ENVIRONMENT="Development",
        ASPNETCORE_URLS=f"https://localhost:{port}",
        ConnectionStrings__DefaultConnection=f"DataSource=Data/{DATABASE.name};Cache=Shared",
        Application__PublicOrigin=f"https://localhost:{port}",
        AdminBootstrap__Enabled=str(bootstrap).lower(),
        AdminBootstrap__Email=admin_email,
        AdminBootstrap__Password=admin_password,
        RateLimiting__Registration__PermitLimit="1000",
        RateLimiting__AdministrativeRead__PermitLimit="1000",
        RateLimiting__AdministrativeMutation__PermitLimit="1000",
        Logging__LogLevel__Microsoft_EntityFrameworkCore_Database_Command="Warning",
        Logging__EventLog__LogLevel__Default="None",
    )
    if extra_environment:
        environment.update(extra_environment)
    process = subprocess.Popen(
        ["dotnet", str(APP)],
        cwd=SERVER,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    base = f"https://localhost:{port}/"
    for _ in range(300):
        if process.poll() is not None:
            raise RuntimeError(f"Server exited during startup with code {process.returncode}")
        try:
            with urllib.request.urlopen(base, context=CONTEXT, timeout=1) as response:
                if response.status == 200:
                    return process, base
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    stop_server(process)
    raise RuntimeError("Server did not become ready after 60 seconds")


def stop_server(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


class Browser:
    def __init__(self, base):
        self.base = base
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=CONTEXT),
        )

    def request(self, path, fields=None):
        url = urllib.parse.urljoin(self.base, path)
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(url, data=data)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode("utf-8")
            page = Page()
            page.feed(body)
            return response.status, urllib.parse.urlsplit(response.url).path, response.headers, page, body

    def login(self, email, password):
        status, _, _, page, _ = self.request("Account/Login")
        assert status == 200
        form = next(form for form in page.forms if form["action"] == "/Account/Login")
        return self.request(form["action"], {
            **form["fields"], "Input.Email": email, "Input.Password": password
        })


def counts():
    with database() as db:
        return tuple(db.execute(f"select count(*) from {table}").fetchone()[0] for table in (
            "AspNetUsers", "AspNetRoles", "Permissions", "RolePermissions"
        ))


@contextmanager
def database():
    connection = sqlite3.connect(DATABASE)
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def run():
    assert APP.exists(), "Build the solution before running the E1 smoke test"
    assert not DATABASE.exists()
    admin_email = f"admin-{uuid.uuid4().hex}@example.invalid"
    admin_password = "Aa9!" + secrets.token_urlsafe(24)
    user_email = f"user-{uuid.uuid4().hex}@example.invalid"
    user_password = "Aa9!" + secrets.token_urlsafe(24)
    port = available_port()
    process = None
    try:
        process, base = start_server(port, admin_email, admin_password, True)
        anonymous = Browser(base)
        for path in ("api/auth/me", "api/security/capabilities", "api/admin/overview"):
            status, _, _, _, _ = anonymous.request(path)
            assert status == 401, (path, status)
        status, path, _, _, _ = anonymous.request("dashboard")
        assert status == 200 and path == "/Account/Login"
        print("anonymous API 401 and dashboard login redirect: ok")

        user = Browser(base)
        _, _, _, page, _ = user.request("Account/Register")
        form = next(form for form in page.forms if form["action"] == "/Account/Register")
        status, path, _, page, _ = user.request(form["action"], {
            **form["fields"], "Input.Email": user_email,
            "Input.Password": user_password, "Input.ConfirmPassword": user_password,
            "Role": "Admin", "Input.Role": "Admin"
        })
        assert status == 200 and path == "/Account/RegisterConfirmation"
        confirmation = next(link for link in page.links if "/Account/ConfirmEmail?" in link)
        with database() as db:
            assert db.execute("select EmailConfirmed from AspNetUsers where Email=?", (user_email,)).fetchone() == (0,)
            roles = db.execute("select r.Name from AspNetRoles r join AspNetUserRoles ur on ur.RoleId=r.Id join AspNetUsers u on u.Id=ur.UserId where u.Email=?", (user_email,)).fetchall()
            assert roles == [("User",)], roles
        user.request(confirmation)
        with database() as db:
            assert db.execute("select EmailConfirmed from AspNetUsers where Email=?", (user_email,)).fetchone() == (1,)
        user.login(user_email, user_password)
        status, _, _, _, body = user.request("api/auth/me")
        assert status == 200 and json.loads(body)["roles"] == ["User"]
        status, _, _, _, body = user.request("api/security/capabilities")
        assert status == 200 and json.loads(body) == []
        status, _, _, _, _ = user.request("api/admin/overview")
        assert status == 403
        status, path, _, page, _ = user.request("Account/Manage")
        assert status == 200 and path == "/Account/Manage"
        status, path, _, _, _ = user.request("dashboard")
        assert status == 200 and path == "/dashboard"
        logout = next(form for form in page.forms if "Account/Logout" in form["action"])
        user.request(logout["action"], logout["fields"])
        assert user.request("api/auth/me")[0] == 401
        print("public registration, User-only role, confirmation, login/logout, 403: ok")

        admin = Browser(base)
        admin.login(admin_email, admin_password)
        status, _, _, _, body = admin.request("api/auth/me")
        assert status == 200 and json.loads(body)["roles"] == ["Admin"]
        status, _, _, _, body = admin.request("api/security/capabilities")
        assert status == 200 and len(json.loads(body)) == 12
        assert admin.request("api/admin/overview")[0] == 200
        with database() as db:
            db.execute("pragma foreign_keys=on")
            role_id, permission_id = db.execute("select rp.RoleId,rp.PermissionId from RolePermissions rp join Permissions p on p.Id=rp.PermissionId where p.Code='users.read'").fetchone()
            db.execute("delete from RolePermissions where RoleId=? and PermissionId=?", (role_id, permission_id))
        assert admin.request("api/admin/overview")[0] == 403
        with database() as db:
            db.execute("insert into RolePermissions(RoleId,PermissionId) values (?,?)", (role_id, permission_id))
        assert admin.request("api/admin/overview")[0] == 200
        print("Admin 200 and immediate permission revocation/restoration: ok")

        first_counts = counts()
        assert first_counts == (2, 2, 12, 12), first_counts
        stop_server(process)
        process, base = start_server(port, admin_email, admin_password, True)
        assert counts() == first_counts
        stop_server(process)
        process, base = start_server(port, admin_email, admin_password, False)
        assert counts() == first_counts
        print("idempotent initialization with bootstrap enabled, then disabled: ok")

        rate_browser = Browser(base)
        for _ in range(8):
            assert rate_browser.request("Account/Login")[0] == 200
        for attempt in range(6):
            status, _, _, page, _ = rate_browser.request("Account/Login")
            form = next(form for form in page.forms if form["action"] == "/Account/Login")
            status, _, headers, _, _ = rate_browser.request(form["action"], {
                **form["fields"], "Input.Email": user_email, "Input.Password": "Wrong9!Password"
            })
            assert status == (200 if attempt < 5 else 429), (attempt, status)
            if attempt == 5:
                assert int(headers.get("Retry-After", "0")) > 0
        assert rate_browser.request("Account/Login")[0] == 200
        print("real POST /Account/Login: five allowed, sixth 429 with Retry-After; GET unlimited: ok")

        with database() as db:
            db.execute("pragma foreign_keys=on")
            assert db.execute("pragma integrity_check").fetchone() == ("ok",)
            assert db.execute("pragma foreign_key_check").fetchall() == []
            assert db.execute("select count(distinct Code) from Permissions").fetchone() == (12,)
            assert db.execute("select count(*) from AspNetUserPasskeys").fetchone() == (0,)
            try:
                db.execute("insert into Permissions(Code,Name) values ('users.read','Duplicate')")
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError("Permission.Code unique index was not enforced")
            try:
                db.execute("insert into RolePermissions(RoleId,PermissionId) values ('missing-role',-1)")
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError("RolePermission foreign keys were not enforced")
        print("SQLite integrity, RBAC relations, passkey table: ok")
    finally:
        if process is not None and process.poll() is None:
            stop_server(process)
        assert DATABASE.resolve().is_relative_to((SERVER / "Data").resolve())
        for suffix in ("", "-shm", "-wal"):
            DATABASE.with_name(DATABASE.name + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    run()
