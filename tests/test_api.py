import json
import secrets
import pyotp
import pytest
from pathlib import Path
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from acm.main import create_app
from acm.storage import Storage
from acm.common import now
from agent.engine import Engine
from tests.test_engine import wait


class LocalAgent:
    def __init__(self, e):
        self.e = e

    def call(self, method, path, data=None):
        from acm.models import AgentChange

        if path == "/inventory":
            return self.e.inventory()
        if path == "/jobs":
            return self.e.jobs()
        if path == "/validate":
            return self.e.validate(AgentChange.model_validate(data))
        if path == "/deploy":
            return self.e.deploy(AgentChange.model_validate(data))


@pytest.fixture
def system(tmp_path):
    key = tmp_path / "master.key"
    key.write_bytes(secrets.token_bytes(32))
    s = Storage(tmp_path / "web.sqlite", key)
    seed = pyotp.random_base32()
    pwd = "a-long-testing-password"
    with s.connect() as c:
        for user, role in [("admin", "admin"), ("reader", "viewer")]:
            c.execute(
                "INSERT INTO admins(username,password,totp,role,totp_enabled) VALUES(?,?,?,?,1)",
                (
                    user,
                    PasswordHasher().hash(pwd),
                    s.encrypt(seed, "totp:" + user),
                    role,
                ),
            )
    cfg = tmp_path / "configuration.yml"
    cfg.write_text(Path("examples/configuration.yml").read_text())
    e = Engine(cfg, tmp_path / "state", demo=True, writable=True)
    client = TestClient(
        create_app(s, LocalAgent(e), origin="http://testserver", secure=False)
    )
    client.headers["Origin"] = "http://testserver"
    return client, s, e, seed, pwd


def login(system, user="admin"):
    c, s, e, seed, pwd = system
    r = c.post(
        "/api/login",
        json={"username": user, "password": pwd, "code": pyotp.TOTP(seed).now()},
    )
    assert r.status_code == 200
    rj = r.json()
    c.headers["X-CSRF-Token"] = rj["csrf"]
    return c


def test_authentication_required(system):
    assert system[0].get("/api/clients").status_code == 401


def test_bad_origin_rejected(system):
    c = system[0]
    c.headers["Origin"] = "https://evil.example.com"
    assert c.post("/api/login", json={}).status_code == 403


def test_csrf_required(system):
    c = login(system)
    del c.headers["X-CSRF-Token"]
    assert c.post("/api/logout", json={}).status_code == 403


def test_viewer_cannot_write(system):
    c = login(system, "reader")
    assert c.post("/api/drafts", json={}).status_code == 403


def test_validation_error_does_not_echo_password(system):
    c = system[0]
    r = c.post(
        "/api/login",
        json={"username": "admin", "password": "sensitive-value", "code": "invalid"},
    )
    assert r.status_code == 422
    assert "sensitive-value" not in r.text


def test_login_password_totp_both_required(system):
    c, s, e, seed, pwd = system
    assert (
        c.post(
            "/api/login", json={"username": "admin", "password": pwd, "code": "000000"}
        ).status_code
        == 401
    )


def test_full_secret_lifecycle(system):
    c = login(system)
    inv = c.get("/api/clients").json()
    payload = {
        "revision": inv["revision"],
        "operation": "upsert",
        "environment": "production",
        "owner": "Example owner",
        "client": {
            "client_id": "new-private",
            "client_name": "New app",
            "redirect_uris": ["https://app.example.com/callback"],
        },
    }
    r = c.post("/api/drafts", json=payload)
    assert r.status_code == 200
    r = r.json()
    assert "secret" not in r
    assert (
        c.post("/api/deliveries/" + r["delivery_id"] + "/claim", json={}).status_code
        == 409
    )
    assert c.post("/api/drafts/" + r["id"] + "/validate", json={}).status_code == 200
    assert (
        c.post(
            "/api/deployments", json={"draft_id": r["id"], "acknowledge_restart": True}
        ).status_code
        == 200
    )
    wait(system[2])
    secret = c.post("/api/deliveries/" + r["delivery_id"] + "/claim", json={}).json()[
        "secret"
    ]
    assert len(secret) == 72
    assert (
        c.post("/api/deliveries/" + r["delivery_id"] + "/claim", json={}).status_code
        == 410
    )
    for path in ["/api/clients", "/api/drafts", "/api/deployments", "/api/audit"]:
        assert secret not in c.get(path).text


def test_expired_reauth_blocks_publish(system):
    c = login(system)
    with system[1].connect() as db:
        db.execute("UPDATE sessions SET reauth=0")
    assert (
        c.post(
            "/api/deployments", json={"draft_id": "a" * 32, "acknowledge_restart": True}
        ).status_code
        == 403
    )


def test_security_headers(system):
    r = system[0].get("/api/health")
    assert r.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_production_http_rejected(system):
    c = login(system)
    inv = c.get("/api/clients").json()
    r = c.post(
        "/api/drafts",
        json={
            "revision": inv["revision"],
            "client": {
                "client_id": "a",
                "client_name": "a",
                "redirect_uris": ["http://example.com/callback"],
            },
        },
    )
    assert r.status_code == 422


def empty_system(system):
    with system[1].connect() as c:
        c.execute("DELETE FROM admins")
        c.execute("DELETE FROM sessions")
    return system[0]


def setup_body(username="chosen-admin"):
    return {
        "username": username,
        "password": "chosen-long-password",
        "confirm_password": "chosen-long-password",
    }


def test_fresh_install_web_setup_and_password_login(system):
    c = empty_system(system)
    assert c.get("/api/auth/status").json() == {"setup_required": True}
    r = c.post("/api/setup", json=setup_body())
    assert r.status_code == 200
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    assert c.get("/api/me").json()["totp_enabled"] == 0
    assert c.get("/api/auth/status").json() == {"setup_required": False}
    assert c.post("/api/setup", json=setup_body("another-admin")).status_code == 409
    c.post("/api/logout", json={})
    assert (
        c.post(
            "/api/login",
            json={"username": "chosen-admin", "password": "chosen-long-password"},
        ).status_code
        == 200
    )


def test_setup_password_confirmation_and_strength(system):
    c = empty_system(system)
    body = setup_body()
    body["confirm_password"] = "different-long-password"
    assert c.post("/api/setup", json=body).status_code == 422
    assert (
        c.post(
            "/api/setup",
            json={"username": "abc", "password": "1234567", "confirm_password": "1234567"},
        ).status_code
        == 422
    )
    assert c.get("/api/auth/status").json()["setup_required"]
    assert (
        c.post(
            "/api/setup",
            json={"username": "abc", "password": "12345678", "confirm_password": "12345678"},
        ).status_code
        == 200
    )
    assert not c.get("/api/auth/status").json()["setup_required"]


def test_setup_rejects_cross_origin(system):
    c = empty_system(system)
    c.headers["Origin"] = "https://evil.example.com"
    assert c.post("/api/setup", json=setup_body()).status_code == 403
    assert c.get("/api/auth/status").json()["setup_required"]


def test_password_only_reauth_when_totp_disabled(system):
    c = empty_system(system)
    r = c.post("/api/setup", json=setup_body())
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    with system[1].connect() as db:
        db.execute("UPDATE sessions SET reauth=0")
    assert (
        c.post("/api/reauth", json={"password": "chosen-long-password"}).status_code
        == 200
    )


def test_totp_opt_in_confirm_and_disable(system):
    c = empty_system(system)
    r = c.post("/api/setup", json=setup_body())
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    r = c.post("/api/settings/totp/begin", json={"password": "chosen-long-password"})
    assert r.status_code == 200
    seed = r.json()["secret"]
    assert "otpauth://" in r.json()["uri"]
    assert not c.get("/api/settings/security").json()["totp_enabled"]
    invalid = next(
        str(i).zfill(6)
        for i in range(100)
        if not pyotp.TOTP(seed).verify(str(i).zfill(6), valid_window=1)
    )
    assert (
        c.post("/api/settings/totp/confirm", json={"code": invalid}).status_code == 400
    )
    assert not c.get("/api/me").json()["totp_enabled"]
    code = pyotp.TOTP(seed).now()
    assert c.post("/api/settings/totp/confirm", json={"code": code}).status_code == 200
    assert c.get("/api/me").json()["totp_enabled"] == 1
    login_result = c.post(
        "/api/login",
        json={"username": "chosen-admin", "password": "chosen-long-password"},
    )
    assert (
        login_result.status_code == 401
        and login_result.headers["X-ACM-TOTP-Required"] == "1"
    )
    assert (
        c.post(
            "/api/settings/totp/disable",
            json={"password": "chosen-long-password", "code": invalid},
        ).status_code
        == 401
    )
    assert (
        c.post(
            "/api/settings/totp/disable",
            json={"password": "chosen-long-password", "code": code},
        ).status_code
        == 200
    )
    assert not c.get("/api/me").json()["totp_enabled"]
    assert (
        c.post(
            "/api/login",
            json={"username": "chosen-admin", "password": "chosen-long-password"},
        ).status_code
        == 200
    )
    for path in ["/api/me", "/api/settings/security", "/api/audit"]:
        assert seed not in c.get(path).text


def test_wrong_password_does_not_disclose_totp_status(system):
    r = system[0].post(
        "/api/login", json={"username": "admin", "password": "wrong-password"}
    )
    assert r.status_code == 401 and "X-ACM-TOTP-Required" not in r.headers


def test_totp_settings_require_auth_and_csrf(system):
    c = system[0]
    assert (
        c.post(
            "/api/settings/totp/begin", json={"password": "some-password"}
        ).status_code
        == 401
    )
    c = login(system)
    del c.headers["X-CSRF-Token"]
    assert (
        c.post(
            "/api/settings/totp/disable",
            json={"password": system[4], "code": pyotp.TOTP(system[3]).now()},
        ).status_code
        == 403
    )


def test_pending_setup_preserves_application_records(system):
    c, s, *_ = system
    with s.connect() as db:
        db.execute("DELETE FROM admins WHERE username='reader'")
        db.execute(
            "UPDATE admins SET needs_setup=1,totp_enabled=0,totp=NULL WHERE username='admin'"
        )
        db.execute(
            "INSERT INTO metadata VALUES('existing-app','Example owner','production')"
        )
    assert c.get("/api/auth/status").json()["setup_required"]
    r = c.post("/api/setup", json=setup_body())
    assert r.status_code == 200
    with s.connect() as db:
        assert db.execute("SELECT count(*) FROM admins").fetchone()[0] == 1
        assert db.execute("SELECT owner FROM metadata").fetchone()[0] == "Example owner"


def test_parallel_setup_creates_exactly_one_admin(system):
    from concurrent.futures import ThreadPoolExecutor

    c = empty_system(system)

    def create(name):
        with TestClient(c.app) as other:
            return other.post(
                "/api/setup",
                json=setup_body(name),
                headers={"Origin": "http://testserver"},
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, ["first-admin", "second-admin"]))
    assert sorted(results) == [200, 409]
    with system[1].connect() as db:
        assert db.execute("SELECT count(*) FROM admins").fetchone()[0] == 1


def test_new_data_directory_initializes_in_browser(tmp_path):
    from acm.storage import open_storage

    s = open_storage(tmp_path / "new")
    with s.connect() as db:
        assert s.setup_required(db)
    assert (tmp_path / "new" / "master.key").stat().st_mode & 0o777 == 0o600


def test_legacy_totp_is_preserved_until_explicitly_changed(tmp_path):
    import sqlite3

    key = tmp_path / "key"
    key.write_bytes(secrets.token_bytes(32))
    db = tmp_path / "legacy.sqlite"
    with sqlite3.connect(db) as c:
        c.execute(
            "CREATE TABLE admins(username TEXT PRIMARY KEY,password TEXT,totp BLOB,role TEXT)"
        )
        c.execute(
            "INSERT INTO admins VALUES(?,?,?,?)",
            ("legacy", "hash", b"old-encrypted-seed", "admin"),
        )
    s = Storage(db, key)
    with s.connect() as c:
        row = c.execute("SELECT * FROM admins").fetchone()
        assert row["totp_enabled"] == 1 and row["needs_setup"] == 0


def test_cli_password_length(tmp_path, monkeypatch):
    import sys
    from acm.cli import main
    from acm.storage import open_storage

    data_dir = str(tmp_path / "cli_data")
    open_storage(data_dir)

    monkeypatch.setattr(sys, "argv", ["acm.cli", "create-admin", "--data", data_dir, "--username", "admin1"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: "1234567")
    import pytest
    with pytest.raises(SystemExit) as exc:
        main()
    assert "Password must contain at least 8 characters" in str(exc.value)

    monkeypatch.setattr(sys, "argv", ["acm.cli", "create-admin", "--data", data_dir, "--username", "admin2"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: "12345678")
    main()



def test_missing_master_key_never_silently_replaced(tmp_path):
    from acm.storage import open_storage

    (tmp_path / "web.sqlite").touch()
    with pytest.raises(RuntimeError):
        open_storage(tmp_path)
    assert not (tmp_path / "master.key").exists()
