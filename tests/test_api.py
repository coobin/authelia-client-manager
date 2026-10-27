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
                "INSERT INTO admins VALUES(?,?,?,?)",
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
