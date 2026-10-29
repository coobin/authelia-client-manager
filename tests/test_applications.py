from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from acm.common import now
from tests.test_api import system, login
from tests.test_engine import wait


@pytest.fixture(autouse=True)
def application_domain(monkeypatch):
    monkeypatch.setenv("ACM_APPLICATION_DOMAIN", "example.com")


def applicant(system, name="employee"):
    c, s, *_ = system
    with s.connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO admins(username,role,totp_enabled,needs_setup) VALUES(?,'applicant',0,0)",
            (name,),
        )
        db.execute(
            "INSERT OR IGNORE INTO applicants VALUES(?,?,?,?,?)",
            (name, "https://auth.example.com", name, name, name + "@example.com"),
        )
        db.execute(
            "INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?,?)",
            (name, name, name, now(), now(), now()),
        )
    from acm.common import digest

    with s.connect() as db:
        db.execute("UPDATE sessions SET id=? WHERE id=?", (digest(name.encode()), name))
    other = TestClient(c.app)
    other.cookies.set("acm_session", name)
    other.headers.update({"Origin": "http://testserver", "X-CSRF-Token": name})
    return other


def payload(**changes):
    return {
        "name": "Example service",
        "purpose": "Internal application",
        "department": "Example department",
        "business_owner": "Owner",
        "technical_owner": "Developer",
        "contact": "dev@example.com",
        "environment": "production",
        "app_type": "backend",
        "framework": "OIDC component",
        "access_url": "https://app.example.com",
        "redirect_uris": ["https://app.example.com/auth/callback"],
        "audience": "Employees",
        "roles": "Explicit administrator list",
        "groups": False,
        "sensitive": "No",
        "agreement": True,
        **changes,
    }


def create(c, **changes):
    r = c.post("/api/applications", json=payload(**changes))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def detail(c, aid):
    r = c.get("/api/applications/" + aid)
    assert r.status_code == 200, r.text
    return r.json()


def approve(admin, aid):
    r = admin.post(
        f"/api/applications/{aid}/review",
        json={
            "version": detail(admin, aid)["version"],
            "decision": "approve",
            "two_factor": True,
        },
    )
    assert r.status_code == 200, r.text


def publish(admin, aid, **extra):
    r = admin.post(
        f"/api/applications/{aid}/publish",
        json={
            "version": detail(admin, aid)["version"],
            "acknowledge_restart": True,
            **extra,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_application_full_flow_and_identity_isolation(system):
    employee = applicant(system)
    stranger = applicant(system, "other-employee")
    admin = login(system)
    aid = create(employee)
    assert stranger.get("/api/applications").json() == []
    assert stranger.get(f"/api/applications/{aid}").status_code == 404
    assert stranger.post(f"/api/applications/{aid}/claim", json={}).status_code == 404
    for path in ("/clients", "/drafts", "/deployments", "/audit", "/deliveries"):
        assert employee.get("/api" + path).status_code == 403
    assert (
        employee.post(
            f"/api/applications/{aid}/review",
            json={"version": 1, "decision": "approve"},
        ).status_code
        == 403
    )
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409
    approve(admin, aid)
    d = detail(employee, aid)
    assert (
        d["status"] == "approved"
        and d["approved"]["authorization_policy"] == "two_factor"
    )
    jid = publish(admin, aid)
    wait(system[2])
    d = detail(employee, aid)
    assert d["status"] == "ready" and d["delivery"]["ready"]
    assert employee.get("/api/applications").json()[0]["status"] == "ready"
    with system[1].connect() as db:
        did = db.execute(
            "SELECT id FROM deliveries WHERE draft_id=?", (jid,)
        ).fetchone()["id"]
    anon = TestClient(admin.app, headers={"Origin": "http://testserver"})
    assert anon.get(f"/api/claim/{did}").status_code == 404
    assert anon.post(f"/api/claim/{did}").status_code == 404
    assert admin.post(f"/api/deliveries/{did}/claim", json={}).status_code == 403
    assert admin.post(f"/api/applications/{aid}/claim", json={}).status_code == 403
    assert all(x["id"] != did for x in admin.get("/api/deliveries").json())
    result = employee.post(f"/api/applications/{aid}/claim", json={})
    assert result.status_code == 200, result.text
    secret = result.json()["secret"]
    assert len(secret) == 72
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 410
    for c in (admin, employee):
        for path in ("/applications", f"/applications/{aid}"):
            assert secret not in c.get("/api" + path).text
    assert secret not in admin.get("/api/audit").text
    assert (
        admin.post(
            f"/api/applications/{aid}/complete", json={"version": d["version"]}
        ).status_code
        == 409
    )
    results = (
        "Login, permission, employee suspension, logout and failure checks passed."
    )
    assert (
        employee.post(
            f"/api/applications/{aid}/acceptance",
            json={"version": d["version"], "results": results},
        ).status_code
        == 200
    )
    d = detail(admin, aid)
    assert (
        admin.post(
            f"/api/applications/{aid}/complete", json={"version": d["version"]}
        ).status_code
        == 200
    )
    assert detail(employee, aid)["status"] == "completed"


def test_return_resubmit_and_stale_review(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    assert (
        admin.post(
            f"/api/applications/{aid}/review", json={"version": 1, "decision": "return"}
        ).status_code
        == 422
    )
    assert (
        admin.post(
            f"/api/applications/{aid}/review",
            json={"version": 1, "decision": "return", "comment": "Clarify roles"},
        ).status_code
        == 200
    )
    assert (
        employee.post(
            f"/api/applications/{aid}/resubmit", json={**payload(), "version": 1}
        ).status_code
        == 409
    )
    assert (
        employee.post(
            f"/api/applications/{aid}/resubmit",
            json={**payload(roles="Updated role mapping"), "version": 2},
        ).status_code
        == 200
    )
    assert (
        admin.post(
            f"/api/applications/{aid}/review",
            json={"version": 1, "decision": "approve"},
        ).status_code
        == 409
    )
    approve(admin, aid)
    assert (
        employee.post(
            f"/api/applications/{aid}/resubmit", json={**payload(), "version": 4}
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "change",
    [
        {"access_url": "http://app.example.com"},
        {"redirect_uris": ["http://app.example.com/callback"]},
        {"agreement": False},
        {"department": " "},
        {"launch_date": "2026-02-31"},
        {"redirect_uris": ["https://app.example.com/*"]},
        {"approved": {}},
        {"applicant": "admin"},
    ],
)
def test_application_validation(system, change):
    assert (
        applicant(system).post("/api/applications", json=payload(**change)).status_code
        == 422
    )


def test_public_client_has_no_secret_and_default_scopes(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee, app_type="spa", groups=False)
    approve(admin, aid)
    assert detail(admin, aid)["approved"]["scopes"] == [
        "openid",
        "profile",
        "email",
        "groups",
    ]
    publish(admin, aid)
    wait(system[2])
    d = detail(employee, aid)
    assert d["status"] == "ready" and d["approved"]["public"] and d["delivery"] is None
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 410


def test_publish_reauth_and_acknowledgement(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    version = detail(admin, aid)["version"]
    assert (
        admin.post(
            f"/api/applications/{aid}/publish",
            json={"version": version, "acknowledge_restart": False},
        ).status_code
        == 400
    )
    with system[1].connect() as db:
        db.execute("UPDATE sessions SET reauth=0")
    assert (
        admin.post(
            f"/api/applications/{aid}/publish",
            json={"version": version, "acknowledge_restart": True},
        ).status_code
        == 403
    )


def test_concurrent_claim_and_reissue(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    publish(admin, aid)
    wait(system[2])
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: employee.post(f"/api/applications/{aid}/claim", json={}),
                range(2),
            )
        )
    assert sorted(r.status_code for r in responses) == [200, 410]
    old = next(r.json()["secret"] for r in responses if r.status_code == 200)
    publish(admin, aid, reissue=True)
    wait(system[2])
    d = detail(employee, aid)
    assert d["claimed_at"] is None and d["delivery"]["ready"]
    new = employee.post(f"/api/applications/{aid}/claim", json={}).json()["secret"]
    assert new != old
    with system[1].connect() as db:
        assert db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 0


def test_fail_closed_after_provider_changes_or_pruned_history(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    jid = publish(admin, aid)
    wait(system[2])
    system[2].update(jid, "rolled_back", "Recovery")
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409
    with system[2].db.connect() as db:
        db.execute("DELETE FROM jobs WHERE id=?", (jid,))
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409


def test_application_csrf_and_anonymous_access(system):
    anon = TestClient(system[0].app, headers={"Origin": "http://testserver"})
    assert anon.get("/api/applications").status_code == 401
    c = applicant(system)
    del c.headers["X-CSRF-Token"]
    assert c.post("/api/applications", json=payload()).status_code == 403


def test_validation_failure_can_retry_with_new_revision(system, monkeypatch):
    from fastapi import HTTPException

    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    agent = admin.app.state.agent
    original = agent.call

    def reject(method, path, data=None):
        if path == "/validate":
            raise HTTPException(409, "配置已变化")
        return original(method, path, data)

    monkeypatch.setattr(agent, "call", reject)
    r = admin.post(
        f"/api/applications/{aid}/publish",
        json={"version": 2, "acknowledge_restart": True},
    )
    assert r.status_code == 409
    assert detail(employee, aid)["status"] == "failed"
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409
    monkeypatch.setattr(agent, "call", original)
    publish(admin, aid)
    wait(system[2])
    assert detail(employee, aid)["status"] == "ready"


def test_lost_deploy_response_reconciles_without_second_registration(
    system, monkeypatch
):
    from fastapi import HTTPException

    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    agent = admin.app.state.agent
    original = agent.call

    def lost_response(method, path, data=None):
        result = original(method, path, data)
        if path == "/deploy":
            raise HTTPException(503, "连接中断")
        return result

    monkeypatch.setattr(agent, "call", lost_response)
    r = admin.post(
        f"/api/applications/{aid}/publish",
        json={"version": 2, "acknowledge_restart": True},
    )
    assert r.status_code == 503
    wait(system[2])
    assert detail(employee, aid)["status"] == "ready"
    assert len(system[2].jobs()) == 1
    assert (
        len(employee.post(f"/api/applications/{aid}/claim", json={}).json()["secret"])
        == 72
    )


def test_reissue_after_pruned_history_and_reject_configuration_drift(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    jid = publish(admin, aid)
    wait(system[2])
    with system[2].db.connect() as db:
        db.execute("DELETE FROM jobs WHERE id=?", (jid,))
    assert detail(employee, aid)["status"] == "attention"
    publish(admin, aid, reissue=True)
    wait(system[2])
    assert detail(employee, aid)["delivery"]["ready"]
    cfg = system[2].config
    cfg.write_text(
        cfg.read_text().replace(
            "https://app.example.com/auth/callback",
            "https://app.example.com/new-callback",
        )
    )
    d = detail(admin, aid)
    assert not d["parameters"]["active"]
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409
    r = admin.post(
        f"/api/applications/{aid}/publish",
        json={"version": d["version"], "acknowledge_restart": True, "reissue": True},
    )
    assert r.status_code == 409


def test_external_credential_change_blocks_old_secret_delivery(system):
    from acm.common import secret_pair

    employee, admin = applicant(system), login(system)
    aid = create(employee)
    approve(admin, aid)
    jid = publish(admin, aid)
    wait(system[2])
    with system[1].connect() as db:
        import json

        hashed = json.loads(
            db.execute("SELECT payload FROM drafts WHERE id=?", (jid,)).fetchone()[
                "payload"
            ]
        )["secret_hash"]
    _, replacement = secret_pair()
    cfg = system[2].config
    cfg.write_text(cfg.read_text().replace(hashed, replacement))
    assert detail(employee, aid)["status"] == "attention"
    assert employee.post(f"/api/applications/{aid}/claim", json={}).status_code == 409


def test_simplified_form_and_default_scopes(system):
    employee = applicant(system)
    data = payload()
    for key in ("audience", "roles", "sensitive", "launch_date", "groups", "framework"):
        data.pop(key, None)
    result = employee.post("/api/applications", json=data)
    assert result.status_code == 200
    aid = result.json()["id"]
    assert detail(employee, aid)["payload"]["groups"] is True
    admin = login(system)
    approve(admin, aid)
    assert detail(admin, aid)["approved"]["scopes"] == [
        "openid",
        "profile",
        "email",
        "groups",
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"access_url": "https://other.test"},
        {"access_url": "https://app.example.com/home"},
        {"access_url": "https://nested.app.example.com"},
        {"redirect_uris": ["https://app.example.com/other"]},
        {
            "redirect_uris": [
                "https://app.example.com/auth/callback",
                "https://app.example.com/extra",
            ]
        },
    ],
)
def test_custom_application_addresses_rejected(system, changes):
    employee = applicant(system)
    assert (
        employee.post("/api/applications", json=payload(**changes)).status_code == 422
    )


def test_application_domain_required(system, monkeypatch):
    monkeypatch.delenv("ACM_APPLICATION_DOMAIN", raising=False)
    assert (
        applicant(system).post("/api/applications", json=payload()).status_code == 503
    )


def test_custom_addresses_rejected_on_resubmit(system):
    employee, admin = applicant(system), login(system)
    aid = create(employee)
    assert (
        admin.post(
            f"/api/applications/{aid}/review",
            json={"version": 1, "decision": "return", "comment": "Update"},
        ).status_code
        == 200
    )
    result = employee.post(
        f"/api/applications/{aid}/resubmit",
        json={
            **payload(redirect_uris=["https://app.example.com/custom"]),
            "version": 2,
        },
    )
    assert result.status_code == 422
    assert detail(employee, aid)["status"] == "returned"
