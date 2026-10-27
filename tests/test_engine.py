import copy
import json
import time
from pathlib import Path
import pytest
from agent.engine import Engine, GuardError, atomic
from acm.common import digest, secret_pair
from acm.models import AgentChange, Client
from uuid import uuid4


@pytest.fixture
def engine(tmp_path):
    cfg = tmp_path / "configuration.yml"
    cfg.write_text(Path("examples/configuration.yml").read_text())
    return Engine(
        cfg,
        tmp_path / "state",
        demo=True,
        writable=True,
        issuer="https://auth.example.com",
    )


def change(e, **kw):
    fields = dict(
        id=uuid4().hex,
        operation="upsert",
        client=Client(
            client_id="test-app",
            client_name="测试",
            public=True,
            redirect_uris=["https://test.example.com/callback"],
            token_endpoint_auth_method="none",
        ),
        revision=e.inventory()["revision"],
    )
    fields.update(kw)
    return AgentChange(**fields)


def wait(e):
    for i in range(100):
        jobs = e.jobs()
        if jobs and jobs[0]["state"] not in [
            "queued",
            "writing",
            "checking",
            "rolling_back",
        ]:
            return jobs[0]
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_inventory_never_exposes_existing_secret(engine):
    with engine.config.open("a") as f:
        f.write("        client_secret: sensitive-test-value\n")
    assert "sensitive-test-value" not in json.dumps(engine.inventory())
    assert engine.inventory()["clients"][0]["has_secret"]


def test_candidate_preserves_global_and_other_clients(engine):
    before = engine.load()[1]
    engine.validate(change(engine))
    assert engine.load()[1] == before
    raw, data = engine.candidate(change(engine))
    obj = engine.y.load(data)
    assert obj["server"] == before["server"]
    assert (
        obj["identity_providers"]["oidc"]["clients"][0]
        == before["identity_providers"]["oidc"]["clients"][0]
    )


def test_stale_revision_rejected_without_writes(engine):
    ch = change(engine)
    engine.config.write_text(engine.config.read_text() + "\n# external\n")
    raw = engine.config.read_bytes()
    with pytest.raises(GuardError):
        engine.validate(ch)
    assert engine.config.read_bytes() == raw


def test_invalid_production_syntax_no_write(engine):
    raw = engine.config.read_bytes()
    ch = change(engine)
    engine.native_validate = lambda data: (_ for _ in ()).throw(GuardError("invalid"))
    with pytest.raises(GuardError):
        engine.deploy(ch)
    assert engine.config.read_bytes() == raw


def test_publish_and_latest_rollback(engine):
    raw = engine.config.read_bytes()
    ch = change(engine)
    engine.deploy(ch)
    assert wait(engine)["state"] == "applied"
    assert len(engine.inventory()["clients"]) == 2
    engine.rollback(ch.id, uuid4().hex)
    assert engine.config.read_bytes() == raw


def test_health_failure_restores_previous_bytes(engine):
    raw = engine.config.read_bytes()
    engine.health = lambda: False
    engine.deploy(change(engine))
    j = wait(engine)
    assert engine.config.read_bytes() == raw
    assert j["state"] == "attention"


def test_restart_failure_restores(engine):
    raw = engine.config.read_bytes()
    calls = []

    def restart():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("simulated failure")

    engine.restart = restart
    engine.deploy(change(engine))
    assert wait(engine)["state"] == "rolled_back"
    assert engine.config.read_bytes() == raw


def test_readonly_refuses_publish(engine):
    engine.writable = False
    with pytest.raises(GuardError):
        engine.deploy(change(engine))


def test_repeated_job_id_does_not_restart_twice(engine):
    calls = []
    engine.restart = lambda: calls.append(1)
    ch = change(engine)
    engine.deploy(ch)
    wait(engine)
    engine.deploy(ch)
    assert len(calls) == 1


def test_import_preserves_unknown_fields_and_secret(engine):
    text = engine.config.read_text().replace(
        "        public: true",
        "        custom_extension: keep-me\n        public: true",
    )
    engine.config.write_text(text)
    cl = Client.model_validate(
        {
            k: v
            for k, v in engine.inventory()["clients"][0].items()
            if k in Client.model_fields
        }
    )
    ch = change(engine, client=cl)
    _, data = engine.candidate(ch)
    assert b"custom_extension: keep-me" in data


def test_duplicate_yaml_keys_rejected(engine):
    engine.config.write_text(engine.config.read_text() + "server: {}\n")
    with pytest.raises(GuardError):
        engine.inventory()


def test_plaintext_secret_hash_not_accepted(engine):
    with pytest.raises(ValueError):
        change(engine, secret_hash="plain-secret")


def test_private_client_requires_secret(engine):
    cl = Client(
        client_id="private-app",
        client_name="private",
        redirect_uris=["https://app.example.com/callback"],
    )
    with pytest.raises(GuardError):
        engine.candidate(change(engine, client=cl))
    _, h = secret_pair()
    engine.candidate(change(engine, client=cl, secret_hash=h))


def test_redirect_restrictions():
    for url in [
        "https://*.example.com/callback",
        "https://user:pass@example.com/callback",
        "https://example.com/#secret",
        "file:///etc/passwd",
    ]:
        with pytest.raises(ValueError):
            Client(client_id="a", client_name="a", redirect_uris=[url])


def test_disable_and_restore_retains_original_secret(engine):
    _, h = secret_pair()
    cl = Client(
        client_id="private-restore",
        client_name="Private",
        redirect_uris=["https://app.example.com/callback"],
    )
    add = change(engine, client=cl, secret_hash=h)
    engine.deploy(add)
    wait(engine)
    disable = change(engine, client=cl, operation="disable")
    engine.deploy(disable)
    assert wait(engine)["state"] == "applied"
    disabled = next(
        x for x in engine.inventory()["clients"] if x["client_id"] == cl.client_id
    )
    assert disabled["disabled"] and h not in json.dumps(disabled)
    restore = change(
        engine, client=cl, operation="restore", restore_id=disabled["restore_id"]
    )
    engine.deploy(restore)
    assert wait(engine)["state"] == "applied"
    old = next(x for x in engine.load()[2] if x["client_id"] == cl.client_id)
    assert old["client_secret"] == h


def test_preview_redacts_new_hash(engine):
    plain, h = secret_pair()
    cl = Client(
        client_id="private-diff",
        client_name="Private",
        redirect_uris=["https://app.example.com/callback"],
    )
    diff = engine.validate(change(engine, client=cl, secret_hash=h))
    assert h not in json.dumps(diff) and plain not in json.dumps(diff)
    assert any(x["field"] == "client_secret" for x in diff["changes"])


def test_recovery_will_not_overwrite_external_changes(engine):
    ch = change(engine)
    engine.deploy(ch)
    wait(engine)
    with engine.db.connect() as c:
        c.execute("UPDATE jobs SET state='checking' WHERE id=?", (ch.id,))
    engine.config.write_text(engine.config.read_text() + "\n# external edit\n")
    raw = engine.config.read_bytes()
    engine.recover()
    assert engine.config.read_bytes() == raw
    assert engine.jobs()[0]["state"] == "attention"
