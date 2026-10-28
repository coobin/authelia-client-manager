import base64
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from acm.common import now
from acm.main import create_app
from tests.test_api import system


@pytest.fixture
def oidc(system, tmp_path, monkeypatch):
    from acm import oidc as module

    secret = tmp_path / "oidc.secret"
    secret.write_text("test-only-client-secret")
    for k, v in {
        "ACM_OIDC_ISSUER": "https://auth.example.com",
        "ACM_OIDC_CLIENT_ID": "portal",
        "ACM_OIDC_SECRET_FILE": str(secret),
    }.items():
        monkeypatch.setenv(k, v)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="test-key", alg="RS256", use="sig")
    calls, state = [], {}

    class Response:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self.data

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url):
            if url.endswith("openid-configuration"):
                return Response(
                    {
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/authorize",
                        "token_endpoint": "https://auth.example.com/token",
                        "jwks_uri": "https://auth.example.com/jwks",
                    }
                )
            assert url == "https://auth.example.com/jwks"
            return Response({"keys": [jwk]})

        def post(self, url, auth, data):
            calls.append(data)
            assert auth == ("portal", "test-only-client-secret")
            assert data["redirect_uri"] == "http://testserver/api/applicant/callback"
            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(data["code_verifier"].encode()).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            assert challenge == state["code_challenge"]
            claims = {
                "iss": "https://auth.example.com",
                "sub": "employee-sub",
                "aud": "portal",
                "exp": now() + 300,
                "iat": now(),
                "nonce": state["nonce"],
                "name": "Example Employee",
                "email": "employee@example.com",
                **state.get("overrides", {}),
            }
            return Response(
                {
                    "id_token": jwt.encode(
                        claims, key, algorithm="RS256", headers={"kid": "test-key"}
                    ),
                    "access_token": "test-token",
                }
            )

    monkeypatch.setattr(module, "httpx", SimpleNamespace(Client=Client))
    c = TestClient(
        create_app(
            system[1],
            system[0].app.state.agent,
            origin="http://testserver",
            secure=False,
        )
    )
    c.headers["Origin"] = "http://testserver"
    return c, state, calls


def start(oidc):
    c, state, _ = oidc
    r = c.get("/api/applicant/login", follow_redirects=False)
    assert r.status_code == 303
    for k, values in parse_qs(urlsplit(r.headers["location"]).query).items():
        state[k] = values[0]
    return "/api/applicant/callback?state=" + state["state"] + "&code=test-code"


def test_employee_login_pkce_identity_and_one_time_state(oidc):
    c, state, calls = oidc
    assert c.get("/api/applicant/auth").json()["enabled"]
    callback = start(oidc)
    assert state["code_challenge_method"] == "S256"
    r = c.get(callback, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/apply"
    me = c.get("/api/me").json()
    assert me["role"] == "applicant" and me["name"] == "Example Employee"
    assert len(calls) == 1
    assert (
        c.get(callback, follow_redirects=False).headers["location"]
        == "/apply?login=failed"
    )
    assert len(calls) == 1
    assert "test-token" not in json.dumps(me)
    assert c.get("/api/clients").status_code == 403


@pytest.mark.parametrize(
    "overrides",
    [
        {"nonce": "wrong"},
        {"iss": "https://other.example.com"},
        {"aud": "other-client"},
        {"exp": now() - 120},
        {"iat": now() + 180},
        {"azp": "wrong"},
        {"aud": ["portal", "other"]},
        {"sub": ""},
    ],
)
def test_invalid_id_token_rejected(oidc, overrides):
    c, state, _ = oidc
    callback = start(oidc)
    state["overrides"] = overrides
    r = c.get(callback, follow_redirects=False)
    assert r.headers["location"] == "/apply?login=failed"
    assert c.get("/api/me").status_code == 401


def test_callback_bound_to_initiating_browser(oidc):
    c, state, calls = oidc
    callback = start(oidc)
    other = TestClient(c.app)
    assert (
        other.get(callback, follow_redirects=False).headers["location"]
        == "/apply?login=failed"
    )
    assert calls == []
    assert c.get(callback, follow_redirects=False).headers["location"] == "/apply"


def test_expired_or_cancelled_login(oidc, system):
    c, state, calls = oidc
    callback = start(oidc)
    with system[1].connect() as db:
        db.execute("UPDATE oidc_states SET expires=0")
    assert (
        c.get(callback, follow_redirects=False).headers["location"]
        == "/apply?login=failed"
    )
    callback = start(oidc)
    assert (
        c.get(
            callback.replace("code=test-code", "error=access_denied"),
            follow_redirects=False,
        ).headers["location"]
        == "/apply?login=failed"
    )
    assert calls == []
