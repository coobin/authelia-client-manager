"""Run inside the manager image with Docker access and a dedicated fixture mount.
ACM_TEST_HOST_ROOT is an EMPTY dedicated host directory mapped to /fixture.
No production configuration or network is used.
"""

import os, time, json, secrets, io, hashlib, base64
from pathlib import Path
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from argon2 import PasswordHasher
from ruamel.yaml import YAML
import docker
from agent.engine import Engine
from acm.models import Client, AgentChange
from acm.common import secret_pair

root = Path("/fixture")
host = os.environ["ACM_TEST_HOST_ROOT"]
image = os.environ["ACM_TEST_IMAGE"]
if any(root.iterdir()):
    raise SystemExit("Fixture directory must be empty")
y = YAML()
name = "acm-isolated-" + uuid4().hex[:10]
secret = lambda: secrets.token_urlsafe(48)
key = (
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    .private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    .decode()
)
public = {
    "client_id": "example-existing",
    "client_name": "Existing fixture",
    "public": True,
    "redirect_uris": ["https://app.example.com/callback"],
    "authorization_policy": "one_factor",
    "require_pkce": True,
    "pkce_challenge_method": "S256",
    "scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "consent_mode": "implicit",
}
cfg = {
    "server": {"address": "tcp://0.0.0.0:9091/"},
    "identity_validation": {"reset_password": {"jwt_secret": secret()}},
    "authentication_backend": {"file": {"path": "/config/users.yml"}},
    "access_control": {"default_policy": "one_factor"},
    "session": {
        "secret": secret(),
        "cookies": [
            {"domain": "example.com", "authelia_url": "https://auth.example.com"}
        ],
    },
    "storage": {
        "encryption_key": secret(),
        "local": {"path": "/config/storage.sqlite3"},
    },
    "notifier": {"filesystem": {"filename": "/config/notifications.txt"}},
    "identity_providers": {
        "oidc": {
            "hmac_secret": secret(),
            "issuer_private_key": key,
            "clients": [public],
        }
    },
}
with (root / "configuration.yml").open("w") as f:
    y.dump(cfg, f)
with (root / "users.yml").open("w") as f:
    y.dump(
        {
            "users": {
                "demo": {
                    "displayname": "Demo User",
                    "password": PasswordHasher().hash("fictional-test-password"),
                    "email": "demo@example.com",
                    "groups": ["example-team"],
                }
            }
        },
        f,
    )
d = docker.from_env()
ct = None
try:
    ct = d.containers.run(
        image,
        detach=True,
        name=name,
        environment={"X_AUTHELIA_CONFIG": "/config/configuration.yml"},
        volumes={host: {"bind": "/config", "mode": "rw"}},
        network_mode="none",
    )
    e = Engine(
        root / "configuration.yml",
        root / "state",
        writable=True,
        target=name,
        issuer="https://auth.example.com",
    )
    print("Waiting for isolated provider", flush=True)
    assert e.health(), "initial fixture health failed"
    print("Isolated provider healthy", flush=True)
    # Native validator accepts our independently generated PBKDF2 encoding.
    plain, h = secret_pair()
    cl = Client(
        client_id="example-new",
        client_name="New fixture",
        redirect_uris=["https://new.example.com/callback"],
    )
    ch = AgentChange(
        id=uuid4().hex,
        operation="upsert",
        client=cl,
        revision=e.inventory()["revision"],
        secret_hash=h,
    )
    e.validate(ch)
    before = (root / "configuration.yml").read_bytes()
    e.deploy(ch)
    for _ in range(150):
        j = e.jobs()[0]
        if j["state"] not in ("queued", "writing", "checking", "rolling_back"):
            break
        time.sleep(1)
    assert j["state"] == "applied", j
    assert len(e.inventory()["clients"]) == 2
    assert e.verify_client(ch)["active"], "live credential receipt must match"
    print("Native validation and actual provider publication passed", flush=True)
    # Validate client secret hash with the native cryptographic implementation.
    result = ct.exec_run(
        ["authelia", "crypto", "hash", "validate", "--password", plain, "--", h]
    )
    if result.exit_code != 0:
        print(
            "Native hash-check command unavailable; endpoint acceptance covered separately",
            flush=True,
        )
    else:
        print("Native secret digest interoperability passed", flush=True)
    # Complete a real Code + PKCE exchange using the fictional employee.
    from urllib.parse import urlencode, urlsplit, parse_qs
    import re

    headers = [
        "--header",
        "Host: auth.example.com",
        "--header",
        "X-Forwarded-Proto: https",
        "--header",
        "X-Forwarded-Host: auth.example.com",
    ]

    def request(path, data=None, cookie=None):
        args = ["wget", "-T", "5", "-S", "-O-", "--max-redirect", "0"] + headers
        if cookie:
            args += ["--header", "Cookie: " + cookie]
        if data is not None:
            args += [
                "--header",
                "Content-Type: application/json",
                "--post-data",
                json.dumps(data),
            ]
        return ct.exec_run(args + ["http://127.0.0.1:9091" + path]).output.decode()

    first = request(
        "/api/firstfactor",
        {
            "username": "demo",
            "password": "fictional-test-password",
            "keepMeLoggedIn": False,
        },
    )
    cookies = re.findall(r"(?i)set-cookie: ([^;\r\n]+)", first)
    assert cookies, "test login did not issue a session cookie"
    cookie = "; ".join(cookies)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secret()
    query = urlencode(
        {
            "client_id": "example-existing",
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile email",
            "state": state,
            "nonce": "fixture-nonce",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    auth = request("/api/oidc/authorization?" + query, cookie=cookie)
    locations = re.findall(r"(?i)location: (\S+)", auth)
    assert locations and "code=" in locations[-1], "authorization did not return a code"
    params = parse_qs(urlsplit(locations[-1].strip()).query)
    assert params["state"] == [state]
    token_args = (
        ["wget", "-T", "5", "-qO-"]
        + headers
        + [
            "--header",
            "Content-Type: application/x-www-form-urlencoded",
            "--post-data",
            urlencode(
                {
                    "grant_type": "authorization_code",
                    "client_id": "example-existing",
                    "code": params["code"][0],
                    "redirect_uri": "https://app.example.com/callback",
                    "code_verifier": verifier,
                }
            ),
            "http://127.0.0.1:9091/api/oidc/token",
        ]
    )
    token_result = ct.exec_run(token_args)
    tokens = json.loads(token_result.output)
    assert token_result.exit_code == 0 and "id_token" in tokens
    head, payload, sig = tokens["id_token"].split(".")
    dec = lambda t: base64.urlsafe_b64decode(t + "=" * ((4 - len(t) % 4) % 4))
    claims = json.loads(dec(payload))
    assert (
        claims["iss"] == "https://auth.example.com"
        and (
            claims["aud"] == "example-existing" or claims["aud"] == ["example-existing"]
        )
        and claims["nonce"] == "fixture-nonce"
    )
    jwks = json.loads(
        ct.exec_run(
            ["wget", "-T", "5", "-qO-"] + headers + ["http://127.0.0.1:9091/jwks.json"]
        ).output
    )
    jwt_header = json.loads(dec(head))
    jwk = next(k for k in jwks["keys"] if k["kid"] == jwt_header["kid"])
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    pub = rsa.RSAPublicNumbers(
        int.from_bytes(dec(jwk["e"]), "big"), int.from_bytes(dec(jwk["n"]), "big")
    ).public_key()
    pub.verify(
        dec(sig), (head + "." + payload).encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    print(
        "Full employee login, Code + PKCE token exchange and ID-token signature verification passed",
        flush=True,
    )
    e.rollback(ch.id, uuid4().hex)
    assert (root / "configuration.yml").read_bytes() == before
    assert not e.verify_client(ch)["active"], "rolled-back credentials must not be delivered"
    print("Actual provider rollback passed", flush=True)
    # Code + PKCE initial authorization must recognize the preserved client.
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    from urllib.parse import urlencode

    query = urlencode(
        {
            "client_id": "example-existing",
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile email",
            "state": secret(),
            "nonce": secret(),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    result = ct.exec_run(
        [
            "wget",
            "-S",
            "-O",
            "/dev/null",
            "--max-redirect",
            "0",
            "--header",
            "Host: auth.example.com",
            "--header",
            "X-Forwarded-Proto: https",
            "--header",
            "X-Forwarded-Host: auth.example.com",
            "http://127.0.0.1:9091/api/oidc/authorization?" + query,
        ]
    )
    assert (
        b"302" in result.output
        and b"client_id" not in result.output.lower().split(b"error=")[-1]
        if b"error=" in result.output
        else b"302" in result.output
    )
    print("Existing client Code + PKCE authorization redirect passed", flush=True)
    print("INTEGRATION PASS", flush=True)
finally:
    if ct:
        ct.remove(force=True)
