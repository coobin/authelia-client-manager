"""Employee login with server-side, browser-bound OIDC transactions."""

import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

from .common import digest, now


def install_oidc(app, storage, origin, secure, session_response):
    issuer = os.getenv("ACM_OIDC_ISSUER", "").rstrip("/")
    client_id = os.getenv("ACM_OIDC_CLIENT_ID", "")
    secret_file = os.getenv("ACM_OIDC_SECRET_FILE", "")
    enabled = bool(issuer and client_id and secret_file)
    callback = origin + "/api/applicant/callback"
    cookie_path = "/api/applicant"

    def metadata():
        if not enabled:
            raise HTTPException(503, "员工统一登录尚未配置，请联系认证管理员")
        if urlsplit(issuer).scheme != "https":
            raise HTTPException(503, "员工认证服务必须使用 HTTPS")
        with httpx.Client(timeout=15, trust_env=False) as client:
            r = client.get(issuer + "/.well-known/openid-configuration")
            r.raise_for_status()
            data = r.json()
        if data.get("issuer") != issuer:
            raise ValueError("Issuer mismatch")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            u = urlsplit(data[key])
            if (
                u.scheme != "https"
                or not u.hostname
                or u.username
                or u.password
                or u.fragment
            ):
                raise ValueError("Invalid OIDC endpoint")
        return data

    @app.get("/api/applicant/auth")
    def status():
        return {"enabled": enabled}

    @app.get("/api/applicant/login")
    def login(req: Request):
        ip = req.client.host if req.client else "local"
        if not storage.limit("employee-login:" + ip, maximum=30):
            raise HTTPException(429, "登录请求较多，请稍后再试")
        try:
            config = metadata()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "无法连接员工认证服务，请稍后重试")
        state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        storage.cleanup()
        with storage.connect() as c:
            c.execute(
                "INSERT INTO oidc_states VALUES(?,?,?,?,?)",
                (
                    digest(state.encode()),
                    digest(browser.encode()),
                    nonce,
                    storage.encrypt(verifier, "oidc:" + state),
                    now() + 600,
                ),
            )
        response = RedirectResponse(
            config["authorization_endpoint"]
            + "?"
            + urlencode(
                {
                    "client_id": client_id,
                    "redirect_uri": callback,
                    "response_type": "code",
                    "scope": "openid profile email",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            ),
            status_code=303,
        )
        response.set_cookie(
            "acm_oidc",
            browser,
            secure=secure,
            httponly=True,
            samesite="lax",
            path=cookie_path,
            max_age=600,
        )
        return response

    @app.get("/api/applicant/callback")
    def complete(req: Request, state: str = "", code: str = "", error: str = ""):
        try:
            if not state or len(state) > 256 or len(code) > 4096:
                raise ValueError("Invalid callback")
            with storage.connect() as c:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM oidc_states WHERE id=?", (digest(state.encode()),)
                ).fetchone()
                if (
                    not row
                    or row["expires"] < now()
                    or not secrets.compare_digest(
                        row["browser"], digest(req.cookies.get("acm_oidc", "").encode())
                    )
                ):
                    raise ValueError("Invalid transaction")
                c.execute("DELETE FROM oidc_states WHERE id=?", (row["id"],))
            if error or not code:
                raise ValueError("Authorization cancelled")
            config = metadata()
            with open(secret_file) as f:
                client_secret = f.read().strip()
            with httpx.Client(timeout=15, trust_env=False) as client:
                token = client.post(
                    config["token_endpoint"],
                    auth=(client_id, client_secret),
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": callback,
                        "code_verifier": storage.decrypt(
                            row["verifier"], "oidc:" + state
                        ),
                    },
                )
                token.raise_for_status()
                encoded = token.json()["id_token"]
                header = jwt.get_unverified_header(encoded)
                if header.get("alg") not in (
                    "RS256",
                    "RS384",
                    "RS512",
                    "ES256",
                    "ES384",
                    "ES512",
                ):
                    raise ValueError("Unsupported signature")
                jwks = client.get(config["jwks_uri"])
                jwks.raise_for_status()
                keys = [
                    k
                    for k in jwks.json()["keys"]
                    if k.get("kid") == header.get("kid")
                    and k.get("use", "sig") == "sig"
                    and k.get("alg", header["alg"]) == header["alg"]
                ]
                if len(keys) != 1:
                    raise ValueError("Ambiguous signing key")
                claims = jwt.decode(
                    encoded,
                    jwt.PyJWK.from_dict(keys[0]).key,
                    algorithms=[header["alg"]],
                    audience=client_id,
                    issuer=issuer,
                    leeway=60,
                    options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
                )
            if (
                not secrets.compare_digest(claims["nonce"], row["nonce"])
                or not isinstance(claims["sub"], str)
                or not claims["sub"]
                or ("azp" in claims and claims["azp"] != client_id)
                or (
                    isinstance(claims["aud"], list)
                    and len(claims["aud"]) > 1
                    and claims.get("azp") != client_id
                )
            ):
                raise ValueError("Invalid identity")
            username = "oidc:" + digest((issuer + "\0" + claims["sub"]).encode())
            name = str(
                claims.get("name") or claims.get("preferred_username") or "员工"
            )[:150]
            email = str(claims.get("email") or "")[:254]
            with storage.connect() as c:
                c.execute("BEGIN IMMEDIATE")
                existing = c.execute(
                    "SELECT role FROM admins WHERE username=?", (username,)
                ).fetchone()
                if existing and existing["role"] != "applicant":
                    raise ValueError("Identity collision")
                c.execute(
                    "INSERT OR IGNORE INTO admins(username,role,totp_enabled,needs_setup) VALUES(?,'applicant',0,0)",
                    (username,),
                )
                c.execute(
                    "INSERT INTO applicants VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET name=excluded.name,email=excluded.email",
                    (username, issuer, claims["sub"], name, email),
                )
            storage.audit(username, "employee-login")
            response = session_response(username)
            response.status_code = 303
            response.headers["location"] = "/apply"
        except Exception:
            response = RedirectResponse("/apply?login=failed", status_code=303)
        response.delete_cookie("acm_oidc", path=cookie_path)
        return response
