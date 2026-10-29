import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit
import httpx
import pyotp
from argon2 import PasswordHasher
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from .common import now, secret_pair, digest
from .storage import Storage, open_storage
from .models import DraftInput, AgentChange


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    code: str = Field(default="", pattern=r"^(?:|\d{6})$")


class Reauth(BaseModel):
    password: str = Field(min_length=1, max_length=200)
    code: str = Field(default="", pattern=r"^(?:|\d{6})$")


class Setup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64, pattern=r"^[^\s\x00-\x1f]+$")
    password: str = Field(min_length=8, max_length=200)
    confirm_password: str = Field(min_length=8, max_length=200)


class TotpConfirmation(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class Deploy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    draft_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    acknowledge_restart: bool


class Agent:
    def __init__(self, socket):
        self.socket = socket

    def call(self, method, path, data=None):
        try:
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=self.socket),
                base_url="http://agent",
                timeout=120,
                trust_env=False,
            ) as c:
                r = c.request(method, path, json=data)
            if r.status_code >= 400:
                raise HTTPException(
                    r.status_code, r.json().get("detail", "代理拒绝操作")
                )
            return r.json()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "发布代理暂不可用，请检查部署状态")



def format_validation_error(exc: RequestValidationError) -> dict:
    field_labels = {
        "client.client_id": "客户端标识",
        "client.client_name": "应用名称",
        "client.redirect_uris": "登录回调地址",
        "client.scopes": "资料范围",
        "client.authorization_policy": "认证强度",
        "client.require_pkce": "要求 PKCE",
        "client.pkce_challenge_method": "PKCE 算法",
        "client.token_endpoint_auth_method": "客户端认证方式",
        "client.grant_types": "授权方式",
        "client.response_types": "响应方式",
        "client": "客户端配置",
        "environment": "接入环境",
        "owner": "负责人",
        "username": "用户名",
        "password": "密码",
        "confirm_password": "确认密码",
        "code": "动态验证码",
        "draft_id": "草稿标识",
        "acknowledge_restart": "重启确认",
        "name": "应用名称",
        "purpose": "应用用途",
        "department": "申请部门",
        "business_owner": "业务负责人",
        "technical_owner": "技术负责人",
        "contact": "联系方式",
        "app_type": "应用类型",
        "framework": "开发框架及 OIDC 组件",
        "access_url": "应用访问地址",
        "redirect_uris": "完整登录回调地址",
        "audience": "使用人群及访问限制",
        "roles": "业务角色及管理员授权方式",
        "sensitive": "敏感业务说明",
        "launch_date": "期望上线日期",
        "agreement": "接入要求确认",
        "version": "申请版本",
        "results": "验收结果",
        "comment": "审批意见",
    }

    formatted = []
    fields = []

    for err in exc.errors():
        loc = [str(x) for x in err.get("loc", ()) if str(x) != "body"]
        loc_key = ".".join(loc)
        base_loc = ".".join([x for x in loc if not x.isdigit()])

        err_type = err.get("type", "")
        raw_msg = str(err.get("msg", ""))
        clean_msg = raw_msg
        if clean_msg.startswith("Value error, "):
            clean_msg = clean_msg[len("Value error, "):]

        label = field_labels.get(base_loc, field_labels.get(loc_key, base_loc or "页面填写内容"))

        if "修正建议" in clean_msg:
            formatted.append(clean_msg)
            if "生产环境" in clean_msg:
                fields.extend(["environment", "client.redirect_uris"])
            elif base_loc:
                fields.append(base_loc)
            continue

        if base_loc:
            fields.append(base_loc)

        if err_type == "string_pattern_mismatch":
            if "client_id" in base_loc:
                formatted.append(f"【{label}】格式不正确。修正建议：仅支持英文字母、数字、点(.)、下划线(_)、波浪线(~)及短横线(-)。")
            elif "code" in base_loc:
                formatted.append(f"【{label}】格式不正确。修正建议：请输入 6 位纯数字验证码。")
            elif "username" in base_loc:
                formatted.append(f"【{label}】格式不正确。修正建议：用户名不能包含空格或控制字符。")
            else:
                formatted.append(f"【{label}】格式不符合规则。修正建议：请检查并修改该项内容。")
        elif err_type in ("string_too_short", "too_short"):
            if "redirect_uris" in base_loc:
                formatted.append(f"【{label}】不能为空。修正建议：请至少输入一行完整合法的回调地址（如 http://... 或 https://...）。")
            elif "password" in base_loc or "confirm_password" in base_loc:
                formatted.append(f"【{label}】长度不足。修正建议：密码至少需要 8 个字符。")
            elif "client_name" in base_loc:
                formatted.append(f"【{label}】不能为空。修正建议：请输入应用名称。")
            elif "client_id" in base_loc:
                formatted.append(f"【{label}】不能为空。修正建议：请输入客户端标识或使用自动生成的标识。")
            else:
                formatted.append(f"【{label}】不能为空。修正建议：请填写该项内容。")
        elif err_type in ("string_too_long", "too_long"):
            formatted.append(f"【{label}】内容过长。修正建议：请精简该项填写内容。")
        elif err_type == "missing":
            if "acknowledge_restart" in base_loc:
                formatted.append(f"【{label}】未勾选。修正建议：发布会重启认证服务，请确认并勾选「我已确认变更内容和重启影响」。")
            else:
                formatted.append(f"【{label}】为必填项。修正建议：请填写该项内容。")
        else:
            formatted.append(f"【{label}】格式不正确。修正建议：请检查该项填写内容。")

    fields = list(dict.fromkeys(fields))

    if len(formatted) == 1:
        detail = formatted[0]
    elif len(formatted) > 1:
        detail = "发现以下内容格式不正确：\n" + "\n".join(f"{i+1}. {text}" for i, text in enumerate(formatted))
    else:
        detail = "输入格式不正确，请检查页面填写内容"

    return {"detail": detail, "fields": fields}

def create_app(storage=None, agent=None, *, origin=None, secure=None, static=None):
    data = Path(os.getenv("ACM_DATA", "runtime/web"))
    s = storage or open_storage(data)
    a = agent or Agent(os.getenv("ACM_AGENT_SOCKET", "runtime/agent.sock"))
    origin = origin or os.getenv("ACM_ORIGIN", "http://localhost:8098")
    secure = (
        secure if secure is not None else os.getenv("ACM_SECURE_COOKIE", "1") == "1"
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.storage = s
    app.state.agent = a

    @app.exception_handler(RequestValidationError)
    async def invalid(req, exc):
        # Pydantic's input/context fields can contain passwords. Never return them.
        res = format_validation_error(exc)
        return JSONResponse(res, status_code=422)

    @app.middleware("http")
    async def security(req, call_next):
        if (
            req.headers.get("content-length", "").isdigit()
            and int(req.headers["content-length"]) > 65536
        ):
            return JSONResponse({"detail": "请求过大"}, 413)
        if (
            req.method not in ("GET", "HEAD", "OPTIONS")
            and req.headers.get("origin") != origin
        ):
            return JSONResponse({"detail": "请求来源不匹配"}, 403)
        r = await call_next(req)
        for k, v in {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        }.items():
            r.headers[k] = v
        return r

    def current(req: Request):
        token = req.cookies.get("acm_session", "")
        key = digest(token.encode())
        with s.connect() as c:
            row = c.execute(
                "SELECT sessions.*,admins.role,admins.totp_enabled FROM sessions JOIN admins ON admins.username=sessions.username WHERE sessions.id=?",
                (key,),
            ).fetchone()
            if not row or row["created"] < now() - 28800 or row["seen"] < now() - 1800:
                raise HTTPException(401, "请登录")
            if req.method not in ("GET", "HEAD") and not secrets.compare_digest(
                req.headers.get("x-csrf-token", ""), row["csrf"]
            ):
                raise HTTPException(403, "请求校验失败，请刷新页面")
            c.execute("UPDATE sessions SET seen=? WHERE id=?", (now(), key))
        return dict(row)

    def admin(u=Depends(current)):
        if u["role"] != "admin":
            raise HTTPException(403, "需要管理员权限")
        return u

    def staff(u=Depends(current)):
        if u["role"] not in ("admin", "viewer"):
            raise HTTPException(403, "需要管理后台权限")
        return u

    def fresh(u=Depends(admin)):
        if u["reauth"] < now() - 300:
            raise HTTPException(403, "请先完成近期安全验证")
        return u

    def verify(username, password, code=""):
        with s.connect() as c:
            r = c.execute(
                "SELECT * FROM admins WHERE username=?", (username,)
            ).fetchone()
        ok = False
        try:
            if r and not r["needs_setup"]:
                ok = PasswordHasher().verify(r["password"], password)
            else:
                PasswordHasher().verify(
                    "$argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWFhYWFhYWFhYQ$5YnZTkJy8I8n2QWbLa8SY4p8GkgpXvJjX4jC9m4vWJE",
                    password,
                )
        except Exception:
            pass
        if not ok:
            raise HTTPException(401, "账号或密码不正确")
        if r["totp_enabled"]:
            valid = False
            try:
                valid = bool(code) and pyotp.TOTP(
                    s.decrypt(r["totp"], "totp:" + username)
                ).verify(code, valid_window=1)
            except Exception:
                pass
            if not valid:
                raise HTTPException(
                    401, "请输入正确的动态验证码", headers={"X-ACM-TOTP-Required": "1"}
                )

    def session_response(username):
        s.cleanup()
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with s.connect() as c:
            c.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                (digest(token.encode()), username, csrf, now(), now(), now()),
            )
        r = JSONResponse({"username": username, "csrf": csrf})
        r.set_cookie(
            "acm_session",
            token,
            httponly=True,
            secure=secure,
            samesite="strict",
            max_age=28800,
            path="/",
        )
        return r

    from .oidc import install_oidc
    from .applications import install_applications
    install_oidc(app, s, origin, secure, session_response)
    install_applications(app, s, a, current, admin, fresh)

    def application_delivery(c, did):
        return c.execute(
            "SELECT 1 FROM applications a JOIN deliveries d ON a.draft_id=d.draft_id WHERE d.id=?",
            (did,),
        ).fetchone()

    @app.get("/api/auth/status")
    def auth_status():
        with s.connect() as c:
            return {"setup_required": s.setup_required(c)}

    @app.post("/api/setup")
    def setup(body: Setup, req: Request):
        if body.password != body.confirm_password:
            raise HTTPException(422, "两次输入的密码不一致。修正建议：请确保「密码」与「确认密码」完全一致。")
        ip = req.client.host if req.client else "local"
        if not s.limit("setup:" + ip, maximum=8):
            raise HTTPException(429, "尝试次数较多，请稍后再试")
        hashed = PasswordHasher().hash(body.password)
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if not s.setup_required(c):
                raise HTTPException(409, "管理员账户已建立，请登录")
            old = c.execute(
                "SELECT username FROM admins WHERE needs_setup=1"
            ).fetchone()
            if old:
                c.execute("DELETE FROM admins WHERE username=?", (old["username"],))
            c.execute(
                "INSERT INTO admins(username,password,totp,role,totp_enabled,needs_setup) VALUES(?,?,NULL,'admin',0,0)",
                (body.username, hashed),
            )
            c.execute("DELETE FROM sessions")
            c.execute("DELETE FROM totp_enrollments")
        s.audit(body.username, "web-setup-completed")
        return session_response(body.username)

    @app.get("/api/settings/security")
    def security_settings(u=Depends(current)):
        return {"username": u["username"], "totp_enabled": bool(u["totp_enabled"])}

    @app.post("/api/settings/totp/begin")
    def begin_totp(body: Reauth, u=Depends(admin)):
        if not s.limit("totp:" + u["username"]):
            raise HTTPException(429, "尝试次数较多，请稍后再试")
        verify(u["username"], body.password, body.code)
        if u["totp_enabled"]:
            raise HTTPException(409, "双因素认证已开启")
        seed = pyotp.random_base32()
        with s.connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO totp_enrollments VALUES(?,?,?)",
                (
                    u["username"],
                    s.encrypt(seed, "enroll:" + u["username"]),
                    now() + 600,
                ),
            )
        return {
            "secret": seed,
            "uri": pyotp.TOTP(seed).provisioning_uri(
                u["username"], issuer_name="Authelia Client Manager"
            ),
            "expires_in": 600,
        }

    @app.post("/api/settings/totp/confirm")
    def confirm_totp(body: TotpConfirmation, u=Depends(admin)):
        if not s.limit("totp-confirm:" + u["username"]):
            raise HTTPException(429, "尝试次数较多，请稍后再试")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT * FROM totp_enrollments WHERE username=?", (u["username"],)
            ).fetchone()
            if not row or row["expires"] < now():
                raise HTTPException(410, "绑定已过期，请重新开始")
            seed = s.decrypt(row["secret"], "enroll:" + u["username"])
            if not pyotp.TOTP(seed).verify(body.code, valid_window=1):
                raise HTTPException(400, "动态验证码不正确")
            c.execute(
                "UPDATE admins SET totp=?,totp_enabled=1 WHERE username=?",
                (s.encrypt(seed, "totp:" + u["username"]), u["username"]),
            )
            c.execute("DELETE FROM totp_enrollments WHERE username=?", (u["username"],))
            c.execute(
                "DELETE FROM sessions WHERE username=? AND id<>?",
                (u["username"], u["id"]),
            )
            c.execute("UPDATE sessions SET reauth=? WHERE id=?", (now(), u["id"]))
        s.audit(u["username"], "totp-enabled")
        return {"ok": True}

    @app.post("/api/settings/totp/disable")
    def disable_totp(body: Reauth, u=Depends(admin)):
        if not s.limit("totp-disable:" + u["username"]):
            raise HTTPException(429, "尝试次数较多，请稍后再试")
        verify(u["username"], body.password, body.code)
        with s.connect() as c:
            c.execute(
                "UPDATE admins SET totp=NULL,totp_enabled=0 WHERE username=?",
                (u["username"],),
            )
            c.execute("DELETE FROM totp_enrollments WHERE username=?", (u["username"],))
            c.execute(
                "DELETE FROM sessions WHERE username=? AND id<>?",
                (u["username"], u["id"]),
            )
            c.execute("UPDATE sessions SET reauth=? WHERE id=?", (now(), u["id"]))
        s.audit(u["username"], "totp-disabled")
        return {"ok": True}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.2.2"}

    @app.post("/api/login")
    def login(body: Login, req: Request):
        ip = req.client.host if req.client else "local"
        if not s.limit("login:" + ip, maximum=12):
            raise HTTPException(429, "尝试次数较多，请稍后再试")
        verify(body.username, body.password, body.code)
        s.audit(body.username, "login")
        return session_response(body.username)

    @app.get("/api/me")
    def me(u=Depends(current)):
        result = {k: u[k] for k in ("username", "role", "csrf", "reauth", "totp_enabled")}
        with s.connect() as c:
            profile = c.execute("SELECT name,email FROM applicants WHERE username=?", (u["username"],)).fetchone()
        if profile:
            result.update(dict(profile))
        return result

    @app.post("/api/logout")
    def logout(u=Depends(current)):
        with s.connect() as c:
            c.execute("DELETE FROM sessions WHERE id=?", (u["id"],))
        r = JSONResponse({"ok": True})
        r.delete_cookie("acm_session")
        return r

    @app.post("/api/reauth")
    def reauth(body: Reauth, u=Depends(admin)):
        if not s.limit("reauth:" + u["username"]):
            raise HTTPException(429, "请稍后再试")
        verify(u["username"], body.password, body.code)
        with s.connect() as c:
            c.execute("UPDATE sessions SET reauth=? WHERE id=?", (now(), u["id"]))
        return {"ok": True}

    @app.get("/api/clients")
    def clients(u=Depends(staff)):
        inv = a.call("GET", "/inventory")
        with s.connect() as c:
            meta = {
                r["client_id"]: dict(r) for r in c.execute("SELECT * FROM metadata")
            }
        for x in inv["clients"]:
            x.update(
                meta.get(x["client_id"], {"owner": "", "environment": "unclassified"})
            )
        return inv

    @app.get("/api/drafts")
    def drafts(u=Depends(staff)):
        with s.connect() as c:
            rows = c.execute(
                "SELECT id,payload,owner,environment,created,validated,used FROM drafts ORDER BY created DESC LIMIT 100"
            ).fetchall()
        out = []
        for row in rows:
            x = dict(row)
            p = json.loads(x.pop("payload"))
            x.update(
                {
                    "client_id": p["client"]["client_id"],
                    "client_name": p["client"]["client_name"],
                    "operation": p["operation"],
                }
            )
            out.append(x)
        return out

    @app.post("/api/drafts")
    def draft(body: DraftInput, u=Depends(admin)):
        inv = a.call("GET", "/inventory")
        if inv["revision"] != body.revision:
            raise HTTPException(409, "配置已变化，请刷新")
        existing = next(
            (x for x in inv["clients"] if x["client_id"] == body.client.client_id), None
        )
        if existing and not existing["editable"]:
            raise HTTPException(409, "该客户端使用高级配置，当前只读")
        if body.operation == "rotate" and not existing:
            raise HTTPException(409, "客户端不存在")
        jid = uuid4().hex
        plain = secret_hash = None
        if (
            not body.client.public
            and body.operation not in ("disable", "restore")
            and (existing is None or body.operation == "rotate")
        ):
            plain, secret_hash = secret_pair()
        ch = AgentChange(
            id=jid,
            operation=body.operation,
            client=body.client,
            revision=body.revision,
            secret_hash=secret_hash,
            restore_id=body.restore_id,
        )
        delivery = uuid4().hex if plain else None
        with s.connect() as c:
            c.execute(
                "INSERT INTO drafts(id,payload,owner,environment,created,validated) VALUES(?,?,?,?,?,0)",
                (jid, ch.model_dump_json(), body.owner, body.environment, now()),
            )
            if plain:
                c.execute(
                    "INSERT INTO deliveries VALUES(?,?,?,?,0)",
                    (
                        delivery,
                        jid,
                        s.encrypt(plain, "delivery:" + delivery),
                        now() + 86400,
                    ),
                )
        s.audit(u["username"], "draft-created", body.client.client_id)
        return {
            "id": jid,
            "delivery_id": delivery,
            "secret_expires_in": 86400 if plain else None,
        }

    @app.post("/api/drafts/{jid}/validate")
    def validate(jid: str, u=Depends(admin)):
        with s.connect() as c:
            r = c.execute("SELECT * FROM drafts WHERE id=?", (jid,)).fetchone()
        if not r:
            raise HTTPException(404, "草稿不存在")
        result = a.call("POST", "/validate", json.loads(r["payload"]))
        with s.connect() as c:
            c.execute("UPDATE drafts SET validated=1 WHERE id=?", (jid,))
        return result

    @app.post("/api/deployments")
    def deploy(body: Deploy, u=Depends(fresh)):
        if not body.acknowledge_restart:
            raise HTTPException(400, "请确认重启影响")
        with s.connect() as c:
            r = c.execute(
                "SELECT * FROM drafts WHERE id=?", (body.draft_id,)
            ).fetchone()
        if not r or not r["validated"]:
            raise HTTPException(409, "请先校验草稿")
        with s.connect() as c:
            if c.execute("SELECT 1 FROM applications WHERE draft_id=?", (body.draft_id,)).fetchone():
                raise HTTPException(409, "申请产生的草稿请在接入申请中发布")
        result = a.call("POST", "/deploy", json.loads(r["payload"]))
        with s.connect() as c:
            c.execute("UPDATE drafts SET used=1 WHERE id=?", (body.draft_id,))
        s.audit(u["username"], "deployment-requested", body.draft_id)
        return result

    @app.get("/api/deployments")
    def deployments(u=Depends(staff)):
        jobs = a.call("GET", "/jobs")
        for j in jobs:
            if j["state"] == "applied" and j["operation"] in ("upsert", "restore"):
                with s.connect() as c:
                    d = c.execute(
                        "SELECT * FROM drafts WHERE id=?", (j["id"],)
                    ).fetchone()
                    if d:
                        c.execute(
                            "INSERT OR REPLACE INTO metadata VALUES(?,?,?)",
                            (j["client_id"], d["owner"], d["environment"]),
                        )
        return jobs

    @app.post("/api/deployments/{jid}/rollback")
    def rollback(jid: str, u=Depends(fresh)):
        result = a.call("POST", "/rollback", {"id": jid, "new_id": uuid4().hex})
        s.audit(u["username"], "rollback-requested", jid)
        return result

    @app.get("/api/deliveries")
    def deliveries(u=Depends(admin)):
        s.cleanup()
        jobs = a.call("GET", "/jobs")
        applied_ids = {j["id"] for j in jobs if j.get("state") == "applied"}
        with s.connect() as c:
            rows = c.execute(
                "SELECT d.id, d.draft_id, d.expires, dr.payload FROM deliveries d LEFT JOIN drafts dr ON d.draft_id=dr.id WHERE d.claimed=0 AND NOT EXISTS(SELECT 1 FROM applications a WHERE a.draft_id=d.draft_id) ORDER BY d.expires"
            ).fetchall()
            res = []
            for r in rows:
                item = {
                    "id": r["id"],
                    "draft_id": r["draft_id"],
                    "expires": r["expires"],
                    "client_id": "",
                    "client_name": "",
                    "ready": r["draft_id"] in applied_ids,
                }
                if r["payload"]:
                    try:
                        p = json.loads(r["payload"])
                        item["client_id"] = p.get("client", {}).get("client_id", "")
                        item["client_name"] = p.get("client", {}).get("client_name", "")
                    except Exception:
                        pass
                res.append(item)
            return res

    @app.get("/api/claim/{did}")
    def claim_info(did: str, req: Request):
        if not re.match(r"^[a-f0-9]{32}$", did):
            raise HTTPException(404, "无效的领取凭证")
        ip = req.client.host if req.client else "local"
        if not s.limit("claim-info:" + ip, maximum=60):
            raise HTTPException(429, "请求过于频繁，请稍后再试")
        with s.connect() as c:
            if application_delivery(c, did):
                raise HTTPException(404, "请登录申请入口领取")
            r = c.execute(
                "SELECT d.id, d.draft_id, d.expires, d.claimed, dr.payload FROM deliveries d LEFT JOIN drafts dr ON d.draft_id=dr.id WHERE d.id=?",
                (did,),
            ).fetchone()
        if not r or r["claimed"] or r["expires"] < now():
            raise HTTPException(410, "该领取链接不存在、已失效或密钥已被领取")
        jobs = a.call("GET", "/jobs")
        ready = any(j["id"] == r["draft_id"] and j["state"] == "applied" for j in jobs)
        client_id = client_name = ""
        if r["payload"]:
            try:
                p = json.loads(r["payload"])
                client_id = p.get("client", {}).get("client_id", "")
                client_name = p.get("client", {}).get("client_name", "")
            except Exception:
                pass
        return {
            "id": did,
            "client_id": client_id,
            "client_name": client_name,
            "expires": r["expires"],
            "ready": ready,
        }

    @app.post("/api/claim/{did}")
    def claim_public(did: str, req: Request):
        if not re.match(r"^[a-f0-9]{32}$", did):
            raise HTTPException(404, "无效的领取凭证")
        ip = req.client.host if req.client else "local"
        if not s.limit("claim-action:" + ip, maximum=20):
            raise HTTPException(429, "请求过于频繁，请稍后再试")
        jobs = a.call("GET", "/jobs")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if application_delivery(c, did):
                raise HTTPException(404, "请登录申请入口领取")
            r = c.execute(
                "SELECT d.id, d.draft_id, d.secret, d.expires, d.claimed, dr.payload FROM deliveries d LEFT JOIN drafts dr ON d.draft_id=dr.id WHERE d.id=?",
                (did,),
            ).fetchone()
            if not r or r["claimed"] or r["expires"] < now():
                raise HTTPException(410, "该密钥链接已失效或已被领取")
            if not any(
                j["id"] == r["draft_id"] and j["state"] == "applied" for j in jobs
            ):
                raise HTTPException(409, "发布尚未完成，配置生效后方可领取密钥")
            plain = s.decrypt(r["secret"], "delivery:" + did)
            c.execute("DELETE FROM deliveries WHERE id=?", (did,))
        s.audit("anonymous:" + ip, "secret-claimed-via-link", did)
        client_id = client_name = ""
        if r["payload"]:
            try:
                p = json.loads(r["payload"])
                client_id = p.get("client", {}).get("client_id", "")
                client_name = p.get("client", {}).get("client_name", "")
            except Exception:
                pass
        return {
            "secret": plain,
            "client_id": client_id,
            "client_name": client_name,
        }

    @app.post("/api/deliveries/{did}/claim")
    def claim(did: str, u=Depends(fresh)):
        jobs = a.call("GET", "/jobs")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if application_delivery(c, did):
                raise HTTPException(403, "申请密钥仅由申请人本人领取")
            r = c.execute("SELECT * FROM deliveries WHERE id=?", (did,)).fetchone()
            if not r or r["claimed"] or r["expires"] < now():
                raise HTTPException(410, "密钥已领取或已过期")
            if not any(
                j["id"] == r["draft_id"] and j["state"] == "applied" for j in jobs
            ):
                raise HTTPException(409, "发布成功后才能领取密钥")
            plain = s.decrypt(r["secret"], "delivery:" + did)
            c.execute("DELETE FROM deliveries WHERE id=?", (did,))
        s.audit(u["username"], "secret-claimed", did)
        return {"secret": plain}

    @app.get("/api/audit")
    def audit(u=Depends(staff)):
        with s.connect() as c:
            return [
                dict(r)
                for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")
            ]

    static = Path(static or os.getenv("ACM_STATIC", "frontend/dist"))
    if (static / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

    @app.get("/claim/{did}")
    def claim_page(did: str):
        if (static / "index.html").exists():
            return FileResponse(static / "index.html")
        raise HTTPException(503, "请先构建前端资源")

    @app.get("/apply")
    @app.get("/")
    def index():
        if (static / "index.html").exists():
            return FileResponse(static / "index.html")
        raise HTTPException(503, "请先构建前端资源")

    return app
