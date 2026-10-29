"""Application, review and credential delivery workflow."""

import json
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import now, secret_pair
from .models import AgentChange, Client, DraftInput


class ApplicationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=150)
    purpose: str = Field(min_length=1, max_length=2000)
    department: str = Field(min_length=1, max_length=150)
    business_owner: str = Field(min_length=1, max_length=100)
    technical_owner: str = Field(min_length=1, max_length=100)
    contact: str = Field(min_length=1, max_length=254)
    environment: Literal["development", "test", "production"]
    app_type: Literal["backend", "spa", "mobile"]
    framework: str = Field(min_length=1, max_length=300)
    access_url: str = Field(min_length=1, max_length=2048)
    redirect_uris: list[str] = Field(min_length=1, max_length=20)
    # Retained for decoding historical applications; no longer requested by the form.
    audience: str = Field(default="", max_length=2000)
    roles: str = Field(default="", max_length=2000)
    groups: bool = False
    sensitive: str = Field(default="", max_length=2000)
    launch_date: str = Field(
        default="", max_length=10, pattern=r"^(?:|\d{4}-\d{2}-\d{2})$"
    )
    agreement: Literal[True]

    @model_validator(mode="after")
    def valid_addresses(self):
        u = urlsplit(self.access_url)
        if (
            u.scheme not in ("https", "http")
            or not u.hostname
            or u.username
            or u.password
            or u.fragment
        ):
            raise ValueError(
                "应用访问地址格式不正确。修正建议：填写完整 HTTP 或 HTTPS 地址，不能包含用户名、密码或锚点。"
            )
        if self.environment == "production" and u.scheme != "https":
            raise ValueError(
                "生产环境应用访问地址必须使用 HTTPS。修正建议：配置 HTTPS 后填写正式访问地址。"
            )
        self.client("validation")
        if self.launch_date:
            from datetime import date

            try:
                date.fromisoformat(self.launch_date)
            except ValueError:
                raise ValueError("期望上线日期不存在。修正建议：选择有效的日历日期。")
        return self

    def client(self, client_id):
        public = self.app_type != "backend"
        client = Client(
            client_id=client_id,
            client_name=self.name,
            public=public,
            redirect_uris=self.redirect_uris,
            scopes=["openid", "profile", "email"] + (["groups"] if self.groups else []),
            token_endpoint_auth_method="none" if public else "client_secret_basic",
        )
        DraftInput(client=client, revision="0" * 64, environment=self.environment)
        return client


class Revision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1)


class Review(Revision):
    decision: Literal["approve", "return", "reject"]
    comment: str = Field(default="", max_length=2000)
    groups: bool = False
    two_factor: bool = False


class Publish(Revision):
    acknowledge_restart: bool
    reissue: bool = False


class Resubmit(ApplicationInput):
    version: int = Field(ge=1)


class Acceptance(Revision):
    results: str = Field(min_length=20, max_length=6000)


def install_applications(app, s, a, current, admin, fresh):
    def row(c, aid, u):
        r = c.execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone()
        if not r or (u["role"] != "admin" and r["applicant"] != u["username"]):
            raise HTTPException(404, "申请不存在")
        return r

    def event(c, aid, u, action, comment=""):
        c.execute(
            "INSERT INTO application_events(application_id,at,actor,action,comment) VALUES(?,?,?,?,?)",
            (aid, now(), u["username"], action, comment),
        )
        c.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
            (now(), u["username"], "application-" + action, aid),
        )

    def check_version(r, version):
        if r["version"] != version:
            raise HTTPException(409, "申请已更新，请刷新后重试")

    def serialize(r):
        d = dict(r)
        d["payload"] = json.loads(d["payload"])
        d["approved"] = json.loads(d["approved"]) if d["approved"] else None
        d["delivery"] = None
        d["deployment_state"] = None
        d["deployment_message"] = ""
        if d["draft_id"]:
            with s.connect() as c:
                draft = c.execute(
                    "SELECT payload FROM drafts WHERE id=?", (d["draft_id"],)
                ).fetchone()
            receipt = a.call("POST", "/verify-client", json.loads(draft["payload"]))
            state = receipt["state"]
            if state:
                d["deployment_state"] = state
                d["deployment_message"] = receipt["message"]
                if state == "applied":
                    d["status"] = "completed" if d["status"] == "completed" else "ready"
                elif state in ("failed", "rolled_back", "attention"):
                    d["status"] = "failed"
                else:
                    d["status"] = "publishing"
            # Only the agent can compare the current credential hash with its receipt.
            inv = a.call("GET", "/inventory")
            client = next(
                (
                    x
                    for x in inv["clients"]
                    if d["approved"]
                    and x["client_id"] == d["approved"]["client_id"]
                    and not x.get("disabled")
                ),
                None,
            )
            active = bool(receipt["active"])
            if not state and client:
                d["status"] = "attention"
            d["parameters"] = {
                "issuer": inv["issuer"],
                "discovery": inv["issuer"].rstrip("/")
                + "/.well-known/openid-configuration",
                "client": d["approved"],
                "active": active,
            }
            if d["status"] in ("ready", "completed") and not active:
                d["status"] = "attention"
            with s.connect() as c:
                delivery = c.execute(
                    "SELECT expires FROM deliveries WHERE draft_id=? AND claimed=0 AND expires>=?",
                    (d["draft_id"], now()),
                ).fetchone()
            if delivery:
                d["delivery"] = {"expires": delivery["expires"], "ready": active}
            with s.connect() as c:
                c.execute(
                    "UPDATE applications SET status=? WHERE id=? AND draft_id=? AND version=?",
                    (d["status"], d["id"], d["draft_id"], d["version"]),
                )
        return d

    @app.get("/api/applications")
    def applications(u=Depends(current)):
        with s.connect() as c:
            if u["role"] == "admin":
                rows = c.execute(
                    "SELECT * FROM applications ORDER BY created DESC,rowid DESC"
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM applications WHERE applicant=? ORDER BY created DESC,rowid DESC",
                    (u["username"],),
                ).fetchall()
        jobs = a.call("GET", "/jobs") if any(r["draft_id"] for r in rows) else []
        out = []
        for r in rows:
            d = {
                **dict(r),
                "payload": json.loads(r["payload"]),
                "approved": json.loads(r["approved"]) if r["approved"] else None,
            }
            job = next((j for j in jobs if j["id"] == r["draft_id"]), None)
            if job:
                if job["state"] == "applied" and d["status"] != "completed":
                    d["status"] = "ready"
                elif job["state"] in ("failed", "rolled_back", "attention"):
                    d["status"] = "failed"
            out.append(d)
        return out

    @app.post("/api/applications")
    def create(body: ApplicationInput, u=Depends(current)):
        if body.groups:
            raise HTTPException(422, "暂不提供部门资料")
        if u["role"] not in ("applicant", "admin"):
            raise HTTPException(403, "需要申请人权限")
        if not s.limit("application:" + u["username"], maximum=20, window=3600):
            raise HTTPException(429, "提交较多，请稍后再试")
        aid = uuid4().hex
        with s.connect() as c:
            c.execute(
                "INSERT INTO applications(id,applicant,payload,status,created,updated) VALUES(?,?,?,'submitted',?,?)",
                (aid, u["username"], body.model_dump_json(), now(), now()),
            )
            event(c, aid, u, "submitted")
        return {"id": aid}

    @app.get("/api/applications/{aid}")
    def detail(aid: str, u=Depends(current)):
        with s.connect() as c:
            r = row(c, aid, u)
            events = [
                dict(e)
                for e in c.execute(
                    "SELECT at,actor,action,comment FROM application_events WHERE application_id=? ORDER BY id",
                    (aid,),
                )
            ]
            profile = c.execute(
                "SELECT name,email FROM applicants WHERE username=?", (r["applicant"],)
            ).fetchone()
        d = serialize(r)
        d["events"] = events
        d["applicant_profile"] = (
            dict(profile) if profile else {"name": r["applicant"], "email": ""}
        )
        return d

    @app.post("/api/applications/{aid}/resubmit")
    def resubmit(aid: str, body: Resubmit, u=Depends(current)):
        if body.groups:
            raise HTTPException(422, "暂不提供部门资料")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = row(c, aid, u)
            if r["applicant"] != u["username"] or r["status"] != "returned":
                raise HTTPException(409, "仅申请人可以修改退回的申请")
            check_version(r, body.version)
            payload = ApplicationInput.model_validate(
                body.model_dump(exclude={"version"})
            )
            c.execute(
                "UPDATE applications SET payload=?,status='submitted',version=version+1,updated=?,comment='' WHERE id=?",
                (payload.model_dump_json(), now(), aid),
            )
            event(c, aid, u, "resubmitted")
        return {"ok": True}

    @app.post("/api/applications/{aid}/review")
    def review(aid: str, body: Review, u=Depends(admin)):
        if body.groups:
            raise HTTPException(422, "暂不提供部门资料")
        if body.decision != "approve" and not body.comment.strip():
            raise HTTPException(422, "请填写退回或拒绝原因")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = row(c, aid, u)
            check_version(r, body.version)
            if r["status"] != "submitted":
                raise HTTPException(409, "该申请已处理，请刷新")
            payload = ApplicationInput.model_validate_json(r["payload"])
            if body.groups and not payload.groups:
                raise HTTPException(422, "申请未要求部门资料，不能扩大批准范围")
            client = payload.client("app-" + aid + "-" + payload.environment)
            client.scopes = ["openid", "profile", "email"] + (
                ["groups"] if body.groups else []
            )
            client.authorization_policy = (
                "two_factor" if body.two_factor else "one_factor"
            )
            status = {
                "approve": "approved",
                "return": "returned",
                "reject": "rejected",
            }[body.decision]
            c.execute(
                "UPDATE applications SET status=?,reviewer=?,comment=?,approved=?,version=version+1,updated=? WHERE id=?",
                (
                    status,
                    u["username"],
                    body.comment,
                    client.model_dump_json() if status == "approved" else None,
                    now(),
                    aid,
                ),
            )
            event(c, aid, u, status, body.comment)
        return {"ok": True}

    @app.post("/api/applications/{aid}/publish")
    def publish(aid: str, body: Publish, u=Depends(fresh)):
        if not body.acknowledge_restart:
            raise HTTPException(400, "请确认发布会重启认证服务")
        jobs = a.call("GET", "/jobs")
        inv = a.call("GET", "/inventory")
        if body.reissue:
            with s.connect() as c:
                existing = row(c, aid, u)
            state = serialize(existing)
            approved = state["approved"]
            live = next(
                (
                    x
                    for x in inv["clients"]
                    if approved
                    and x["client_id"] == approved["client_id"]
                    and not x.get("disabled")
                    and x.get("editable")
                ),
                None,
            )
            if not live or approved["public"]:
                raise HTTPException(409, "仅已存在且可管理的后端客户端可以重新签发密钥")
            live_client = Client.model_validate(
                {k: v for k, v in live.items() if k in Client.model_fields}
            )
            if live_client.model_dump() != approved:
                raise HTTPException(
                    409, "客户端配置已变化，请先核对并重新申请，不能覆盖新的配置"
                )
            if (
                state["status"] == "publishing"
                or state["deployment_state"] == "attention"
            ):
                raise HTTPException(
                    409, "当前发布尚未完成或需要人工核查，请先处理发布记录"
                )
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = row(c, aid, u)
            check_version(r, body.version)
            allowed = (
                ("ready", "completed", "attention", "failed")
                if body.reissue
                else ("approved", "publishing", "failed")
            )
            if r["status"] not in allowed:
                raise HTTPException(409, "请先完成审批")
            previous = next((j for j in jobs if j["id"] == r["draft_id"]), None)
            if (
                not body.reissue
                and previous
                and previous["state"]
                in (
                    "queued",
                    "writing",
                    "checking",
                    "applied",
                    "rolling_back",
                    "attention",
                )
            ):
                raise HTTPException(409, "该发布已提交或需要人工核查，请刷新查看结果")
            client = Client.model_validate_json(r["approved"])
            p = ApplicationInput.model_validate_json(r["payload"])
            operation = "rotate" if body.reissue else r["operation"]
            if operation == "upsert" and any(
                x["client_id"] == client.client_id for x in inv["clients"]
            ):
                raise HTTPException(
                    409, "客户端已存在，请核查发布记录，不能覆盖已有客户端"
                )
            # Persist the exact change before contacting the agent, allowing safe retry after a lost response.
            if r["draft_id"] and not previous and not body.reissue:
                draft = c.execute(
                    "SELECT payload FROM drafts WHERE id=?", (r["draft_id"],)
                ).fetchone()
                change = AgentChange.model_validate_json(draft["payload"])
            else:
                jid = uuid4().hex
                plain, hashed = secret_pair() if not client.public else (None, None)
                change = AgentChange(
                    id=jid,
                    operation=operation,
                    client=client,
                    revision=inv["revision"],
                    secret_hash=hashed,
                )
                c.execute(
                    "INSERT INTO drafts(id,payload,owner,environment,created,validated) VALUES(?,?,?,?,?,0)",
                    (
                        jid,
                        change.model_dump_json(),
                        p.technical_owner,
                        p.environment,
                        now(),
                    ),
                )
                if r["draft_id"]:
                    c.execute(
                        "DELETE FROM deliveries WHERE draft_id=?", (r["draft_id"],)
                    )
                if plain:
                    did = uuid4().hex
                    c.execute(
                        "INSERT INTO deliveries VALUES(?,?,?,?,0)",
                        (did, jid, s.encrypt(plain, "delivery:" + did), now() + 86400),
                    )
            c.execute(
                "UPDATE applications SET status='publishing',draft_id=?,operation=?,claimed_at=NULL,acceptance='',updated=? WHERE id=?",
                (change.id, operation, now(), aid),
            )
        try:
            a.call("POST", "/validate", change.model_dump())
            with s.connect() as c:
                c.execute("UPDATE drafts SET validated=1 WHERE id=?", (change.id,))
            result = a.call("POST", "/deploy", change.model_dump())
        except HTTPException as exc:
            # A connection error may mean the agent accepted the job. Keep its id for reconciliation.
            if exc.status_code != 503:
                with s.connect() as c:
                    # No accepted job: a new revision can be generated on the next explicit retry.
                    latest = a.call("GET", "/jobs")
                    if not any(j["id"] == change.id for j in latest):
                        c.execute(
                            "DELETE FROM deliveries WHERE draft_id=?", (change.id,)
                        )
                        c.execute(
                            "UPDATE applications SET status='failed',draft_id=NULL,updated=? WHERE id=?",
                            (now(), aid),
                        )
            raise
        with s.connect() as c:
            c.execute("UPDATE drafts SET used=1 WHERE id=?", (change.id,))
            c.execute("UPDATE applications SET version=version+1 WHERE id=?", (aid,))
            event(c, aid, u, "reissuing" if body.reissue else "publishing")
            c.execute(
                "INSERT OR REPLACE INTO metadata VALUES(?,?,?)",
                (client.client_id, p.technical_owner, p.environment),
            )
        return result

    @app.post("/api/applications/{aid}/claim")
    def claim(aid: str, u=Depends(current)):
        with s.connect() as c:
            r = row(c, aid, u)
        if r["applicant"] != u["username"]:
            raise HTTPException(403, "仅申请人本人可以领取")
        d = serialize(r)
        if not d.get("parameters", {}).get("active"):
            raise HTTPException(409, "配置尚未生效或已经变更，请联系管理员")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row(c, aid, u)
            delivery = c.execute(
                "SELECT * FROM deliveries WHERE draft_id=? AND claimed=0 AND expires>=?",
                (r["draft_id"], now()),
            ).fetchone()
            if not delivery or r["claimed_at"]:
                raise HTTPException(410, "密钥已领取或已过期，请联系管理员轮换密钥")
            plain = s.decrypt(delivery["secret"], "delivery:" + delivery["id"])
            c.execute("DELETE FROM deliveries WHERE id=?", (delivery["id"],))
            c.execute(
                "UPDATE applications SET claimed_at=?,updated=? WHERE id=?",
                (now(), now(), aid),
            )
            event(c, aid, u, "claimed")
        return {"secret": plain}

    @app.post("/api/applications/{aid}/acceptance")
    def acceptance(aid: str, body: Acceptance, u=Depends(current)):
        with s.connect() as c:
            r = row(c, aid, u)
        check_version(r, body.version)
        if r["applicant"] != u["username"] or serialize(r)["status"] != "ready":
            raise HTTPException(409, "请在发布成功后由申请人提交验收结果")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = row(c, aid, u)
            check_version(r, body.version)
            c.execute(
                "UPDATE applications SET acceptance=?,version=version+1,updated=? WHERE id=?",
                (body.results, now(), aid),
            )
            event(c, aid, u, "acceptance-submitted", body.results)
        return {"ok": True}

    @app.post("/api/applications/{aid}/complete")
    def complete(aid: str, body: Revision, u=Depends(admin)):
        with s.connect() as c:
            r = row(c, aid, u)
        if serialize(r)["status"] != "ready" or not r["acceptance"]:
            raise HTTPException(409, "发布成功并提交验收结果后才能确认完成")
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = row(c, aid, u)
            check_version(r, body.version)
            c.execute(
                "UPDATE applications SET status='completed',version=version+1,updated=? WHERE id=?",
                (now(), aid),
            )
            event(c, aid, u, "completed")
        return {"ok": True}
