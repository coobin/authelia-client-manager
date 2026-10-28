"""The only component permitted to read original provider configuration."""

import copy
import fcntl
import io
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from uuid import uuid4
import docker
from ruamel.yaml import YAML
from acm.common import DB, digest, now
from acm.models import AgentChange

FIELDS = {
    "client_id",
    "client_name",
    "public",
    "authorization_policy",
    "redirect_uris",
    "scopes",
    "require_pkce",
    "pkce_challenge_method",
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
}
SECRET_WORDS = ("secret", "password", "private_key")


class GuardError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def atomic(path, data, mode=0o600, uid=None, gid=None):
    path = Path(path)
    tmp = path.with_name(".acm-" + uuid4().hex)
    try:
        with open(tmp, "xb") as f:
            os.chmod(tmp, mode)
            if uid is not None:
                os.chown(tmp, uid, gid)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


class Engine:
    def __init__(
        self,
        config,
        state,
        *,
        demo=False,
        writable=False,
        target="",
        inside="/config/configuration.yml",
        issuer="",
    ):
        self.config = Path(config)
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.demo, self.writable, self.target, self.inside, self.issuer = (
            demo,
            writable,
            target,
            inside,
            issuer,
        )
        self.lock = threading.Lock()
        self.db = DB(self.state / "agent.sqlite")
        with self.db.connect() as c:
            c.executescript(
                """CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,state TEXT NOT NULL,base TEXT,candidate TEXT,created INTEGER,updated INTEGER,message TEXT,backup TEXT,operation TEXT,client_id TEXT);"""
            )
        self.y = YAML(typ="rt")
        self.y.allow_duplicate_keys = False
        self.y.preserve_quotes = True

    def load(self):
        if self.config.is_symlink() or self.config.stat().st_size > 2_000_000:
            raise GuardError("配置路径或大小不受支持")
        raw = self.config.read_bytes()
        if b"{{" in raw or b"${" in raw:
            raise GuardError("模板配置暂仅支持只读处理", 409)
        try:
            obj = self.y.load(raw)
        except Exception:
            raise GuardError("配置 YAML 无法安全解析", 409)

        def walk(v, depth=0, seen=None):
            seen = set() if seen is None else seen
            if depth > 25:
                raise GuardError("配置嵌套过深", 409)
            if isinstance(v, (list, dict)):
                if id(v) in seen:
                    raise GuardError("配置别名暂不支持", 409)
                seen.add(id(v))
                for x in (v.values() if isinstance(v, dict) else v):
                    walk(x, depth + 1, seen)
            if hasattr(v, "anchor") and v.anchor.value:
                raise GuardError("配置别名暂不支持", 409)
            if hasattr(v, "tag") and str(v.tag).startswith("!"):
                raise GuardError("配置标签暂不支持", 409)

        walk(obj)
        try:
            clients = obj["identity_providers"]["oidc"]["clients"]
        except (KeyError, TypeError):
            raise GuardError("未找到 OIDC 客户端列表", 409)
        if not isinstance(clients, list) or len(clients) > 500:
            raise GuardError("客户端列表不受支持", 409)
        ids = [v.get("client_id") for v in clients]
        if len(ids) != len(set(ids)) or None in ids:
            raise GuardError("客户端标识存在重复或缺失", 409)
        return raw, obj, clients

    def inventory(self):
        with self.lock:
            raw, _, clients = self.load()
            clean = []
            for x in clients:
                item = {k: copy.deepcopy(v) for k, v in x.items() if k in FIELDS}
                item["has_secret"] = bool(x.get("client_secret"))
                item["extra_fields"] = [
                    k for k in x if k not in FIELDS and k != "client_secret"
                ]
                # Advanced existing clients remain visible but cannot be destructively normalized.
                try:
                    from acm.models import Client

                    Client.model_validate(
                        {k: v for k, v in item.items() if k in FIELDS}
                    )
                    item["editable"] = True
                except Exception:
                    item["editable"] = False
                clean.append(item)
            # Disabled entries are reconstructed only from private successful snapshots.
            live_ids = {x["client_id"] for x in clients}
            with self.db.connect() as db:
                disabled = db.execute(
                    "SELECT * FROM jobs WHERE operation='disable' AND state='applied' ORDER BY created DESC,rowid DESC"
                ).fetchall()
            for job in disabled:
                if job["client_id"] in live_ids:
                    continue
                try:
                    old = self.y.load(Path(job["backup"]).read_bytes())[
                        "identity_providers"
                    ]["oidc"]["clients"]
                    original = next(
                        x for x in old if x["client_id"] == job["client_id"]
                    )
                    item = {
                        k: copy.deepcopy(v) for k, v in original.items() if k in FIELDS
                    }
                    item.update(
                        has_secret=bool(original.get("client_secret")),
                        extra_fields=[],
                        editable=True,
                        disabled=True,
                        restore_id=job["id"],
                    )
                    clean.append(item)
                    live_ids.add(job["client_id"])
                except Exception:
                    continue
            return {
                "revision": digest(raw),
                "clients": clean,
                "writable": self.writable,
                "demo": self.demo,
                "issuer": self.issuer,
                "version": "0.1.0",
            }

    def candidate(self, ch):
        raw, obj, clients = self.load()
        if digest(raw) != ch.revision:
            raise GuardError("生产配置已变化，请刷新后重新创建草稿", 409)
        before = copy.deepcopy(obj)
        match = next(
            (x for x in clients if x["client_id"] == ch.client.client_id), None
        )
        if ch.operation == "disable":
            if match is None:
                raise GuardError("应用已经停用或不存在", 409)
            clients.remove(match)
        elif ch.operation == "restore":
            if match is not None:
                raise GuardError("客户端已存在，不能覆盖恢复", 409)
            with self.db.connect() as db:
                job = db.execute(
                    "SELECT * FROM jobs WHERE id=? AND operation='disable' AND state='applied'",
                    (ch.restore_id,),
                ).fetchone()
            if not job or job["client_id"] != ch.client.client_id:
                raise GuardError("恢复来源无效", 409)
            old = self.y.load(Path(job["backup"]).read_bytes())["identity_providers"][
                "oidc"
            ]["clients"]
            clients.append(
                copy.deepcopy(
                    next(x for x in old if x["client_id"] == ch.client.client_id)
                )
            )
        elif ch.operation == "rotate":
            if match is None or match.get("public", False):
                raise GuardError("只能轮换已有后端客户端的密钥")
            if not ch.secret_hash:
                raise GuardError("缺少新密钥摘要")
            match["client_secret"] = ch.secret_hash
        else:
            if match is None:
                match = {}
                clients.append(match)
                if not ch.client.public and not ch.secret_hash:
                    raise GuardError("新后端应用需要生成密钥")
            elif bool(match.get("public", False)) != ch.client.public:
                raise GuardError("已有客户端不支持直接切换类型，请新建客户端")
            match.update(ch.client.model_dump())
            if ch.client.public:
                match.pop("client_secret", None)
            elif ch.secret_hash:
                match["client_secret"] = ch.secret_hash
        a = copy.deepcopy(before)
        b = copy.deepcopy(obj)
        a["identity_providers"]["oidc"]["clients"] = []
        b["identity_providers"]["oidc"]["clients"] = []
        if a != b:
            raise GuardError("变更越过客户端配置边界", 409)
        old_other = [
            v
            for v in before["identity_providers"]["oidc"]["clients"]
            if v["client_id"] != ch.client.client_id
        ]
        new_other = [v for v in clients if v["client_id"] != ch.client.client_id]
        if old_other != new_other:
            raise GuardError("其他客户端发生变化", 409)
        s = io.StringIO()
        self.y.dump(obj, s)
        return raw, s.getvalue().encode()

    def _container(self, check_version=True):
        try:
            d = docker.from_env(timeout=20)
            ct = d.containers.get(self.target)
            ct.reload()
            env = ct.attrs["Config"].get("Env", [])
            config = [
                e.split("=", 1)[1] for e in env if e.startswith("X_AUTHELIA_CONFIG=")
            ]
            if config != [self.inside]:
                raise GuardError("目标配置加载路径不符合支持模式", 409)
            if any(
                e.startswith("AUTHELIA_IDENTITY_PROVIDERS_")
                or e.startswith("X_AUTHELIA_CONFIG_")
                for e in env
            ):
                raise GuardError("目标存在未支持的覆盖配置", 409)
            if ct.attrs["Config"].get("Cmd") and any(
                x in ("-c", "--config") or x.startswith("--config=")
                for x in ct.attrs["Config"]["Cmd"]
            ):
                raise GuardError("目标含额外加载参数", 409)
            if check_version:
                version = ct.exec_run(["authelia", "--version"]).output.decode()
                if not re.search(r"v4\.39\.1(?:\s|$)", version):
                    raise GuardError("尚未验证该 Authelia 版本，发布已阻止", 409)
            return ct
        except GuardError:
            raise
        except Exception:
            raise GuardError("无法连接指定的认证实例", 503)

    def validate(self, ch):
        with self.lock:
            raw, data = self.candidate(ch)
            before = self.y.load(raw)["identity_providers"]["oidc"]["clients"]
            after = self.y.load(data)["identity_providers"]["oidc"]["clients"]
            old = next((x for x in before if x["client_id"] == ch.client.client_id), {})
            new = next((x for x in after if x["client_id"] == ch.client.client_id), {})
            changes = []
            for k in sorted(FIELDS | {"client_secret"}):
                if old.get(k) != new.get(k):
                    changes.append(
                        {
                            "field": k,
                            "before": (
                                ("[已配置]" if old.get(k) else "[未配置]")
                                if k == "client_secret"
                                else old.get(k)
                            ),
                            "after": (
                                ("[新密钥摘要]" if new.get(k) else "[未配置]")
                                if k == "client_secret"
                                else new.get(k)
                            ),
                        }
                    )
            self.native_validate(data)
            return {
                "valid": True,
                "demo": self.demo,
                "message": (
                    "配置检查通过"
                    if not self.demo
                    else "演示结构检查通过；未连接生产实例"
                ),
                "client_id": ch.client.client_id,
                "operation": ch.operation,
                "candidate": digest(data),
                "changes": changes,
            }

    def native_validate(self, data):
        if self.demo:
            return
        ct = self._container()
        stage = self.config.parent / (".acm-validate-" + uuid4().hex + ".yml")
        inside = str(Path(self.inside).parent / stage.name)
        try:
            atomic(stage, data, mode=0o600)
            # Container root executes a read-only validation command, not a second server.
            result = ct.exec_run(
                ["authelia", "validate-config", "--config", inside], user="0"
            )
            if result.exit_code != 0:
                # Never relay parser output: it can contain secret YAML values.
                raise GuardError("Authelia 原生校验未通过；未修改生产文件", 422)
        finally:
            stage.unlink(missing_ok=True)

    def jobs(self):
        with self.db.connect() as c:
            return [
                dict(r)
                for r in c.execute(
                    "SELECT id,state,created,updated,message,operation,client_id FROM jobs ORDER BY created DESC,rowid DESC LIMIT 100"
                )
            ]

    def verify_client(self, change):
        """Check the receipt against live configuration without revealing its secret."""
        from acm.models import Client

        with self.lock:
            _, _, clients = self.load()
            with self.db.connect() as c:
                job = c.execute(
                    "SELECT state,message FROM jobs WHERE id=? AND client_id=?",
                    (change.id, change.client.client_id),
                ).fetchone()
                pending = c.execute(
                    "SELECT 1 FROM jobs WHERE client_id=? AND id<>? AND state IN ('queued','writing','checking','rolling_back','attention')",
                    (change.client.client_id, change.id),
                ).fetchone()
            active = False
            live = next(
                (x for x in clients if x.get("client_id") == change.client.client_id),
                None,
            )
            if job and job["state"] == "applied" and live and not pending:
                try:
                    configured = Client.model_validate(
                        {k: v for k, v in live.items() if k in FIELDS}
                    )
                    active = (
                        configured == change.client
                        and not (set(live) - FIELDS - {"client_secret"})
                        and (
                            not live.get("client_secret")
                            if change.client.public
                            else bool(change.secret_hash)
                            and live.get("client_secret") == change.secret_hash
                        )
                    )
                except Exception:
                    active = False
            return {
                "active": active,
                "state": job["state"] if job else None,
                "message": job["message"] if job else "",
            }

    def update(self, jid, state, message):
        with self.db.connect() as c:
            c.execute(
                "UPDATE jobs SET state=?,message=?,updated=? WHERE id=?",
                (state, message, now(), jid),
            )

    def health(self):
        if self.demo:
            return True
        ct = self._container(check_version=False)
        for _ in range(30):
            ct.reload()
            state = ct.attrs["State"]
            if state.get("Health", {}).get("Status") == "healthy":
                import httpx

                try:
                    from urllib.parse import urlsplit

                    u = urlsplit(self.issuer)
                    r = ct.exec_run(
                        [
                            "wget",
                            "-T",
                            "5",
                            "-qO-",
                            "--header",
                            "Host: " + u.netloc,
                            "--header",
                            "X-Forwarded-Proto: " + u.scheme,
                            "--header",
                            "X-Forwarded-Host: " + u.netloc,
                            "http://127.0.0.1:9091/.well-known/openid-configuration",
                        ]
                    )
                    doc = json.loads(r.output)
                    return r.exit_code == 0 and doc.get("issuer") == self.issuer
                except Exception:
                    return False
            if state.get("Status") in ("exited", "dead"):
                return False
            time.sleep(2)
        return False

    def restart(self):
        if not self.demo:
            self._container(check_version=False).restart(timeout=10)

    def deploy(self, ch):
        if not self.writable:
            raise GuardError("当前为只读模式，管理员尚未启用发布", 403)
        # Idempotency is checked before revalidating a now-stale original revision.
        with self.db.connect() as c:
            if c.execute("SELECT id FROM jobs WHERE id=?", (ch.id,)).fetchone():
                return {"id": ch.id}
        self.validate(ch)
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT id FROM jobs WHERE id=?", (ch.id,)).fetchone():
                return {"id": ch.id}
            if c.execute(
                "SELECT id FROM jobs WHERE state IN ('queued','writing','checking','rolling_back')"
            ).fetchone():
                raise GuardError("已有发布任务正在执行", 409)
            c.execute(
                "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    ch.id,
                    "queued",
                    ch.revision,
                    None,
                    now(),
                    now(),
                    "等待执行",
                    None,
                    ch.operation,
                    ch.client.client_id,
                ),
            )
        threading.Thread(target=self.execute, args=(ch,), daemon=True).start()
        return {"id": ch.id}

    def execute(self, ch):
        with self.lock, open(self.state / "publish.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                import shutil

                if (
                    min(
                        shutil.disk_usage(self.config.parent).free,
                        shutil.disk_usage(self.state).free,
                    )
                    < 50_000_000
                ):
                    raise GuardError("磁盘空间不足，已停止发布")
                raw, data = self.candidate(ch)
                self.native_validate(data)
                backup = self.state / (ch.id + ".backup")
                atomic(backup, raw)
                with self.db.connect() as c:
                    c.execute(
                        "UPDATE jobs SET candidate=?,backup=? WHERE id=?",
                        (digest(data), str(backup), ch.id),
                    )
                if digest(self.config.read_bytes()) != ch.revision:
                    raise GuardError("外部配置变化，已停止发布", 409)
                self.update(ch.id, "writing", "正在应用配置")
                st = self.config.stat()
                atomic(self.config, data, st.st_mode & 0o777, st.st_uid, st.st_gid)
                self.update(ch.id, "checking", "正在重启并检查认证服务")
                self.restart()
                if not self.health():
                    raise GuardError("认证服务未通过检查")
                self.update(ch.id, "applied", "发布成功")
            except Exception as exc:
                self._recover_one(ch.id, "发布失败")
            finally:
                (self.state / (ch.id + ".request")).unlink(missing_ok=True)

    def _recover_one(self, jid, reason):
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if row is None:
            return
        current = digest(self.config.read_bytes())
        if row["candidate"] and current == row["candidate"] and row["backup"]:
            try:
                self.update(jid, "rolling_back", reason + "，正在恢复")
                st = self.config.stat()
                atomic(
                    self.config,
                    Path(row["backup"]).read_bytes(),
                    st.st_mode & 0o777,
                    st.st_uid,
                    st.st_gid,
                )
                self.restart()
                healthy = self.health()
                self.update(
                    jid,
                    "rolled_back" if healthy else "attention",
                    "已恢复上一版" if healthy else "恢复检查失败，需要服务器处理",
                )
            except Exception:
                self.update(jid, "attention", "恢复失败，需要服务器处理")
        elif current == row["base"]:
            self.update(jid, "failed", reason + "；生产配置未变化")
        else:
            self.update(jid, "attention", "配置已由其他渠道变化，停止自动恢复")

    def recover(self):
        with self.db.connect() as c:
            rows = c.execute(
                "SELECT id FROM jobs WHERE state IN ('queued','writing','checking','rolling_back')"
            ).fetchall()
        for r in rows:
            self._recover_one(r["id"], "代理恢复中断任务")

    def rollback(self, jid, newid):
        if not self.writable:
            raise GuardError("只读模式", 403)
        with self.lock, open(self.state / "publish.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.db.connect() as c:
                rows = c.execute(
                    "SELECT * FROM jobs ORDER BY created DESC,rowid DESC"
                ).fetchall()
                row = next((r for r in rows if r["id"] == jid), None)
                if not row or rows[0]["id"] != jid or row["state"] != "applied":
                    raise GuardError("仅支持回滚最新成功发布", 409)
                if digest(self.config.read_bytes()) != row["candidate"]:
                    raise GuardError("配置已有外部变化，不能覆盖", 409)
            data = Path(row["backup"]).read_bytes()
            self.native_validate(data)
            original = self.config.read_bytes()
            backup = self.state / (newid + ".backup")
            atomic(backup, original)
            with self.db.connect() as c:
                c.execute(
                    "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        newid,
                        "queued",
                        digest(original),
                        digest(data),
                        now(),
                        now(),
                        "回滚排队",
                        str(backup),
                        "rollback",
                        row["client_id"],
                    ),
                )
            # Record before replacement so process recovery can compensate safely.
            try:
                self.update(newid, "writing", "正在恢复配置")
                st = self.config.stat()
                atomic(self.config, data, st.st_mode & 0o777, st.st_uid, st.st_gid)
                self.restart()
                if not self.health():
                    raise GuardError("恢复后检查失败")
                self.update(newid, "applied", "已回滚上一笔变更")
            except Exception:
                self._recover_one(newid, "回滚失败")
            return {"id": newid}
