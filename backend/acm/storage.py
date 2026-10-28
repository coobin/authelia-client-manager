import base64
import json
import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .common import DB, now


def open_storage(data):
    data = Path(data)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = data / "master.key"
    if not key.exists():
        if (data / "web.sqlite").exists():
            raise RuntimeError(
                "Database exists without its master key; restore the key before starting"
            )
        try:
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
    return Storage(data / "web.sqlite", key)


class Storage(DB):
    def __init__(self, path, key_path):
        super().__init__(path)
        self.key_path = Path(key_path)
        if not self.key_path.is_file():
            raise RuntimeError("Initialize the master key with python -m acm.cli init")
        self.aes = AESGCM(self.key_path.read_bytes())
        with self.connect() as c:
            c.executescript("""
CREATE TABLE IF NOT EXISTS admins(username TEXT PRIMARY KEY,password TEXT,totp BLOB,role TEXT);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,username TEXT,csrf TEXT,created INTEGER,seen INTEGER,reauth INTEGER);
CREATE TABLE IF NOT EXISTS drafts(id TEXT PRIMARY KEY,payload TEXT,owner TEXT,environment TEXT,created INTEGER,validated INTEGER,used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY,draft_id TEXT,secret BLOB,expires INTEGER,claimed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS metadata(client_id TEXT PRIMARY KEY,owner TEXT,environment TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER,actor TEXT,action TEXT,target TEXT);
CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY,count INTEGER,until INTEGER);
CREATE TABLE IF NOT EXISTS totp_enrollments(username TEXT PRIMARY KEY,secret BLOB,expires INTEGER);
CREATE TABLE IF NOT EXISTS applicants(username TEXT PRIMARY KEY,issuer TEXT NOT NULL,subject TEXT NOT NULL,name TEXT NOT NULL,email TEXT NOT NULL,UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS oidc_states(id TEXT PRIMARY KEY,browser TEXT NOT NULL,nonce TEXT NOT NULL,verifier BLOB NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,applicant TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,created INTEGER NOT NULL,updated INTEGER NOT NULL,reviewer TEXT NOT NULL DEFAULT '',comment TEXT NOT NULL DEFAULT '',approved TEXT,draft_id TEXT,claimed_at INTEGER,acceptance TEXT NOT NULL DEFAULT '',operation TEXT NOT NULL DEFAULT 'upsert');
CREATE TABLE IF NOT EXISTS application_events(id INTEGER PRIMARY KEY,application_id TEXT NOT NULL,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,comment TEXT NOT NULL DEFAULT '');
""")

        # Preserve legacy enrollment until explicitly changed by the administrator.
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            columns = {r["name"] for r in c.execute("PRAGMA table_info(admins)")}
            if "totp_enabled" not in columns:
                c.execute(
                    "ALTER TABLE admins ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0"
                )
                c.execute("UPDATE admins SET totp_enabled=1 WHERE totp IS NOT NULL")
            if "needs_setup" not in columns:
                c.execute(
                    "ALTER TABLE admins ADD COLUMN needs_setup INTEGER NOT NULL DEFAULT 0"
                )

    def setup_required(self, c):
        rows = c.execute("SELECT username,role,needs_setup FROM admins WHERE role='admin'").fetchall()
        return not rows or (
            len(rows) == 1
            and rows[0]["role"] == "admin"
            and bool(rows[0]["needs_setup"])
        )

    def encrypt(self, plain, context):
        nonce = secrets.token_bytes(12)
        return nonce + self.aes.encrypt(nonce, plain.encode(), context.encode())

    def decrypt(self, data, context):
        return self.aes.decrypt(data[:12], data[12:], context.encode()).decode()

    def audit(self, actor, action, target=""):
        with self.connect() as c:
            c.execute(
                "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
                (now(), actor, action, target),
            )

    def cleanup(self):
        with self.connect() as c:
            c.execute("DELETE FROM deliveries WHERE expires<? OR claimed=1", (now(),))
            c.execute("DELETE FROM totp_enrollments WHERE expires<?", (now(),))
            c.execute("DELETE FROM oidc_states WHERE expires<?", (now(),))
            c.execute(
                "DELETE FROM sessions WHERE created<? OR seen<?",
                (now() - 28800, now() - 1800),
            )

    def limit(self, key, maximum=8, window=300):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT * FROM limits WHERE key=?", (key,)).fetchone()
            if r and r["until"] > now():
                if r["count"] >= maximum:
                    return False
                c.execute("UPDATE limits SET count=count+1 WHERE key=?", (key,))
            else:
                c.execute(
                    "INSERT OR REPLACE INTO limits VALUES(?,?,?)",
                    (key, 1, now() + window),
                )
        return True
