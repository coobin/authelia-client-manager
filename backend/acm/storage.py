import base64
import json
import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .common import DB, now


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
""")

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
