import base64
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def secret_pair():
    plain = secrets.token_urlsafe(54)
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha512", plain.encode(), salt, 310000)
    encode = lambda b: base64.b64encode(b).decode().rstrip("=").replace("+", ".")
    return plain, f"$pbkdf2-sha512$310000${encode(salt)}${encode(derived)}"


class DB:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()
        os.chmod(self.path, 0o600)


def now():
    return int(time.time())
