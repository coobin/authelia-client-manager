"""Host-only bootstrap. No default administrator or open signup endpoint."""

import argparse
import getpass
import os
import secrets
from pathlib import Path
from argon2 import PasswordHasher
import pyotp
from .storage import Storage


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["init", "create-admin", "reset-admin"])
    p.add_argument("--data", default=os.getenv("ACM_DATA", "runtime/web"))
    p.add_argument("--username", default="admin")
    p.add_argument("--role", choices=["admin", "viewer"], default="admin")
    p.add_argument(
        "--bundle", help="Write generated initial credentials to this private file"
    )
    a = p.parse_args()
    d = Path(a.data)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = d / "master.key"
    if not key.exists():
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    s = Storage(d / "web.sqlite", key)
    if a.command == "init":
        print("Initialized.")
        return
    password = (
        secrets.token_urlsafe(24)
        if a.bundle
        else getpass.getpass("New password (minimum 14 characters): ")
    )
    if len(password) < 14:
        raise SystemExit("Password must contain at least 14 characters")
    if a.bundle and Path(a.bundle).exists():
        raise SystemExit("Bundle file already exists; no changes made")
    seed = pyotp.random_base32()
    with s.connect() as c:
        exists = c.execute(
            "SELECT 1 FROM admins WHERE username=?", (a.username,)
        ).fetchone()
        if exists and a.command != "reset-admin":
            raise SystemExit("Account exists; no changes made")
        if not exists and a.command == "reset-admin":
            raise SystemExit("Account does not exist")
        c.execute(
            "INSERT OR REPLACE INTO admins VALUES(?,?,?,?)",
            (
                a.username,
                PasswordHasher().hash(password),
                s.encrypt(seed, "totp:" + a.username),
                a.role,
            ),
        )
        c.execute("DELETE FROM sessions WHERE username=?", (a.username,))
    if a.bundle:
        path = Path(a.bundle)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(
                "Username: "
                + a.username
                + "\nPassword: "
                + password
                + "\nTOTP secret: "
                + seed
                + "\nTOTP URI: "
                + pyotp.TOTP(seed).provisioning_uri(
                    a.username, issuer_name="Authelia Client Manager"
                )
                + "\n"
            )
        print("Administrator created. Credentials written to the private bundle file.")
    else:
        print(
            "TOTP setup URI (store privately): "
            + pyotp.TOTP(seed).provisioning_uri(
                a.username, issuer_name="Authelia Client Manager"
            )
        )
    s.audit(
        "host-cli",
        (
            "administrator-reset"
            if a.command == "reset-admin"
            else "administrator-created"
        ),
        a.username,
    )


if __name__ == "__main__":
    main()
