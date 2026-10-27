"""Optional host recovery commands. New installations initialize in the browser."""

import argparse
import getpass
import os
import secrets
from pathlib import Path
from argon2 import PasswordHasher
import pyotp
from .storage import open_storage


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "command", choices=["init", "create-admin", "reset-admin", "prepare-setup"]
    )
    p.add_argument("--data", default=os.getenv("ACM_DATA", "runtime/web"))
    p.add_argument("--username", default="admin")
    p.add_argument("--role", choices=["admin", "viewer"], default="admin")
    p.add_argument("--enable-totp", action="store_true")
    p.add_argument(
        "--bundle", help="Optional private generated recovery credential file"
    )
    a = p.parse_args()
    s = open_storage(a.data)
    if a.command == "init":
        print("Initialized. Open the browser to create your administrator account.")
        return
    if a.command == "prepare-setup":
        with s.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            rows = c.execute("SELECT username,role FROM admins").fetchall()
            if (
                len(rows) != 1
                or rows[0]["username"] != a.username
                or rows[0]["role"] != "admin"
            ):
                raise SystemExit(
                    "Web setup transition requires exactly one designated administrator; no changes made"
                )
            c.execute(
                "UPDATE admins SET needs_setup=1,totp_enabled=0,totp=NULL WHERE username=?",
                (a.username,),
            )
            c.execute("DELETE FROM sessions")
            c.execute("DELETE FROM totp_enrollments")
        s.audit("host-cli", "web-setup-prepared", a.username)
        print("Web administrator setup prepared. Application records were preserved.")
        return
    if a.bundle and Path(a.bundle).exists():
        raise SystemExit("Bundle exists; no changes made")
    password = (
        secrets.token_urlsafe(24)
        if a.bundle
        else getpass.getpass("New password (minimum 8 characters): ")
    )
    if len(password) < 8:
        raise SystemExit("Password must contain at least 8 characters")
    seed = pyotp.random_base32() if a.enable_totp else None
    with s.connect() as c:
        exists = c.execute(
            "SELECT 1 FROM admins WHERE username=?", (a.username,)
        ).fetchone()
        if exists and a.command != "reset-admin":
            raise SystemExit("Account exists; no changes made")
        if not exists and a.command == "reset-admin":
            raise SystemExit("Account does not exist")
        c.execute(
            "INSERT OR REPLACE INTO admins(username,password,totp,role,totp_enabled,needs_setup) VALUES(?,?,?,?,?,0)",
            (
                a.username,
                PasswordHasher().hash(password),
                s.encrypt(seed, "totp:" + a.username) if seed else None,
                a.role,
                int(bool(seed)),
            ),
        )
        c.execute("DELETE FROM sessions WHERE username=?", (a.username,))
        c.execute("DELETE FROM totp_enrollments WHERE username=?", (a.username,))
    text = "Username: " + a.username + "\nPassword: " + password + "\n"
    if seed:
        text += (
            "TOTP secret: "
            + seed
            + "\nTOTP URI: "
            + pyotp.TOTP(seed).provisioning_uri(
                a.username, issuer_name="Authelia Client Manager"
            )
            + "\n"
        )
    if a.bundle:
        fd = os.open(a.bundle, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        print("Credentials written to the private recovery bundle.")
    elif seed:
        print(
            "Private TOTP setup URI: "
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
