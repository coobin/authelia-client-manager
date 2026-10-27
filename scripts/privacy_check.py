"""Conservative source scan. Not a replacement for full-history secret scanners."""

import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
r = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
    cwd=root,
    text=True,
    capture_output=True,
)
paths = (
    r.stdout.splitlines()
    if r.returncode == 0
    else [
        str(x.relative_to(root))
        for x in root.rglob("*")
        if x.is_file()
        and not any(
            p
            in {
                ".venv",
                "node_modules",
                "runtime",
                ".git",
                "dist",
                "__pycache__",
                ".pytest_cache",
            }
            for p in x.parts
        )
    ]
)
patterns = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}"),
    re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b"),
    re.compile("/" + r"Users/[^/\s]+/"),
    re.compile("/" + r"home/[^/\s]+/"),
]
errors = []
for name in paths:
    p = root / name
    if not p.is_file() or "egg-info" in name:
        continue
    try:
        t = p.read_text()
    except UnicodeError:
        continue
    if any(x.search(t) for x in patterns):
        errors.append(name)
if errors:
    raise SystemExit(
        "Review potential private content in: " + ", ".join(sorted(set(errors)))
    )
print("Source privacy-pattern check passed.")
