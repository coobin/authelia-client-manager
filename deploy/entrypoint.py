import os
from pathlib import Path
import uvicorn

if os.getenv("ACM_ROLE") == "agent":
    sock = os.getenv("ACM_AGENT_SOCKET", "/run/acm/agent.sock")
    Path(sock).parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    uvicorn.run("agent.main:create_app", factory=True, uds=sock, access_log=False)
else:
    uvicorn.run(
        "acm.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=8098,
        access_log=False,
        proxy_headers=False,
    )
