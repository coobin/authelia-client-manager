import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from acm.models import AgentChange
from agent.engine import Engine, GuardError


def create_app(engine=None):
    e = engine or Engine(
        os.environ["ACM_CONFIG"],
        os.environ.get("ACM_AGENT_STATE", "/state"),
        demo=os.getenv("ACM_DEMO") == "1",
        writable=os.getenv("ACM_WRITABLE") == "1",
        target=os.getenv("ACM_TARGET", ""),
        inside=os.getenv("ACM_INSIDE_CONFIG", "/config/configuration.yml"),
        issuer=os.getenv("ACM_ISSUER", "https://auth.example.com"),
    )

    @asynccontextmanager
    async def lifespan(app):
        e.recover()
        yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine = e

    @app.exception_handler(GuardError)
    async def guard(req, exc):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    @app.get("/inventory")
    def inventory():
        return e.inventory()

    @app.post("/validate")
    def validate(ch: AgentChange):
        return e.validate(ch)

    @app.post("/deploy")
    def deploy(ch: AgentChange):
        return e.deploy(ch)

    @app.get("/jobs")
    def jobs():
        return e.jobs()

    class Rollback(BaseModel):
        id: str = Field(pattern=r"^[a-f0-9]{32}$")
        new_id: str = Field(pattern=r"^[a-f0-9]{32}$")

    @app.post("/rollback")
    def rollback(r: Rollback):
        return e.rollback(r.id, r.new_id)

    return app
