from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import re


class Client(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._~-]+$")
    client_name: str = Field(min_length=1, max_length=150)
    public: bool = False
    redirect_uris: list[str] = Field(min_length=1, max_length=20)
    scopes: list[str] = ["openid", "profile", "email"]
    authorization_policy: Literal["one_factor", "two_factor"] = "one_factor"
    require_pkce: bool = True
    pkce_challenge_method: Literal["S256"] = "S256"
    token_endpoint_auth_method: Literal[
        "client_secret_basic", "client_secret_post", "none"
    ] = "client_secret_basic"
    grant_types: list[str] = ["authorization_code"]
    response_types: list[str] = ["code"]

    @field_validator("redirect_uris")
    @classmethod
    def uris(cls, values):
        if len(values) != len(set(values)):
            raise ValueError("回调地址不能重复")
        for v in values:
            if len(v) > 2048 or re.search(r"[\s\x00-\x1f*]", v):
                raise ValueError("回调地址包含不允许的字符")
            u = urlsplit(v)
            if (
                u.scheme not in ("https", "http")
                or not u.hostname
                or u.username
                or u.password
                or u.fragment
            ):
                raise ValueError(
                    "使用完整的 HTTP 或 HTTPS 回调地址，不含用户凭据或片段"
                )
        return values

    @field_validator("scopes")
    @classmethod
    def scope_check(cls, v):
        if "openid" not in v or set(v) - {
            "openid",
            "profile",
            "email",
            "groups",
            "offline_access",
        }:
            raise ValueError("请选择支持的资料范围，必须包含 openid")
        return list(dict.fromkeys(v))

    @model_validator(mode="after")
    def compatible(self):
        if self.public and (
            self.token_endpoint_auth_method != "none" or not self.require_pkce
        ):
            raise ValueError("公共客户端必须启用 PKCE 并使用 none 认证方式")
        if not self.public and self.token_endpoint_auth_method == "none":
            raise ValueError("后端客户端需要客户端认证")
        if self.response_types != ["code"] or self.grant_types not in (
            ["authorization_code"],
            ["authorization_code", "refresh_token"],
        ):
            raise ValueError("本版本支持授权码流程，可选 refresh_token")
        if "refresh_token" in self.grant_types and "offline_access" not in self.scopes:
            raise ValueError("刷新令牌需要 offline_access 范围")
        return self


class DraftInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["upsert", "disable", "rotate", "restore"] = "upsert"
    client: Client
    restore_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    environment: Literal["development", "test", "production"] = "production"
    owner: str = Field(default="", max_length=100)

    @model_validator(mode="after")
    def production_https(self):
        if (
            self.environment == "production"
            and self.operation != "disable"
            and any(not u.startswith("https://") for u in self.client.redirect_uris)
        ):
            raise ValueError("生产环境回调必须使用 HTTPS；旧 HTTP 回调请先评估后迁移")
        return self


class AgentChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    operation: Literal["upsert", "disable", "rotate", "restore"]
    client: Client
    restore_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    secret_hash: str | None = Field(default=None, max_length=300)

    @field_validator("secret_hash")
    @classmethod
    def supported_hash(cls, v):
        if v is not None and not re.fullmatch(
            r"\$pbkdf2-sha512\$310000\$[A-Za-z0-9./]{22}\$[A-Za-z0-9./]{86}", v
        ):
            raise ValueError("不支持的密钥摘要")
        return v
