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
            raise ValueError("登录回调地址存在重复项。修正建议：请检查并删除重复的回调地址。")
        for v in values:
            if len(v) > 2048 or re.search(r"[\s\x00-\x1f*]", v):
                raise ValueError("登录回调地址包含空格或非法字符。修正建议：每行填写一个完整合法的 URL，不能包含空格或通配符。")
            u = urlsplit(v)
            if (
                u.scheme not in ("https", "http")
                or not u.hostname
                or u.username
                or u.password
                or u.fragment
            ):
                raise ValueError(
                    "登录回调地址格式不正确。修正建议：必须使用完整的 http:// 或 https:// 地址，不能包含用户名密码或 # 锚点。"
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
            raise ValueError("用户资料范围（scopes）不合法。修正建议：必须包含 openid，且仅支持 openid、profile、email、groups、offline_access。")
        return list(dict.fromkeys(v))

    @model_validator(mode="after")
    def compatible(self):
        if self.public and (
            self.token_endpoint_auth_method != "none" or not self.require_pkce
        ):
            raise ValueError("公共客户端（纯前端应用）配置不兼容。修正建议：必须启用 PKCE，且客户端认证方式必须设置为 none。")
        if not self.public and self.token_endpoint_auth_method == "none":
            raise ValueError("后端 Web 应用必须配置认证方式。修正建议：请选择 client_secret_basic 或 client_secret_post。")
        if self.response_types != ["code"] or self.grant_types not in (
            ["authorization_code"],
            ["authorization_code", "refresh_token"],
        ):
            raise ValueError("授权模式不兼容。修正建议：当前仅支持 authorization_code（授权码模式），可选 refresh_token。")
        if "refresh_token" in self.grant_types and "offline_access" not in self.scopes:
            raise ValueError("刷新令牌配置不完整。修正建议：启用 refresh_token 时必须在用户资料范围中勾选或包含 offline_access。")
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
            raise ValueError("生产环境回调地址必须使用 HTTPS（检测到非 HTTPS 地址）。修正建议：如果是内部局域网服务，请将「接入环境」切换为「测试」或「开发」；如果是正式生产服务，请配置 SSL 证书并将回调地址修改为 https:// 开头。")
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
            raise ValueError("不支持的密钥摘要格式。修正建议：密钥摘要必须符合 PBKDF2-SHA512 格式。")
        return v
