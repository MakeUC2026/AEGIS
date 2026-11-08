"""Runtime settings, validated at startup (CONST-SEC-001: secrets only from env).

`AEGIS_AUTH_MODE=dev` (local JWKS, dev login) is refused when APP_ENV=production.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_PROXY_SECRET_LEN = 32
HOURLY_MESSAGE_CAP = 30  # PRD §6.1
AFF_TIMEOUT_S = 30.0  # PRD §6.3: AFF unreachable or 30 s timeout -> not sent
DEFAULT_DAILY_LLM_BUDGET = 3000  # global model calls per UTC day (PRD §15.1 Cost)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = Field(default="", alias="DATABASE_URL")

    # Auth (PRD §3.2, §4.3)
    auth_mode: Literal["auth0", "dev"] = Field(default="auth0", alias="AEGIS_AUTH_MODE")
    auth0_domain: str = Field(default="", alias="AUTH0_DOMAIN")
    auth0_audience: str = Field(default="", alias="AUTH0_AUDIENCE")
    dev_jwt_public_key: str = Field(default="", alias="AEGIS_DEV_JWT_PUBLIC_KEY")
    dev_jwt_issuer: str = Field(default="aegis-dev", alias="AEGIS_DEV_JWT_ISSUER")
    dev_jwt_audience: str = Field(default="aegis-dev-api", alias="AEGIS_DEV_JWT_AUDIENCE")

    # Next.js -> FastAPI trust boundary (PRD §8.5, §15.1)
    proxy_secret: SecretStr = Field(default=SecretStr(""), alias="AEGIS_PROXY_SECRET")

    # Seams (M1 §0.3): which contracts are faked on this branch; dev keyword script for the fake
    use_fakes: str = Field(default="", alias="AEGIS_USE_FAKES")
    fake_script: str = Field(default="", alias="AEGIS_FAKE_SCRIPT")

    # Arena limits
    hourly_message_cap: int = Field(default=HOURLY_MESSAGE_CAP, alias="AEGIS_HOURLY_MESSAGE_CAP")
    daily_llm_budget: int = Field(default=DEFAULT_DAILY_LLM_BUDGET, alias="AEGIS_DAILY_LLM_BUDGET")
    aff_timeout_s: float = Field(default=AFF_TIMEOUT_S, alias="AEGIS_AFF_TIMEOUT_S")

    # Models (pinned at G0, PRD §18.2)
    gemini_api_key: SecretStr = Field(default=SecretStr(""), alias="GEMINI_API_KEY")
    bot_model_id: str = Field(default="", alias="AEGIS_BOT_MODEL_ID")  # Gemini, the arena bot
    gemini_flash_model_id: str = Field(default="", alias="AEGIS_GEMINI_FLASH_MODEL_ID")
    gemini_pro_model_id: str = Field(default="", alias="AEGIS_GEMINI_PRO_MODEL_ID")
    gemini_embedding_model_id: str = Field(default="", alias="AEGIS_GEMINI_EMBEDDING_MODEL_ID")

    @field_validator("dev_jwt_public_key")
    @classmethod
    def _unescape_pem(cls, value: str) -> str:
        # .env stores PEMs on one line with "\n" escapes; a shell `source` keeps them literal.
        return value.replace("\\n", "\n")

    @model_validator(mode="after")
    def _guard(self) -> Settings:
        if self.app_env == "production":
            if self.auth_mode == "dev":
                raise ValueError("AEGIS_AUTH_MODE=dev is not allowed in production")
            if len(self.proxy_secret.get_secret_value()) < MIN_PROXY_SECRET_LEN:
                raise ValueError("AEGIS_PROXY_SECRET must be at least 32 characters in production")
            if not (self.auth0_domain and self.auth0_audience):
                raise ValueError("AUTH0_DOMAIN and AUTH0_AUDIENCE are required in production")
        if self.auth_mode == "dev" and not self.dev_jwt_public_key:
            raise ValueError("AEGIS_AUTH_MODE=dev needs AEGIS_DEV_JWT_PUBLIC_KEY")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
