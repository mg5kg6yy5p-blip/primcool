from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/primcool"

    jwt_secret: str = "dev-secret-replace-me"
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 60

    admin_token: str | None = None

    resend_api_key: str | None = None
    notify_email: str | None = None

    allowed_origins: str = "https://primecoolservices.com,https://www.primecoolservices.com"

    def origin_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
