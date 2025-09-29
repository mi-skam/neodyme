from typing import Any, Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Neodyme API"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"

    # Database
    database_url: str = Field(
        description="Database URL for SQLAlchemy. Use 'sqlite+aiosqlite:///./test.db' for SQLite or 'postgresql+asyncpg://user:pass@localhost/db' for PostgreSQL"
    )

    # API
    api_v1_prefix: str = "/api/v1"
    docs_url: str | None = "/docs"
    redoc_url: str | None = "/redoc"

    # Security
    secret_key: str = Field(min_length=32, description="Secret key for JWT tokens")
    access_token_expire_minutes: int = 30

    @computed_field  # type: ignore[misc]
    @property
    def database_engine_options(self) -> dict[str, Any]:
        if self.database_url.startswith("sqlite"):
            return {
                "echo": self.debug,
                "pool_pre_ping": True,
                "connect_args": {"check_same_thread": False},
            }
        else:
            return {
                "echo": self.debug,
                "pool_pre_ping": True,
                "pool_size": 10,
                "max_overflow": 20,
            }

    @computed_field  # type: ignore[misc]
    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


settings = Settings()
