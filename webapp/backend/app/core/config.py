from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path


class Settings(BaseSettings):
    APP_ENV: str = "development"
    SECRET_KEY: str = Field(default="dev-secret-change-me")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_ISSUER: str = "ai-registry"
    JWT_AUDIENCE: str = "ai-registry"
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    DATABASE_URL: str = f"sqlite:///{Path(__file__).parents[3]}/data/registry.db"
    AWS_PROFILE: str | None = None
    AWS_DEFAULT_REGION: str = "ap-south-1"

    class Config:
        env_file = str(Path(__file__).parents[2] / ".env")
        case_sensitive = True


settings = Settings()
