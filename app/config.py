"""
AegisSec Configuration

Centralized configuration using pydantic-settings.
All sensitive values are loaded from environment variables.
Never hardcode secrets — this is a core DevSecOps principle.
"""
import os
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    app_name: str = "AegisSec"
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "change-this-to-a-random-secret-key-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Database
    database_url: str = "sqlite:///./aegissec.db"

    # AI Assistant (Optional)
    openai_api_key: str = ""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    model_config = ConfigDict(env_file=".env", case_sensitive=False)


@lru_cache()
def get_settings() -> Settings:
    """Cache settings to avoid re-reading .env on every request."""
    return Settings()
