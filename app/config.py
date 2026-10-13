import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "Real-Time Threat Intelligence Cache and Malicious URL/IP Detection System Using Redis"
    APP_ENV: str = "development"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Redis Configuration
    REDIS_URL: str = "redis://127.0.0.1:6379/0"
    REDIS_TIMEOUT_SECONDS: float = 2.0
    REDIS_MAX_CONNECTIONS: int = 20

    # Threat Intelligence Provider: "demo" or "virustotal"
    CTI_PROVIDER: str = "demo"

    # VirusTotal Provider Credentials
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_TIMEOUT_SECONDS: float = 5.0

    # Cache TTL Policies (in seconds)
    TTL_MALICIOUS_SECONDS: int = 7200
    TTL_BENIGN_SECONDS: int = 3600
    TTL_UNKNOWN_SECONDS: int = 300

    # Security & Admin
    ADMIN_API_KEY: str = "adminkey-threat-intel-2026-secure"
    ALERT_RISK_THRESHOLD: int = 75

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]


settings = Settings()
