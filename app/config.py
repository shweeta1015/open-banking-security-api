"""Application Configuration."""
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "OpenBankingSecurityAPI Simulator"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./open_banking_sim.db"

    # RSA Keys
    RSA_PRIVATE_KEY_PATH: str = "./.keys/private_key.pem"
    RSA_PUBLIC_KEY_PATH: str = "./.keys/public_key.pem"
    RSA_KEY_ID: str = "obs-key-2026-v1"

    # OAuth & JWT
    JWT_ISSUER: str = "https://auth.simulator.openbanking.local"
    JWT_AUDIENCE: str = "https://api.simulator.openbanking.local"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    AUTH_CODE_EXPIRE_SECONDS: int = 300

    # Rate Limiting
    DEFAULT_PARTNER_RATE_LIMIT: int = 60
    DEFAULT_ENDPOINT_RATE_LIMIT: int = 30

    # Replay Protection (DPoP)
    DPOP_PROOF_MAX_AGE_SECONDS: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def private_key_file(self) -> Path:
        return Path(self.RSA_PRIVATE_KEY_PATH)

    @property
    def public_key_file(self) -> Path:
        return Path(self.RSA_PUBLIC_KEY_PATH)


@lru_cache()
def get_settings() -> Settings:
    return Settings()
