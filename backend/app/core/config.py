from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    FERNET_KEY: str
    NVD_API_KEY: str = ""
    OTX_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    DARAJA_CONSUMER_KEY: str = ""
    DARAJA_CONSUMER_SECRET: str = ""
    DARAJA_SHORTCODE: str = ""
    DARAJA_PASSKEY: str = ""
    DARAJA_CALLBACK_URL: str = ""
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    ENVIRONMENT: str = "development"
    MODEL_BASE_PATH: str
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    ADMIN_USERNAME: str
    ADMIN_PASSWORD: str

    # Anomaly engine
    AUTH_THRESHOLD: float = -0.1
    ACCOUNT_THRESHOLD: float = -0.1
    PROCESS_THRESHOLD: float = -0.15
    ENGINE_SLEEP_SECONDS: int = 300
    ENGINE_MOCK_MODE: bool = False

    # Database pool
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    LOG_COLLECTOR_DB_POOL_SIZE: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()