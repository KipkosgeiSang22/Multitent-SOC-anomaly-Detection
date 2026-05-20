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
    MODEL_BASE_PATH: str = "C:/soc_platform/models"
    SMTP_HOST: str = ""
    ADMIN_USERNAME : str
    ADMIN_PASSWORD: str
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()