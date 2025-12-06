from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    BREVO_API_KEY: str
    BREVO_EMAIL: str
    BREVO_SENDER_NAME: str
    JWT_KEY: str
    JWT_ALGORITHM: str
  
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore", 
    )

Config = Settings()