import os

from pydantic import Field
from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Herm Auth Service"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8001
    HOST: str = "0.0.0.0"

    # Database
    DATABASE_URL: str
    DATABASE_SCHEMA: str = "public"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    REFRESH_TOKEN_ROTATION_ENABLED: bool = True

    # Password Reset
    FRONTEND_URL: str = "http://localhost:3000"
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 24
    
    # CORS - comma-separated list of allowed origins (stored as string)
    # IMPORTANT: Cannot use "*" when credentials are enabled
    # Example: "https://beta-app.herm.io,https://app.herm.io"
    CORS_ORIGINS_STR: str = Field(
        default="http://localhost:3000",
        alias="CORS_ORIGINS",
        description="Comma-separated list of allowed CORS origins"
    )
    
    @property
    def CORS_ORIGINS(self) -> List[str]:
        """Parse CORS_ORIGINS from comma-separated string to list"""
        return [origin.strip() for origin in self.CORS_ORIGINS_STR.split(",") if origin.strip()]
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # AWS
    AWS_REGION: str = "us-east-1"
    AWS_ENDPOINT_URL: Optional[str] = Field(default=None, description="AWS endpoint URL (for localstack)")
    
    # Logging
    LOG_LEVEL: str = "INFO"

    NOTIFICATION_QUEUE_URL: str = "INFO"

    class Config:
        env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
        case_sensitive = True
        populate_by_name = True  # Allow using alias for env var


settings = Settings()