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

    # Slack alert notifications (Incoming Webhook). Blank = no-op (dev safe).
    # Receives ops/system alerts (critical + warning) via send_alert. Injected
    # as an SSM secret (prod_slack_auth_alerts_webhook) in production.
    ALERT_SLACK_WEBHOOK: str = ""

    NOTIFICATION_QUEUE_URL: str = "INFO"

    # Consumer-service internal API (referral signup linkage)
    CONSUMER_INTERNAL_BASE_URL: Optional[str] = Field(
        default=None,
        description="Base URL including /herm-consumer/v1/internal (e.g. http://consumer-service:8000/herm-consumer/v1/internal)"
    )
    CONSUMER_INTERNAL_API_KEY: Optional[str] = Field(
        default=None,
        description="Shared internal API key for consumer-service internal endpoints"
    )
    CONSUMER_INTERNAL_TIMEOUT_SECONDS: int = 5

    # Inbound internal API key for endpoints under /herm-auth/v1/internal/*.
    # Distinct from CONSUMER_INTERNAL_API_KEY which is the outbound key
    # auth-service uses to call consumer-service.
    INTERNAL_API_KEY: Optional[str] = Field(
        default=None,
        description="Shared secret required on X-Internal-API-Key for /internal/* endpoints",
    )

    # =========================================================================
    # Social login (Google / Apple / Facebook)
    #
    # These are the values copied back from each provider's developer console.
    # Replace every TODO_* placeholder with the real value (see the platform
    # setup guide). The *_STR fields are comma-separated and exposed as lists.
    # =========================================================================

    # Google: ALL OAuth client IDs whose ID tokens you accept — typically your
    # iOS client id, Android client id, and Web/"server" client id. The ID
    # token's `aud` must equal one of these. With @react-native-google-signin
    # the aud is usually your WEB (server) client id, configured as webClientId
    # on the native side, so that one is mandatory here.
    GOOGLE_CLIENT_IDS_STR: str = Field(
        default="TODO_GOOGLE_WEB_CLIENT_ID.apps.googleusercontent.com",
        alias="GOOGLE_CLIENT_IDS",
        description="Comma-separated Google OAuth client IDs accepted as ID-token audiences",
    )

    # Apple: the client IDs whose identity tokens you accept. For the native
    # app this is your iOS bundle id (e.g. io.herm.app). Add your web Services
    # ID too if you also do Sign in with Apple on the web.
    APPLE_CLIENT_IDS_STR: str = Field(
        default="TODO_APPLE_BUNDLE_ID",
        alias="APPLE_CLIENT_IDS",
        description="Comma-separated Apple client IDs (bundle id and/or services id)",
    )

    # Facebook
    FACEBOOK_APP_ID: str = Field(
        default="TODO_FACEBOOK_APP_ID",
        description="Facebook (Meta) app id; also the expected OIDC token audience",
    )
    FACEBOOK_APP_SECRET: Optional[str] = Field(
        default=None,
        description="Facebook app secret; required to validate classic (Android) access tokens via debug_token",
    )
    # Facebook does not expose an `email_verified` claim. Facebook requires a
    # confirmed email to use the platform, so we treat its emails as verified by
    # default. Set to false for maximum strictness — that forces existing-account
    # links via the settings page instead of auto-linking by matched email.
    FACEBOOK_EMAIL_VERIFIED_DEFAULT: bool = True

    @property
    def GOOGLE_CLIENT_IDS(self) -> List[str]:
        return [c.strip() for c in self.GOOGLE_CLIENT_IDS_STR.split(",") if c.strip()]

    @property
    def APPLE_CLIENT_IDS(self) -> List[str]:
        return [c.strip() for c in self.APPLE_CLIENT_IDS_STR.split(",") if c.strip()]

    class Config:
        env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
        case_sensitive = True
        populate_by_name = True  # Allow using alias for env var


settings = Settings()