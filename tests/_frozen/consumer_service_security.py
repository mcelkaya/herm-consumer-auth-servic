from typing import Optional
from jwt.exceptions import PyJWTError
from app.core.config import settings
from tests._frozen.consumer_service_jwt_keys import HmacKeyRing  # frozen: was app.core.jwt_keys


def _key_ring() -> HmacKeyRing:
    # Built per call (cheap) so settings changes, e.g. in tests, take effect.
    return HmacKeyRing(
        settings.SECRET_KEY,
        settings.JWT_SECONDARY_SECRET_KEY,
        algorithm=settings.ALGORITHM,
        require_kid=settings.JWT_REQUIRE_KID,
    )


def check_jwt_keys() -> None:
    """Startup guard: ERROR log for keys < 32 bytes; raise if enforcement is on."""
    _key_ring().check_key_strength(enforce=settings.JWT_ENFORCE_MIN_KEY_LENGTH)


class SecurityService:
    """Security service for JWT token validation"""
    
    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        """Decode and verify JWT token from email-integration-service"""
        try:
            return _key_ring().decode(token)
        except PyJWTError:
            return None
    
    @staticmethod
    def get_user_id_from_token(token: str) -> Optional[str]:
        """Extract user_id from JWT token"""
        payload = SecurityService.decode_token(token)
        if not payload:
            return None
        return payload.get("sub")


security_service = SecurityService()
