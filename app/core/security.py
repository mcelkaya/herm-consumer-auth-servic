from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from app.core.config import settings
from app.core.jwt_keys import HmacKeyRing

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    """Security service for password hashing and JWT tokens"""
    
    @staticmethod
    def _truncate_password(password: str) -> bytes:
        """
        Truncate password to 72 bytes for bcrypt compatibility.
        Bcrypt has a maximum input length of 72 bytes.
        """
        password_bytes = password.encode('utf-8')
        # Truncate to 72 bytes if necessary
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        return password_bytes

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password"""
        truncated = SecurityService._truncate_password(plain_password).decode('utf-8', errors='ignore')
        return pwd_context.verify(truncated, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash a password"""
        truncated = SecurityService._truncate_password(password).decode('utf-8', errors='ignore')
        return pwd_context.hash(truncated)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        jti = to_encode.get("jti") or str(uuid4())
        to_encode.update({"exp": expire, "type": "access", "jti": jti})
        return _key_ring().encode(to_encode)
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        return _key_ring().encode(to_encode)
    
    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        """Decode and verify JWT token"""
        try:
            return _key_ring().decode(token)
        except PyJWTError:
            return None


security_service = SecurityService()
