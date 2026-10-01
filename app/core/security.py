import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid4
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from app.core.config import settings
from app.core.access_token_keys import AccessTokenKeySet
from app.core.jwt_keys import HmacKeyRing

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# (raw setting value, parsed keyset or None). Parsing PEMs is not free, so it
# happens once per distinct setting value (once per process in production).
_keyset_cache: Tuple[Optional[str], Optional[AccessTokenKeySet]] = (None, None)


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


def _load_access_token_keyset() -> AccessTokenKeySet:
    """Parse ACCESS_TOKEN_SIGNING_KEYS (cached). Raises ValueError if missing/invalid."""
    global _keyset_cache
    raw = settings.ACCESS_TOKEN_SIGNING_KEYS
    if not raw or not raw.strip():
        raise ValueError("ACCESS_TOKEN_SIGNING_KEYS is not configured")
    if _keyset_cache[0] != raw or _keyset_cache[1] is None:
        _keyset_cache = (raw, AccessTokenKeySet.from_json(raw))
    return _keyset_cache[1]


def get_access_token_keyset() -> Optional[AccessTokenKeySet]:
    """The configured RS256 keyset, or None when absent or invalid."""
    try:
        return _load_access_token_keyset()
    except ValueError:
        return None


def check_access_token_keys() -> None:
    """
    Startup guard for the RS256 access-token keyset.

    RS256 mode: a missing/invalid keyset raises (service refuses to start).
    HS256 mode: no keyset is normal and silent; an invalid one is logged as
    ERROR (kids/sizes only) but does not block startup.
    """
    from app.models.oauth_client import OAuthClient
    from app.services.oidc_token_service import ACCESS_TOKEN_AUD as OIDC_ACCESS_TOKEN_AUD

    audience = settings.ACCESS_TOKEN_AUDIENCE
    if audience == OIDC_ACCESS_TOKEN_AUD or audience.startswith(OAuthClient.CLIENT_ID_PREFIX):
        # Would make internal access tokens indistinguishable from partner OIDC tokens.
        raise ValueError(f"ACCESS_TOKEN_AUDIENCE {audience!r} collides with an OIDC audience")

    rs256 = settings.ACCESS_TOKEN_ALGORITHM == "RS256"
    raw = settings.ACCESS_TOKEN_SIGNING_KEYS
    if not rs256 and (not raw or not raw.strip()):
        return
    try:
        keyset = _load_access_token_keyset()
    except ValueError as exc:
        if rs256:
            raise
        logger.error("jwt.access_token_keys_invalid mode=HS256 reason=%s", exc)
        return
    logger.info(
        "jwt.access_token_keys_loaded mode=%s active=%s bits=%s",
        settings.ACCESS_TOKEN_ALGORITHM,
        keyset.active_kid,
        keyset.key_bits,
    )


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
        if settings.ACCESS_TOKEN_ALGORITHM == "RS256":
            # No silent fallback to HS256: a missing keyset raises here (and
            # startup already refused to boot in that case).
            to_encode.update({"iss": settings.OIDC_ISSUER, "aud": settings.ACCESS_TOKEN_AUDIENCE})
            return _load_access_token_keyset().encode(to_encode)
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
        """Decode and verify JWT token (HS256 via the key ring; RS256 via the access-token keyset)."""
        try:
            if jwt.get_unverified_header(token).get("alg") == "RS256":
                # Accepted whenever a keyset is configured (also in HS256 mode),
                # so rolling back RS256 -> HS256 does not log anyone out.
                keyset = get_access_token_keyset()
                if keyset is None:
                    return None
                return keyset.decode(
                    token,
                    audience=settings.ACCESS_TOKEN_AUDIENCE,
                    issuer=settings.OIDC_ISSUER,
                )
            return _key_ring().decode(token)
        except PyJWTError:
            return None


security_service = SecurityService()
