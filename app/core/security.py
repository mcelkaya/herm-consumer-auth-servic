import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid4
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from app.core.config import settings
from app.core.access_token_keys import AccessTokenKeySet

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# (raw setting value, parsed keyset or None). Parsing PEMs is not free, so it
# happens once per distinct setting value (once per process in production).
_keyset_cache: Tuple[Optional[str], Optional[AccessTokenKeySet]] = (None, None)


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
    Startup guard: access tokens are RS256-only (no verifier accepts HS256), so
    the service refuses to start unless ACCESS_TOKEN_ALGORITHM is RS256 and
    ACCESS_TOKEN_SIGNING_KEYS holds a valid keyset. Logs kids/sizes only.
    """
    from app.models.oauth_client import OAuthClient
    from app.services.oidc_token_service import ACCESS_TOKEN_AUD as OIDC_ACCESS_TOKEN_AUD

    audience = settings.ACCESS_TOKEN_AUDIENCE
    if audience == OIDC_ACCESS_TOKEN_AUD or audience.startswith(OAuthClient.CLIENT_ID_PREFIX):
        # Would make internal access tokens indistinguishable from partner OIDC tokens.
        raise ValueError(f"ACCESS_TOKEN_AUDIENCE {audience!r} collides with an OIDC audience")

    if settings.ACCESS_TOKEN_ALGORITHM != "RS256":
        raise ValueError(
            f"ACCESS_TOKEN_ALGORITHM must be RS256, got {settings.ACCESS_TOKEN_ALGORITHM!r}"
        )
    try:
        keyset = _load_access_token_keyset()
    except ValueError as exc:
        raise ValueError(
            f"{exc}. Access tokens are RS256-only; for local dev generate a keyset with "
            "`python scripts/generate_access_token_keypair.py` and set it as "
            "ACCESS_TOKEN_SIGNING_KEYS (see .env.example)"
        ) from None
    logger.info(
        "jwt.access_token_keys_loaded mode=RS256 active=%s bits=%s",
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
        to_encode.update({"iss": settings.OIDC_ISSUER, "aud": settings.ACCESS_TOKEN_AUDIENCE})
        # A missing keyset raises here (startup already refused to boot in that case).
        return _load_access_token_keyset().encode(to_encode)

    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        """
        Verify an access token: RS256 only, via the access-token keyset (kid
        lookup, aud/iss/exp required). Any other alg, an unknown kid or a
        missing keyset -> None. There is no HS256 fallback: the old shared
        secret is retired and must never mint a token auth accepts.
        """
        keyset = get_access_token_keyset()
        if keyset is None:
            return None
        try:
            if jwt.get_unverified_header(token).get("alg") != "RS256":
                return None
            return keyset.decode(
                token,
                audience=settings.ACCESS_TOKEN_AUDIENCE,
                issuer=settings.OIDC_ISSUER,
            )
        except PyJWTError:
            return None


security_service = SecurityService()
