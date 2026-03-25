from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.user_service import UserService
from app.services.token_blocklist_service import TokenBlocklistService
from app.models.user import User

security = HTTPBearer()


async def get_blocklist(request: Request) -> TokenBlocklistService:
    """Dependency: Redis-backed token blocklist — app.state.redis bağlantısını kullanır."""
    return TokenBlocklistService(redis=request.app.state.redis)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
    blocklist: TokenBlocklistService = Depends(get_blocklist),
) -> User:
    """Dependency to get current authenticated user (blocklist kontrolü dahil)."""
    token = credentials.credentials
    return await get_current_user_with_blocklist(token=token, db=db, blocklist=blocklist)


async def get_current_user_with_blocklist(
    token: str,
    db: AsyncSession,
    blocklist: "TokenBlocklistService",
) -> User:
    """
    Validate a raw JWT string, check blocklist, then return the User.
    Used directly in tests and called internally by get_current_user.
    """
    from app.core.security import security_service
    from app.services.user_service import UserService
    from uuid import UUID

    payload = security_service.decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    jti = payload.get("jti")
    if jti and await blocklist.is_blocked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user_service = UserService(db)
    user = await user_service.get_user_by_id(UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    return user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Dependency to get current user and verify admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

