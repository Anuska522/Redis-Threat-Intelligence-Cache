from fastapi import Header, HTTPException, status
from typing import Optional
from app.config import settings


async def verify_admin_key(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None)
) -> str:
    # Accept either X-Admin-Key header or Authorization: Bearer <key>
    provided_key = None
    if x_admin_key:
        provided_key = x_admin_key.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        provided_key = authorization[7:].strip()

    if not provided_key or provided_key != settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Valid administrative API key required in 'X-Admin-Key' or 'Authorization: Bearer' header."
        )
    return provided_key
