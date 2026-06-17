"""Auth dependencies. `get_current_user` decodes the Bearer JWT, loads the user,
and pins their id into the request-scoped ContextVar so the audit layer can
attribute mutations automatically."""
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.context import set_actor
from app.core.security import TokenError, decode_access_token
from app.db.session import get_db
from app.models.enums import UserRole
from app.models.user import User


def _bearer_token(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    return token


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    token = _bearer_token(request)
    try:
        claims = decode_access_token(token, settings)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}")

    try:
        user_id = UUID(claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token subject")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer valid")

    set_actor(db, user.id)
    return user


def require_roles(*allowed: UserRole):
    """Build a dependency that enforces one of the given roles."""
    def _dep(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires one of: {', '.join(r.value for r in allowed)}",
            )
        return user
    return _dep


require_admin = require_roles(UserRole.admin)
require_admin_or_dispatcher = require_roles(UserRole.admin, UserRole.dispatcher)
require_staff = require_roles(UserRole.admin, UserRole.dispatcher, UserRole.technician)


def require_portal_user(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Portal-user-only guard. The user MUST be linked to a customer
    account; queries downstream scope everything by user.customer_account_id."""
    if user.role != UserRole.portal_user:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Portal access only")
    if user.customer_account_id is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Portal user must be linked to a customer account",
        )
    return user
