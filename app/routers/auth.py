from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.enums import AuditAction, UserRole
from app.models.user import User
from app.schemas.auth import (
    AuthStatus,
    BootstrapRequest,
    CurrentUser,
    LoginRequest,
    TokenResponse,
)
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/status", response_model=AuthStatus)
def status(db: Annotated[Session, Depends(get_db)]) -> AuthStatus:
    return AuthStatus(users_exist=db.scalar(select(func.count()).select_from(User)) > 0)


@router.post("/bootstrap", response_model=TokenResponse, status_code=201)
def bootstrap_first_admin(
    payload: BootstrapRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    if db.scalar(select(func.count()).select_from(User)) > 0:
        raise HTTPException(status_code=403, detail="Bootstrap unavailable: users already exist")
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=UserRole.admin,
        is_active=True,
    )
    db.add(user)
    db.flush()
    record_audit(
        db, entity_type="user_account", entity_id=user.id,
        action=AuditAction.create, after={"email": user.email, "role": user.role.value},
        actor_user_id=user.id,
    )
    db.commit()
    token = create_access_token(subject=str(user.id), role=user.role.value, settings=settings)
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        # Same message either way so we don't leak whether the email exists.
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        settings=settings,
        customer_account_id=str(user.customer_account_id) if user.customer_account_id else None,
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=CurrentUser)
def me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user


@router.post("/logout", status_code=204)
def logout() -> None:
    # Stateless JWT — the client just drops the token. Endpoint exists so the
    # UI has a hook for any future blacklist behavior.
    return None


# `serialize` re-export retained so `from app.services.audit import serialize`
# remains the single source.
__all__ = ["router", "serialize"]
