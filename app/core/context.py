"""Helpers for surfacing the request actor to the audit layer.

`set_actor` writes the user id onto the session so `record_audit` can pick it
up without threading the user through every endpoint signature.
"""
from uuid import UUID

from sqlalchemy.orm import Session


def set_actor(db: Session, user_id: UUID | None) -> None:
    db.info["actor_user_id"] = user_id


def get_actor(db: Session) -> UUID | None:
    return db.info.get("actor_user_id")
