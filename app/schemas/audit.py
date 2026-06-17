from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import AuditAction


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    actor_user_id: UUID | None
    entity_type: str
    entity_id: UUID
    action: AuditAction
    before: dict | None
    after: dict | None
    at: datetime
