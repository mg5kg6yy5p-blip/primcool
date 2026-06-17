"""Auth: user_account table

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


user_role = sa.Enum(
    "admin", "dispatcher", "technician", "portal_user",
    name="user_role", create_type=False,
)


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_pg():
        user_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "user_account",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("role", user_role, nullable=False),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_user_email", "user_account", ["email"], unique=True)
    op.create_index("ix_user_customer", "user_account", ["customer_account_id"])


def downgrade() -> None:
    op.drop_index("ix_user_customer", table_name="user_account")
    op.drop_index("ix_user_email", table_name="user_account")
    op.drop_table("user_account")
    if _is_pg():
        user_role.drop(op.get_bind(), checkfirst=True)
