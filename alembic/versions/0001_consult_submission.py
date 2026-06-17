"""Initial: consult_submission table

Revision ID: 0001
Revises:
Create Date: 2026-06-14
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "consult_submission",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("fname", sa.String(120), nullable=False),
        sa.Column("lname", sa.String(120), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("phone", sa.String(40), nullable=False, server_default=""),
        sa.Column("company", sa.String(200), nullable=False, server_default=""),
        sa.Column("tier", sa.String(40), nullable=False),
        sa.Column("msg", sa.String(4000), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def downgrade() -> None:
    op.drop_table("consult_submission")
