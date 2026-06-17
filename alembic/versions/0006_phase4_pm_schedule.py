"""Phase 4: pm_schedule

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


pm_trigger_kind = sa.Enum(
    "calendar", "meter", name="pm_trigger_kind", create_type=False,
)


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_pg():
        pm_trigger_kind.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "pm_schedule",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column("site_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("site.id"), nullable=False),
        sa.Column("functional_location_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("functional_location.id"), nullable=True),
        sa.Column("equipment_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment.id"), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(2000), nullable=False, server_default=""),
        sa.Column("trigger_kind", pm_trigger_kind, nullable=False),
        sa.Column("interval_days", sa.Integer, nullable=True),
        sa.Column("meter_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("meter.id"), nullable=True),
        sa.Column("interval_value", sa.Float, nullable=True),
        sa.Column("last_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_completed_value", sa.Float, nullable=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_due_value", sa.Float, nullable=True),
        sa.Column("order_title", sa.String(200), nullable=False),
        sa.Column(
            "billing_class",
            sa.Enum("contract", "billable", "warranty", "goodwill",
                    name="billing_class", create_type=False),
            nullable=False, server_default="contract",
        ),
        sa.Column(
            "priority",
            sa.Enum("emergency", "high", "medium", "low",
                    name="severity", create_type=False),
            nullable=False, server_default="medium",
        ),
        sa.Column("service_contract_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_pm_customer", "pm_schedule", ["customer_account_id"])
    op.create_index("ix_pm_site", "pm_schedule", ["site_id"])
    op.create_index("ix_pm_fl", "pm_schedule", ["functional_location_id"])
    op.create_index("ix_pm_equipment", "pm_schedule", ["equipment_id"])
    op.create_index("ix_pm_meter", "pm_schedule", ["meter_id"])
    op.create_index("ix_pm_contract", "pm_schedule", ["service_contract_id"])
    op.create_index("ix_pm_active", "pm_schedule", ["is_active"])

    # Index for the engine's open-cycle lookup.
    op.create_index("ix_wo_pm_schedule", "work_order", ["pm_schedule_id"])


def downgrade() -> None:
    op.drop_index("ix_wo_pm_schedule", table_name="work_order")
    op.drop_table("pm_schedule")
    if _is_pg():
        pm_trigger_kind.drop(op.get_bind(), checkfirst=True)
