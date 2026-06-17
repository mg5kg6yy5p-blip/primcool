"""Phase 2: notification, work_order, operation, saved_view

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


notification_category = sa.Enum(
    "cooling", "heating", "leak", "electrical", "noise", "maintenance_request", "other",
    name="notification_category", create_type=False,
)
severity = sa.Enum("emergency", "high", "medium", "low", name="severity", create_type=False)
notification_status = sa.Enum(
    "new", "acknowledged", "converted", "closed_no_action",
    name="notification_status", create_type=False,
)
order_type = sa.Enum(
    "corrective", "preventive", "install", "inspection", name="order_type", create_type=False
)
billing_class = sa.Enum(
    "contract", "billable", "warranty", "goodwill", name="billing_class", create_type=False
)
order_status = sa.Enum(
    "created", "scheduled", "in_progress", "tech_complete", "closed", "cancelled",
    name="order_status", create_type=False,
)
operation_status = sa.Enum("open", "confirmed", name="operation_status", create_type=False)

# All enums introduced by Phase 2 (severity is shared by notification.severity
# and work_order.priority).
_NEW_ENUMS = [
    severity, notification_category, notification_status, order_type,
    billing_class, order_status, operation_status,
]


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    bind = op.get_bind()
    if _is_pg():
        for enum in _NEW_ENUMS:
            enum.create(bind, checkfirst=True)

    json_type = sa.dialects.postgresql.JSONB if _is_pg() else sa.JSON

    op.create_table(
        "notification",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column("site_id", sa.Uuid(as_uuid=True), sa.ForeignKey("site.id"), nullable=False),
        sa.Column("space_id", sa.Uuid(as_uuid=True), sa.ForeignKey("space.id"), nullable=True),
        sa.Column("category", notification_category, nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("photo_url", sa.String(1000), nullable=True),
        sa.Column("status", notification_status, nullable=False, server_default="new"),
        sa.Column("created_by", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_notif_customer", "notification", ["customer_account_id"])
    op.create_index("ix_notif_site", "notification", ["site_id"])
    op.create_index("ix_notif_space", "notification", ["space_id"])
    op.create_index("ix_notif_status", "notification", ["status"])

    op.create_table(
        "work_order",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("notification_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("notification.id"), nullable=True),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column("site_id", sa.Uuid(as_uuid=True), sa.ForeignKey("site.id"), nullable=False),
        sa.Column("functional_location_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("functional_location.id"), nullable=True),
        sa.Column("equipment_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment.id"), nullable=True),
        sa.Column("pm_schedule_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("order_type", order_type, nullable=False),
        sa.Column("billing_class", billing_class, nullable=False, server_default="billable"),
        sa.Column("priority", severity, nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("status", order_status, nullable=False, server_default="created"),
        sa.Column("assigned_to_user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("scheduled_date", sa.Date, nullable=True),
        sa.Column("due_date", sa.Date, nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_wo_notification", "work_order", ["notification_id"])
    op.create_index("ix_wo_customer", "work_order", ["customer_account_id"])
    op.create_index("ix_wo_site", "work_order", ["site_id"])
    op.create_index("ix_wo_fl", "work_order", ["functional_location_id"])
    op.create_index("ix_wo_equipment", "work_order", ["equipment_id"])
    op.create_index("ix_wo_priority", "work_order", ["priority"])
    op.create_index("ix_wo_status", "work_order", ["status"])

    op.create_table(
        "operation",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("work_order_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("work_order.id"), nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False, server_default="10"),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("status", operation_status, nullable=False, server_default="open"),
        sa.Column("planned_hours", sa.Float, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_operation_wo", "operation", ["work_order_id"])

    op.create_table(
        "saved_view",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("entity", sa.String(40), nullable=False, server_default="work_order_list"),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("filters", json_type, nullable=False),
        sa.Column("columns", json_type, nullable=False),
        sa.Column("sort", json_type, nullable=False),
        sa.Column("is_default", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_saved_view_user", "saved_view", ["user_id"])

    # Notification is append-only except status timestamps; per spec the PG
    # immutability trigger is NOT applied here (status transitions mutate it).


def downgrade() -> None:
    op.drop_table("saved_view")
    op.drop_table("operation")
    op.drop_table("work_order")
    op.drop_table("notification")

    if _is_pg():
        for enum in _NEW_ENUMS:
            enum.drop(op.get_bind(), checkfirst=True)
