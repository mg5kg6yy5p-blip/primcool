"""Phase 5: contracts, BOM, billing rates, invoice drafts, customer.gct_rate

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-17
"""
from typing import Sequence, Union
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


contract_status = sa.Enum(
    "active", "expired", "cancelled", name="contract_status", create_type=False,
)
invoice_status = sa.Enum(
    "draft", "issued", "void", name="invoice_status", create_type=False,
)
line_kind = sa.Enum(
    "labor", "part", "tax", "adjustment", name="line_kind", create_type=False,
)


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_pg():
        contract_status.create(op.get_bind(), checkfirst=True)
        invoice_status.create(op.get_bind(), checkfirst=True)
        line_kind.create(op.get_bind(), checkfirst=True)

    json_type = sa.dialects.postgresql.JSONB if _is_pg() else sa.JSON

    # gct_rate on customer_account
    with op.batch_alter_table("customer_account") as batch:
        batch.add_column(sa.Column(
            "gct_rate", sa.Float, nullable=False, server_default="0",
        ))

    op.create_table(
        "service_contract",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("starts_on", sa.Date, nullable=False),
        sa.Column("ends_on", sa.Date, nullable=False),
        sa.Column("included_pm_visits_per_year", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("response_sla", json_type, nullable=False),
        sa.Column("terms_notes", sa.String(4000), nullable=False, server_default=""),
        sa.Column("status", contract_status, nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_contract_customer", "service_contract", ["customer_account_id"])

    op.create_table(
        "contract_site",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("service_contract_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("service_contract.id"), nullable=False),
        sa.Column("site_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("site.id"), nullable=False),
    )
    op.create_index("ix_cs_contract", "contract_site", ["service_contract_id"])
    op.create_index("ix_cs_site", "contract_site", ["site_id"])

    op.create_table(
        "billing_rate",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "role",
            sa.Enum("admin", "dispatcher", "technician", "portal_user",
                    name="user_role", create_type=False),
            nullable=False, unique=True,
        ),
        sa.Column("hourly_amount", sa.Float, nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="JMD"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "equipment_bom",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("equipment_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment.id"), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "bom_item",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("equipment_bom_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment_bom.id"), nullable=False),
        sa.Column("material_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("material.id"), nullable=False),
        sa.Column("quantity", sa.Float, nullable=False, server_default="1"),
    )
    op.create_index("ix_bom_item_bom", "bom_item", ["equipment_bom_id"])
    op.create_index("ix_bom_item_material", "bom_item", ["material_id"])

    op.create_table(
        "invoice_draft",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("work_order_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("work_order.id"), nullable=False),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column(
            "billing_class",
            sa.Enum("contract", "billable", "warranty", "goodwill",
                    name="billing_class", create_type=False),
            nullable=False,
        ),
        sa.Column("currency", sa.String(3), nullable=False, server_default="JMD"),
        sa.Column("subtotal", sa.Float, nullable=False, server_default="0"),
        sa.Column("gct_rate", sa.Float, nullable=False, server_default="0"),
        sa.Column("gct_amount", sa.Float, nullable=False, server_default="0"),
        sa.Column("total", sa.Float, nullable=False, server_default="0"),
        sa.Column("status", invoice_status, nullable=False, server_default="draft"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_invoice_wo", "invoice_draft", ["work_order_id"])
    op.create_index("ix_invoice_customer", "invoice_draft", ["customer_account_id"])

    op.create_table(
        "invoice_draft_line",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("invoice_draft_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("invoice_draft.id"), nullable=False),
        sa.Column("kind", line_kind, nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("qty", sa.Float, nullable=False, server_default="1"),
        sa.Column("unit_amount", sa.Float, nullable=False, server_default="0"),
        sa.Column("total", sa.Float, nullable=False, server_default="0"),
        sa.Column("source_confirmation_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("source_part_id", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.create_index("ix_line_draft", "invoice_draft_line", ["invoice_draft_id"])

    # Seed default JMD billing rates so the billable cascade produces non-zero
    # lines out of the box. Admin can edit these later. Use SQLAlchemy's
    # generic Uuid type so the migration is portable across SQLite and
    # Postgres (str() UUIDs would otherwise fail SQLite's binder).
    op.bulk_insert(
        sa.table(
            "billing_rate",
            sa.Column("id", sa.Uuid(as_uuid=True)),
            sa.Column("role", sa.String()),
            sa.Column("hourly_amount", sa.Float()),
            sa.Column("currency", sa.String()),
            sa.Column("is_active", sa.Boolean()),
        ),
        [
            {"id": uuid4(), "role": "technician", "hourly_amount": 3000.0,
             "currency": "JMD", "is_active": True},
            {"id": uuid4(), "role": "dispatcher", "hourly_amount": 4000.0,
             "currency": "JMD", "is_active": True},
            {"id": uuid4(), "role": "admin", "hourly_amount": 5000.0,
             "currency": "JMD", "is_active": True},
        ],
    )


def downgrade() -> None:
    op.drop_table("invoice_draft_line")
    op.drop_table("invoice_draft")
    op.drop_table("bom_item")
    op.drop_table("equipment_bom")
    op.drop_table("billing_rate")
    op.drop_table("contract_site")
    op.drop_table("service_contract")
    with op.batch_alter_table("customer_account") as batch:
        batch.drop_column("gct_rate")
    if _is_pg():
        line_kind.drop(op.get_bind(), checkfirst=True)
        invoice_status.drop(op.get_bind(), checkfirst=True)
        contract_status.drop(op.get_bind(), checkfirst=True)
