"""Phase 3: materials, stock, append-only confirmations + parts

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_IMMUTABLE_TABLES = ["confirmation", "confirmation_part"]


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        "material",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("part_number", sa.String(120), nullable=False, unique=True),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("unit_cost", sa.Float, nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="JMD"),
        sa.Column("uom", sa.String(20), nullable=False, server_default="ea"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "stock_location",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False, server_default="shop"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "stock_quant",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("material_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("material.id"), nullable=False),
        sa.Column("stock_location_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("stock_location.id"), nullable=False),
        sa.Column("qty", sa.Float, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_stock_quant_material", "stock_quant", ["material_id"])
    op.create_index("ix_stock_quant_location", "stock_quant", ["stock_location_id"])
    op.create_index("uq_stock_material_location", "stock_quant",
                    ["material_id", "stock_location_id"], unique=True)

    op.create_table(
        "confirmation",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("operation_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("operation.id"), nullable=False),
        sa.Column("technician_user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("actual_hours", sa.Float, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_final", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("notes", sa.String(2000), nullable=False, server_default=""),
        sa.Column("reversal_of_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("confirmation.id"), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_confirmation_operation", "confirmation", ["operation_id"])
    op.create_index("ix_confirmation_reversal", "confirmation", ["reversal_of_id"])

    op.create_table(
        "confirmation_part",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("confirmation_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("confirmation.id"), nullable=False),
        sa.Column("material_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("material.id"), nullable=False),
        sa.Column("stock_location_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("stock_location.id"), nullable=False),
        sa.Column("qty_used", sa.Float, nullable=False),
        sa.Column("unit_cost_at_use", sa.Float, nullable=False, server_default="0"),
    )
    op.create_index("ix_confirmation_part_cnf", "confirmation_part", ["confirmation_id"])
    op.create_index("ix_confirmation_part_material", "confirmation_part", ["material_id"])

    # Append-only triggers on Postgres only — SQLite cannot replicate them, so
    # the tests prove append-only behavior through service-layer logic.
    if _is_pg():
        for table in _IMMUTABLE_TABLES:
            op.execute(
                f"""
                CREATE TRIGGER {table}_no_mutation
                BEFORE UPDATE OR DELETE ON {table}
                FOR EACH ROW EXECUTE FUNCTION reject_mutation();
                """
            )


def downgrade() -> None:
    if _is_pg():
        for table in _IMMUTABLE_TABLES:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_mutation ON {table};")

    op.drop_table("confirmation_part")
    op.drop_table("confirmation")
    op.drop_table("stock_quant")
    op.drop_table("stock_location")
    op.drop_table("material")
