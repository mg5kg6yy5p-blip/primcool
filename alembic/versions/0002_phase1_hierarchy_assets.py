"""Phase 1: hierarchy, assets, audit + immutability triggers

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Enum definitions (create_type=False; we create them explicitly on PG so the
# shared asset_class type isn't created twice).
customer_type = sa.Enum(
    "apartment_complex", "strip_mall", "commercial", "residential",
    name="customer_type", create_type=False,
)
customer_status = sa.Enum("active", "inactive", name="customer_status", create_type=False)
space_type = sa.Enum(
    "residential_unit", "retail", "office", "common_area", "mechanical_room", "exterior",
    name="space_type", create_type=False,
)
asset_class = sa.Enum(
    "split_ac", "central_ahu", "package_unit", "chiller", "cooling_tower", "exhaust", "other",
    name="asset_class", create_type=False,
)
fl_status = sa.Enum("active", "inactive", name="fl_status", create_type=False)
equipment_status = sa.Enum(
    "installed", "in_storage", "in_repair", "scrapped",
    name="equipment_status", create_type=False,
)
meter_type = sa.Enum("run_hours", "starts", "other", name="meter_type", create_type=False)
reading_source = sa.Enum("manual", "import", name="reading_source", create_type=False)
audit_action = sa.Enum(
    "create", "update", "status_change", "install", "remove", "delete",
    name="audit_action", create_type=False,
)

_ALL_ENUMS = [
    customer_type, customer_status, space_type, asset_class, fl_status,
    equipment_status, meter_type, reading_source, audit_action,
]

_IMMUTABLE_TABLES = ["audit_log", "meter_reading"]


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    bind = op.get_bind()
    if _is_pg():
        for enum in _ALL_ENUMS:
            enum.create(bind, checkfirst=True)

    json_type = sa.dialects.postgresql.JSONB if _is_pg() else sa.JSON

    op.create_table(
        "customer_account",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("type", customer_type, nullable=False),
        sa.Column("billing_currency", sa.String(3), nullable=False, server_default="JMD"),
        sa.Column("contact_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("contact_email", sa.String(254), nullable=False, server_default=""),
        sa.Column("contact_phone", sa.String(40), nullable=False, server_default=""),
        sa.Column("status", customer_status, nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "site",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("customer_account_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("customer_account.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("address", sa.String(500), nullable=False, server_default=""),
        sa.Column("geo_lat", sa.Float, nullable=True),
        sa.Column("geo_lng", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_site_customer_account_id", "site", ["customer_account_id"])

    op.create_table(
        "building",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("site_id", sa.Uuid(as_uuid=True), sa.ForeignKey("site.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_building_site_id", "building", ["site_id"])

    op.create_table(
        "space",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("site_id", sa.Uuid(as_uuid=True), sa.ForeignKey("site.id"), nullable=False),
        sa.Column("building_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("building.id"), nullable=True),
        sa.Column("identifier", sa.String(120), nullable=False),
        sa.Column("space_type", space_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_space_site_id", "space", ["site_id"])
    op.create_index("ix_space_building_id", "space", ["building_id"])

    op.create_table(
        "functional_location",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("site_id", sa.Uuid(as_uuid=True), sa.ForeignKey("site.id"), nullable=False),
        sa.Column("building_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("building.id"), nullable=True),
        sa.Column("space_id", sa.Uuid(as_uuid=True), sa.ForeignKey("space.id"), nullable=True),
        sa.Column("parent_fl_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("functional_location.id"), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("fl_class", asset_class, nullable=False),
        sa.Column("status", fl_status, nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_fl_site_id", "functional_location", ["site_id"])
    op.create_index("ix_fl_building_id", "functional_location", ["building_id"])
    op.create_index("ix_fl_space_id", "functional_location", ["space_id"])
    op.create_index("ix_fl_parent_fl_id", "functional_location", ["parent_fl_id"])

    op.create_table(
        "equipment",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("serial", sa.String(120), nullable=True, unique=True),
        sa.Column("model", sa.String(200), nullable=False, server_default=""),
        sa.Column("manufacturer", sa.String(200), nullable=False, server_default=""),
        sa.Column("equipment_class", asset_class, nullable=False),
        sa.Column("status", equipment_status, nullable=False, server_default="in_storage"),
        sa.Column("warranty_months", sa.Integer, nullable=True),
        sa.Column("notes", sa.String(2000), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "equipment_install",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("equipment_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment.id"), nullable=False),
        sa.Column("functional_location_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("functional_location.id"), nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("installed_by_user_id", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.create_index("ix_install_equipment_id", "equipment_install", ["equipment_id"])
    op.create_index("ix_install_fl_id", "equipment_install", ["functional_location_id"])
    op.create_index(
        "uq_active_install_per_fl", "equipment_install", ["functional_location_id"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL"),
        sqlite_where=sa.text("removed_at IS NULL"),
    )
    op.create_index(
        "uq_active_install_per_equipment", "equipment_install", ["equipment_id"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL"),
        sqlite_where=sa.text("removed_at IS NULL"),
    )

    op.create_table(
        "meter",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("equipment_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("equipment.id"), nullable=False),
        sa.Column("meter_type", meter_type, nullable=False),
        sa.Column("unit", sa.String(40), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_meter_equipment_id", "meter", ["equipment_id"])

    op.create_table(
        "meter_reading",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("meter_id", sa.Uuid(as_uuid=True), sa.ForeignKey("meter.id"), nullable=False),
        sa.Column("reading_value", sa.Float, nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", reading_source, nullable=False, server_default="manual"),
        sa.Column("recorded_by", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.create_index("ix_meter_reading_meter_id", "meter_reading", ["meter_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("actor_user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("entity_type", sa.String(80), nullable=False),
        sa.Column("entity_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("action", audit_action, nullable=False),
        sa.Column("before", json_type, nullable=True),
        sa.Column("after", json_type, nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_audit_entity_type", "audit_log", ["entity_type"])
    op.create_index("ix_audit_entity_id", "audit_log", ["entity_id"])

    # Immutability is a database guarantee: block UPDATE/DELETE on append-only
    # tables at the engine level (Postgres only).
    if _is_pg():
        op.execute(
            """
            CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Table % is append-only', TG_TABLE_NAME;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
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
        op.execute("DROP FUNCTION IF EXISTS reject_mutation();")

    op.drop_table("audit_log")
    op.drop_table("meter_reading")
    op.drop_table("meter")
    op.drop_table("equipment_install")
    op.drop_table("equipment")
    op.drop_table("functional_location")
    op.drop_table("space")
    op.drop_table("building")
    op.drop_table("site")
    op.drop_table("customer_account")

    if _is_pg():
        for enum in _ALL_ENUMS:
            enum.drop(op.get_bind(), checkfirst=True)
