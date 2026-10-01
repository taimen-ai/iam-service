"""principal :enable — idempotency key and moment of enabling

Revision ID: 0008_principal_enable
Revises: 0007_people_scope
Create Date: 2026-09-29 18:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_principal_enable"
down_revision = "0007_people_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ключ включения принадлежит вызывающему (как ключ создания в membership),
    # а момент включения отсекает access token, выпущенные до отключения.
    op.create_table(
        "principal_enablements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("principal_id", sa.Uuid(), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("previous_status", sa.String(20), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=True),
        sa.Column("idempotency_actor", sa.String(200), nullable=True),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_actor",
            "idempotency_key",
            name="uq_principal_enablements_idempotency",
        ),
    )
    op.create_index(
        "ix_principal_enablements_principal",
        "principal_enablements",
        ["principal_id", "enabled_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_principal_enablements_principal", table_name="principal_enablements")
    op.drop_table("principal_enablements")
