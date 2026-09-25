"""channel (telegram) as a human login method

Revision ID: 0005_channel_login
Revises: 0004_scim_provisioning
Create Date: 2026-09-25 15:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_channel_login"
down_revision = "0004_scim_provisioning"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "channel_providers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("channel IN ('telegram')", name="channel"),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_channel_providers_tenant"),
        sa.PrimaryKeyConstraint("id", name="pk_channel_providers"),
        sa.UniqueConstraint("tenant_id", "channel", name="uq_channel_providers_tenant_channel"),
    )
    op.create_table(
        "channel_link_intents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(length=40), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("external_identity_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint("channel IN ('telegram')", name="channel"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_channel_link_intents_tenant"
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["principals.id"], name="fk_channel_link_intents_principal"
        ),
        sa.ForeignKeyConstraint(
            ["external_identity_id"],
            ["external_identities.id"],
            name="fk_channel_link_intents_external_identity",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_channel_link_intents"),
        sa.UniqueConstraint("code_hash", name="uq_channel_link_intents_code_hash"),
    )
    op.create_index(
        "ix_channel_link_intents_principal",
        "channel_link_intents",
        ["tenant_id", "principal_id", "created_at"],
    )
    # Лимиты частоты считают недавние записи audit по действию.
    op.create_index(
        "ix_audit_events_action", "audit_events", ["tenant_id", "action", "occurred_at"]
    )

    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint(
            "source", "source IN ('manual', 'federated', 'provisioned', 'channel')"
        )


def downgrade() -> None:
    op.drop_index("ix_channel_link_intents_principal", table_name="channel_link_intents")
    op.drop_table("channel_link_intents")
    # Привязки каналов без своих таблиц смысла не имеют и старым ограничением
    # `source` не допускаются.
    op.execute("DELETE FROM external_identities WHERE source = 'channel'")
    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('manual', 'federated', 'provisioned')")

    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("channel_providers")
