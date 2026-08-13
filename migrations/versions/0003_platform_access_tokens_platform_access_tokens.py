"""platform access tokens and audience token exchange

Revision ID: 0003_platform_access_tokens
Revises: 0002_identity_federation
Create Date: 2026-08-14 01:35:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_platform_access_tokens"
down_revision = "0002_identity_federation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authentication_contexts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("external_identity_id", sa.Uuid(), nullable=True),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("acr", sa.String(length=200), nullable=True),
        sa.Column("amr", sa.JSON(), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "source IN ('federation', 'bootstrap')", name="ck_authentication_contexts_source"
        ),
        sa.ForeignKeyConstraint(
            ["external_identity_id"],
            ["external_identities.id"],
            name="fk_authentication_contexts_external_identity",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["principals.id"], name="fk_authentication_contexts_principal"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_authentication_contexts_tenant"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authentication_contexts"),
    )
    op.create_index(
        "ix_authentication_contexts_principal",
        "authentication_contexts",
        ["tenant_id", "principal_id", "recorded_at"],
    )
    op.create_table(
        "platform_access_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        # Полный токен не хранится: только lookup prefix и hash секрета.
        sa.Column("public_prefix", sa.String(length=64), nullable=False),
        sa.Column("secret_hash", sa.String(length=128), nullable=False),
        sa.Column("audiences", sa.JSON(), nullable=False),
        sa.Column("scope_ceiling", sa.JSON(), nullable=False),
        sa.Column("authentication_context", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("rotated_from_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=200), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('platform_access_token', 'legacy_control_plane_api_key')",
            name="ck_platform_access_tokens_kind",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["principals.id"], name="fk_platform_access_tokens_principal"
        ),
        sa.ForeignKeyConstraint(
            ["rotated_from_id"],
            ["platform_access_tokens.id"],
            name="fk_platform_access_tokens_rotated_from",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_platform_access_tokens_tenant"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_platform_access_tokens"),
        sa.UniqueConstraint("public_prefix", name="uq_platform_access_tokens_prefix"),
        sa.UniqueConstraint("secret_hash", name="uq_platform_access_tokens_secret_hash"),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_platform_access_tokens_idempotency"
        ),
    )
    op.create_index(
        "ix_platform_access_tokens_principal",
        "platform_access_tokens",
        ["tenant_id", "principal_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_platform_access_tokens_principal", table_name="platform_access_tokens")
    op.drop_table("platform_access_tokens")
    op.drop_index("ix_authentication_contexts_principal", table_name="authentication_contexts")
    op.drop_table("authentication_contexts")
