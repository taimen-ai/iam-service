"""oidc and ldap identity federation

Revision ID: 0002_identity_federation
Revises: 0001_iam_foundation
Create Date: 2026-08-14 01:10:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_identity_federation"
down_revision = "0001_iam_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identity_providers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("audience", sa.String(length=200), nullable=False),
        sa.Column("jwks_uri", sa.String(length=500), nullable=False),
        sa.Column("subject_claim", sa.String(length=80), nullable=False),
        sa.Column("external_id_claim", sa.String(length=80), nullable=False),
        sa.Column("group_claim", sa.String(length=80), nullable=False),
        sa.Column("group_mappings", sa.JSON(), nullable=False),
        sa.Column("required_acr_values", sa.JSON(), nullable=False),
        sa.Column("required_amr_values", sa.JSON(), nullable=False),
        sa.Column("lifecycle_profile", sa.String(length=20), nullable=False),
        sa.Column("jwks_cache_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("jwks_stale_grace_seconds", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="status"),
        sa.CheckConstraint(
            "lifecycle_profile IN ('read_only', 'managed')", name="lifecycle_profile"
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_identity_providers_tenant_key"),
        sa.UniqueConstraint("tenant_id", "issuer", name="uq_identity_providers_tenant_issuer"),
    )

    with op.batch_alter_table("external_identities") as batch:
        batch.add_column(sa.Column("identity_provider_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("external_id", sa.String(length=500), nullable=True))
        batch.add_column(
            sa.Column("source", sa.String(length=20), nullable=False, server_default="manual")
        )
        batch.add_column(
            sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("last_acr", sa.String(length=200), nullable=True))
        batch.create_check_constraint("source", "source IN ('manual', 'federated')")
        batch.create_foreign_key(
            "fk_external_identities_identity_provider",
            "identity_providers",
            ["identity_provider_id"],
            ["id"],
        )
        batch.create_unique_constraint(
            "uq_external_identities_provider_external_id",
            ["identity_provider_id", "external_id"],
        )

    with op.batch_alter_table("groups") as batch:
        batch.add_column(
            sa.Column("source", sa.String(length=20), nullable=False, server_default="local")
        )
        batch.add_column(sa.Column("identity_provider_id", sa.Uuid(), nullable=True))
        batch.create_check_constraint("source", "source IN ('local', 'federated')")
        batch.create_foreign_key(
            "fk_groups_identity_provider",
            "identity_providers",
            ["identity_provider_id"],
            ["id"],
        )

    with op.batch_alter_table("group_members") as batch:
        batch.add_column(
            sa.Column("source", sa.String(length=20), nullable=False, server_default="local")
        )
        batch.add_column(sa.Column("identity_provider_id", sa.Uuid(), nullable=True))
        batch.create_check_constraint("source", "source IN ('local', 'federated')")
        batch.create_foreign_key(
            "fk_group_members_identity_provider",
            "identity_providers",
            ["identity_provider_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("group_members") as batch:
        batch.drop_constraint("fk_group_members_identity_provider", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.drop_column("identity_provider_id")
        batch.drop_column("source")

    with op.batch_alter_table("groups") as batch:
        batch.drop_constraint("fk_groups_identity_provider", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.drop_column("identity_provider_id")
        batch.drop_column("source")

    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("uq_external_identities_provider_external_id", type_="unique")
        batch.drop_constraint("fk_external_identities_identity_provider", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.drop_column("last_acr")
        batch.drop_column("last_authenticated_at")
        batch.drop_column("source")
        batch.drop_column("external_id")
        batch.drop_column("identity_provider_id")

    op.drop_table("identity_providers")
