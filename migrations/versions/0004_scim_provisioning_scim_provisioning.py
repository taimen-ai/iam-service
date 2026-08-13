"""scim 2.0 identity provisioning

Revision ID: 0004_scim_provisioning
Revises: 0003_platform_access_tokens
Create Date: 2026-08-14 02:05:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_scim_provisioning"
down_revision = "0003_platform_access_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provisioning_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("service_principal_id", sa.Uuid(), nullable=True),
        sa.Column("upstream_mode", sa.String(length=20), nullable=False),
        sa.Column("upstream_base_url", sa.String(length=500), nullable=False),
        sa.Column("upstream_realm", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("stale_after_seconds", sa.Integer(), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stale_alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('scim', 'ldap')", name="ck_provisioning_sources_kind"),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name="ck_provisioning_sources_status"
        ),
        sa.CheckConstraint(
            "upstream_mode IN ('off', 'scim', 'admin', 'auto')",
            name="ck_provisioning_sources_upstream_mode",
        ),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"],
            ["identity_providers.id"],
            name="fk_provisioning_sources_identity_provider",
        ),
        sa.ForeignKeyConstraint(
            ["service_principal_id"],
            ["principals.id"],
            name="fk_provisioning_sources_service_principal",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_provisioning_sources_tenant"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_provisioning_sources"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_provisioning_sources_tenant_key"),
        # Одна population — один authoritative source: SCIM и LDAP не могут
        # писать в один identity provider одновременно.
        sa.UniqueConstraint(
            "tenant_id", "identity_provider_id", name="uq_provisioning_sources_population"
        ),
        sa.UniqueConstraint(
            "service_principal_id", name="uq_provisioning_sources_service_principal"
        ),
    )

    with op.batch_alter_table("external_identities") as batch:
        batch.add_column(sa.Column("provisioning_source_id", sa.Uuid(), nullable=True))
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint(
            "source", "source IN ('manual', 'federated', 'provisioned')"
        )
        batch.create_foreign_key(
            "fk_external_identities_provisioning_source",
            "provisioning_sources",
            ["provisioning_source_id"],
            ["id"],
        )

    with op.batch_alter_table("groups") as batch:
        batch.add_column(sa.Column("provisioning_source_id", sa.Uuid(), nullable=True))
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('local', 'federated', 'scim')")
        batch.create_foreign_key(
            "fk_groups_provisioning_source",
            "provisioning_sources",
            ["provisioning_source_id"],
            ["id"],
        )

    with op.batch_alter_table("group_members") as batch:
        batch.add_column(sa.Column("provisioning_source_id", sa.Uuid(), nullable=True))
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('local', 'federated', 'scim')")
        batch.create_foreign_key(
            "fk_group_members_provisioning_source",
            "provisioning_sources",
            ["provisioning_source_id"],
            ["id"],
        )

    op.create_table(
        "scim_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_source_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(length=500), nullable=False),
        sa.Column("user_name", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("external_identity_id", sa.Uuid(), nullable=True),
        sa.Column("upstream_user_id", sa.String(length=200), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["external_identity_id"],
            ["external_identities.id"],
            name="fk_scim_users_external_identity",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["principals.id"], name="fk_scim_users_principal"
        ),
        sa.ForeignKeyConstraint(
            ["provisioning_source_id"],
            ["provisioning_sources.id"],
            name="fk_scim_users_provisioning_source",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_scim_users_tenant"),
        sa.PrimaryKeyConstraint("id", name="pk_scim_users"),
        sa.UniqueConstraint(
            "provisioning_source_id", "external_id", name="uq_scim_users_source_external_id"
        ),
        sa.UniqueConstraint(
            "provisioning_source_id", "user_name", name="uq_scim_users_source_user_name"
        ),
        sa.UniqueConstraint("principal_id", name="uq_scim_users_principal"),
    )
    op.create_index("ix_scim_users_tenant", "scim_users", ["tenant_id", "provisioning_source_id"])

    op.create_table(
        "scim_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_source_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(length=500), nullable=True),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], name="fk_scim_groups_group"),
        sa.ForeignKeyConstraint(
            ["provisioning_source_id"],
            ["provisioning_sources.id"],
            name="fk_scim_groups_provisioning_source",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_scim_groups_tenant"),
        sa.PrimaryKeyConstraint("id", name="pk_scim_groups"),
        sa.UniqueConstraint(
            "provisioning_source_id", "external_id", name="uq_scim_groups_source_external_id"
        ),
        sa.UniqueConstraint(
            "provisioning_source_id", "display_name", name="uq_scim_groups_source_display_name"
        ),
        sa.UniqueConstraint("group_id", name="uq_scim_groups_group"),
    )
    op.create_index("ix_scim_groups_tenant", "scim_groups", ["tenant_id", "provisioning_source_id"])


def downgrade() -> None:
    op.drop_index("ix_scim_groups_tenant", table_name="scim_groups")
    op.drop_table("scim_groups")
    op.drop_index("ix_scim_users_tenant", table_name="scim_users")
    op.drop_table("scim_users")

    with op.batch_alter_table("group_members") as batch:
        batch.drop_constraint("fk_group_members_provisioning_source", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('local', 'federated')")
        batch.drop_column("provisioning_source_id")

    with op.batch_alter_table("groups") as batch:
        batch.drop_constraint("fk_groups_provisioning_source", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('local', 'federated')")
        batch.drop_column("provisioning_source_id")

    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("fk_external_identities_provisioning_source", type_="foreignkey")
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint("source", "source IN ('manual', 'federated')")
        batch.drop_column("provisioning_source_id")

    op.drop_table("provisioning_sources")
