"""verified e-mail of federated external identity (ADR-0004)

Revision ID: 0009_identity_email
Revises: 0008_principal_enable
Create Date: 2026-09-30 06:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_identity_email"
down_revision = "0008_principal_enable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Почту пишет только federation-вход, и только подтверждённую IdP: у
    # существующих identity она появится при следующем входе. Колонка не
    # уникальна — один ящик законно бывает у двух identity.
    with op.batch_alter_table("external_identities") as batch:
        batch.add_column(sa.Column("email", sa.String(320), nullable=True))
    op.create_index("ix_external_identities_email", "external_identities", ["email"])


def downgrade() -> None:
    op.drop_index("ix_external_identities_email", table_name="external_identities")
    with op.batch_alter_table("external_identities") as batch:
        batch.drop_column("email")
