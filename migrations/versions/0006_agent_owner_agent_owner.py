"""owner of an agent principal (scope iam:agents)

Revision ID: 0006_agent_owner
Revises: 0005_channel_login
Create Date: 2026-09-27 06:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_agent_owner"
down_revision = "0005_channel_login"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Существующие principal заведены bootstrap-операцией и владельца не имеют.
    with op.batch_alter_table("principals") as batch:
        batch.add_column(sa.Column("owner_principal_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_principals_owner", "principals", ["owner_principal_id"], ["id"]
        )
    op.create_index("ix_principals_owner", "principals", ["owner_principal_id"])


def downgrade() -> None:
    op.drop_index("ix_principals_owner", table_name="principals")
    with op.batch_alter_table("principals") as batch:
        batch.drop_constraint("fk_principals_owner", type_="foreignkey")
        batch.drop_column("owner_principal_id")
