"""idempotency key of principal creation (scope iam:people)

Revision ID: 0007_people_scope
Revises: 0006_agent_owner
Create Date: 2026-09-29 06:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_people_scope"
down_revision = "0006_agent_owner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ключ живёт в membership: создание Principal идемпотентно в пределах
    # tenant и вызывающего.
    with op.batch_alter_table("tenant_memberships") as batch:
        batch.add_column(sa.Column("idempotency_key", sa.String(200), nullable=True))
        batch.add_column(sa.Column("idempotency_actor", sa.String(200), nullable=True))
        batch.create_unique_constraint(
            "uq_tenant_memberships_idempotency",
            ["tenant_id", "idempotency_actor", "idempotency_key"],
        )


def downgrade() -> None:
    with op.batch_alter_table("tenant_memberships") as batch:
        batch.drop_constraint("uq_tenant_memberships_idempotency", type_="unique")
        batch.drop_column("idempotency_actor")
        batch.drop_column("idempotency_key")
