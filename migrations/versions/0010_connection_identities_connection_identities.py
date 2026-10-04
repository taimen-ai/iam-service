"""connection identities: source `connection` and the reserved issuer prefix (ADR-0004)

Revision ID: 0010_connection_identities
Revises: 0009_identity_email
Create Date: 2026-09-30 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_connection_identities"
down_revision = "0009_identity_email"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Префикс `connection:` зарезервирован за identity подключений: провайдер
    # с таким issuer дал бы federation войти парой подключения. API такого не
    # допускает (`invalid_issuer`), но данные могли попасть в базу в обход него.
    reserved = (
        op.get_bind()
        .execute(sa.text("SELECT key FROM identity_providers WHERE issuer LIKE 'connection:%'"))
        .scalars()
        .all()
    )
    if reserved:
        raise RuntimeError(
            "identity providers with the reserved issuer prefix 'connection:' exist "
            f"(keys: {', '.join(sorted(reserved))}); fix their issuer before upgrading"
        )
    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint(
            "source",
            "source IN ('manual', 'federated', 'provisioned', 'channel', 'connection')",
        )


def downgrade() -> None:
    # Сопоставления подключений входа не дают и старым ограничением `source`
    # не допускаются.
    op.execute("DELETE FROM external_identities WHERE source = 'connection'")
    with op.batch_alter_table("external_identities") as batch:
        batch.drop_constraint("source", type_="check")
        batch.create_check_constraint(
            "source", "source IN ('manual', 'federated', 'provisioned', 'channel')"
        )
