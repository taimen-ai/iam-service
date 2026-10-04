import sqlite3

from alembic import command
from alembic.config import Config


def test_migration_upgrade_downgrade_upgrade_roundtrip(tmp_path) -> None:
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path}")

    command.upgrade(config, "head")
    with sqlite3.connect(database_path) as connection:
        assert "service_accounts" in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    command.downgrade(config, "base")
    with sqlite3.connect(database_path) as connection:
        assert "service_accounts" not in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    command.upgrade(config, "head")


def test_identity_email_column_and_index(tmp_path) -> None:
    """ADR-0004, п. 1: почта identity — nullable, с неуникальным индексом."""

    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path}")

    command.upgrade(config, "head")
    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(external_identities)")
        }
        indexes = {
            row[1]: row[2] for row in connection.execute("PRAGMA index_list(external_identities)")
        }
    assert columns["email"][2] == "VARCHAR(320)"
    assert columns["email"][3] == 0
    assert indexes["ix_external_identities_email"] == 0

    command.downgrade(config, "0008_principal_enable")
    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(external_identities)")}
    assert "email" not in columns
