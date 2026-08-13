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
