import asyncio
from pathlib import Path
import sqlite3
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from src.settings import settings
from tests.support.paths import ALEMBIC_INI


async def test_migration_legacy_family_id_and_security_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies that 6aa8f9bfed61 isolates legacy session families and increments security_version."""
    db_file = tmp_path / "test_migration.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    monkeypatch.setattr(settings, "database_url", db_url)

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)

    # 1. Upgrade up to 1481b1cdf6a4
    await asyncio.to_thread(command.upgrade, cfg, "1481b1cdf6a4")

    # 2. Seed data before family_id column exists
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (id, name, email, hashed_password, role, is_active, security_version) "
            "VALUES (1, 'User One', 'user1@example.com', 'hash1', 'USER', 1, 1)"
        )
        cursor.execute(
            "INSERT INTO users (id, name, email, hashed_password, role, is_active, security_version) "
            "VALUES (2, 'User Two', 'user2@example.com', 'hash2', 'USER', 1, 1)"
        )
        # 2 sessions for User 1
        cursor.execute(
            "INSERT INTO refresh_sessions (id, user_id, refresh_token_jti, is_revoked, expires_at) "
            "VALUES (1, 1, 'jti-u1-s1', 0, '2030-01-01 00:00:00')"
        )
        cursor.execute(
            "INSERT INTO refresh_sessions (id, user_id, refresh_token_jti, is_revoked, expires_at) "
            "VALUES (2, 1, 'jti-u1-s2', 0, '2030-01-01 00:00:00')"
        )
        # 2 sessions for User 2
        cursor.execute(
            "INSERT INTO refresh_sessions (id, user_id, refresh_token_jti, is_revoked, expires_at) "
            "VALUES (3, 2, 'jti-u2-s1', 0, '2030-01-01 00:00:00')"
        )
        cursor.execute(
            "INSERT INTO refresh_sessions (id, user_id, refresh_token_jti, is_revoked, expires_at) "
            "VALUES (4, 2, 'jti-u2-s2', 0, '2030-01-01 00:00:00')"
        )
        conn.commit()

    # 3. Upgrade to f2001b0d2995 (the flawed migration with server_default='legacy')
    await asyncio.to_thread(command.upgrade, cfg, "f2001b0d2995")

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT family_id FROM refresh_sessions")
        rows = cursor.fetchall()
        assert len(rows) == 4
        assert all(row[0] == "legacy" for row in rows)

    # 4. Upgrade to head (our corrective migration)
    await asyncio.to_thread(command.upgrade, cfg, "head")

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id, refresh_token_jti, family_id FROM refresh_sessions")
        sessions = cursor.fetchall()
        assert len(sessions) == 4
        # Verify family_id == refresh_token_jti for each row
        family_ids = [row[3] for row in sessions]
        for sid, uid, jti, fid in sessions:
            assert fid == jti
        assert len(set(family_ids)) == 4

        # Verify security_version bumped to 2 for all users
        cursor.execute("SELECT id, security_version FROM users")
        user_rows = cursor.fetchall()
        assert len(user_rows) == 2
        assert all(row[1] == 2 for row in user_rows)

        # Verify family_id has no server_default
        cursor.execute("PRAGMA table_info(refresh_sessions)")
        cols = cursor.fetchall()
        family_col = next(c for c in cols if c[1] == "family_id")
        assert family_col[4] is None

    # Verify exactly one head
    script = ScriptDirectory.from_config(cfg)
    assert len(script.get_heads()) == 1


async def test_migration_clean_upgrade_and_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies that an empty database upgrades to head without drift."""
    db_file = tmp_path / "clean_migration.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    monkeypatch.setattr(settings, "database_url", db_url)

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)

    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.check, cfg)
