"""Upgrade existing databases without losing memory or relational checks."""

import os
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from connectd.store import Store


class MemoryMigrationTests(unittest.TestCase):
    def _upgrade_existing(self, url: str) -> None:
        config = Config()
        config.set_main_option("script_location", str(
            Path(__file__).parents[1] / "src" / "connectd" / "migrations"))
        config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
        command.upgrade(config, "0008")
        store = Store(url)
        with store.connect() as db:
            db.execute("INSERT INTO organizations(org_id,name,created_at) VALUES (?,?,?)",
                       ("migration-org", "Migration", "2026-01-01T00:00:00Z"))
            db.execute("""INSERT INTO memory_claims(claim_id,org_id,scope,claim_text,
                status,is_trusted,origin,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                ("migration-claim", "migration-org", "repo:historical", "Vetted",
                 "promoted", True, "legacy_etl", "2026-01-01T00:00:00Z"))
        store.dispose()
        command.upgrade(config, "head")
        store = Store(url)
        try:
            with store.connect() as db:
                org = db.execute("""SELECT memory_authority,allow_remote_librarian
                    FROM organizations WHERE org_id=?""",
                                 ("migration-org",)).fetchone()
                claim = db.execute("SELECT task_id,claim_text FROM memory_claims WHERE claim_id=?",
                                   ("migration-claim",)).fetchone()
                db.execute("SELECT handler_id FROM tool_registry LIMIT 1").fetchone()
                db.execute("SELECT admin_id FROM daemon_admins LIMIT 1").fetchone()
                db.execute("SELECT job_id FROM memory_evaluation_jobs LIMIT 1").fetchone()
            self.assertEqual(org["memory_authority"], "hybrid")
            self.assertFalse(org["allow_remote_librarian"])
            self.assertIsNone(claim["task_id"])
            self.assertEqual(claim["claim_text"], "Vetted")
            with self.assertRaises(IntegrityError):
                with store.connect() as db:
                    db.execute("""INSERT INTO memory_claims(claim_id,org_id,task_id,scope,
                        claim_text,status,is_trusted,origin,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        ("orphan", "migration-org", "missing-task", "task:missing-task",
                         "Should reject", "pending", False, "test", "2026-01-01T00:00:00Z"))
            with self.assertRaises(IntegrityError):
                with store.connect() as db:
                    db.execute("""UPDATE memory_claims SET status='unsupported'
                        WHERE claim_id='migration-claim'""")
        finally:
            store.dispose()

    def test_sqlite_upgrade(self):
        scratch = Path(__file__).parents[1] / "work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            path = Path(directory) / "upgrade.db"
            self._upgrade_existing("sqlite:///" + path.as_posix())

    @unittest.skipUnless(os.environ.get("CONNECTD_TEST_POSTGRES_URL"),
                         "no isolated PostgreSQL test URL")
    def test_postgres_upgrade(self):
        base_url = os.environ["CONNECTD_TEST_POSTGRES_URL"]
        database_name = "connectd_migration_" + uuid4().hex
        admin = create_engine(base_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as connection:
                connection.exec_driver_sql(f"CREATE DATABASE {database_name}")
            test_url = make_url(base_url).set(database=database_name).render_as_string(hide_password=False)
            try:
                self._upgrade_existing(test_url)
            finally:
                with admin.connect() as connection:
                    connection.exec_driver_sql(f"DROP DATABASE {database_name} WITH (FORCE)")
        finally:
            admin.dispose()
