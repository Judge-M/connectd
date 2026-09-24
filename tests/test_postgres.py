"""Run with CONNECTD_TEST_POSTGRES_URL set to an isolated test database."""

import os
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectd.compute import PrivacyClass
from connectd.config import ConnectdConfig
from connectd.governance import Governance
from connectd.memory import MemoryLedger
from connectd.store import Store
from connectd.task import TaskManager


@unittest.skipUnless(os.environ.get("CONNECTD_TEST_POSTGRES_URL"), "no isolated PostgreSQL test URL")
class PostgresIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.environ["CONNECTD_TEST_POSTGRES_URL"])
        self.store.initialize()

    def tearDown(self):
        self.store.dispose()

    def test_task_grant_memory_in_one_postgres(self):
        scope = "repo:pg-test-" + uuid.uuid4().hex
        task_id = TaskManager(self.store).create_task("Postgres check", PrivacyClass.PUBLIC, scope)
        tool_id = "read-" + uuid.uuid4().hex
        with self.store.connect() as db:
            db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,active)
                VALUES (?,?,?,?,?,?)""", (tool_id, "Read", "code.read", "{}", 0, True))
        grant = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile()).issue(task_id, "worker-pg", tool_id, {})
        self.assertEqual(grant["tool_id"], tool_id)
        memory = MemoryLedger(self.store)
        claim = memory.capture(scope, "PG works", "worker-pg")
        self.assertEqual(memory.recall(scope), [])
        memory.promote(claim, "operator-pg")
        self.assertIn("PG works", memory.recall(scope))
