"""Memory recall retains authority metadata without widening worker trust."""

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from connectd.api import create_app
from connectd.auth import AuthService
from connectd.compute import PrivacyClass
from connectd.config import ConnectdConfig
from connectd.memory import MemoryLedger, _validity
from connectd.store import Store
from connectd.task import TaskManager


class MemoryTests(unittest.TestCase):
    def test_validity_labels_do_not_guess_timezones(self):
        self.assertEqual(_validity("2000-01-01T00:00:00Z"), "stale")
        self.assertEqual(_validity("2000-01-01T00:00:00"), "unknown")
        self.assertEqual(_validity("bad-date"), "unknown")

    def test_provenance_validity_and_contradiction_filter(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "memory.db")
            store.initialize()
            ledger = MemoryLedger(store)
            first = ledger.capture("repo:connectd", "Primary claim", "operator",
                confidence=0.92, confidence_label="high", valid_until="2099-01-01T00:00:00Z",
                tags=["architecture"], sources=[{"source_id": "src-1", "source_uri": "notes.md",
                    "source_hash": "abc", "origin": "document", "title": "Notes"}])
            other = ledger.capture("repo:connectd", "Conflicting claim", "operator")
            ledger.promote(first, "human-1")
            ledger.promote(other, "human-1")
            records = ledger.recall_records("repo:connectd")
            selected = next(item for item in records if item["id"] == first)
            self.assertEqual(selected["confidence"], "high")
            self.assertEqual(selected["confidence_score"], 0.92)
            self.assertEqual(selected["validity"], "current")
            self.assertEqual(selected["sources"][0]["title"], "Notes")
            self.assertEqual(selected["tags"], ["architecture"])
            with store.connect() as db:
                db.execute("""INSERT INTO claim_contradictions(contradiction_id,existing_claim_id,
                    new_claim_id,status) VALUES (?,?,?,'open')""", ("conflict-1", first, other))
            self.assertEqual(ledger.recall("repo:connectd"), [])
            flagged = ledger.recall_records("repo:connectd", trusted_only=False)
            self.assertEqual(len(flagged), 2)
            self.assertFalse(flagged[0]["trusted"])
            self.assertEqual(flagged[0]["contradiction_warnings"][0]["contradiction_id"], "conflict-1")
            store.dispose()

    def test_full_recall_and_worker_brief_respect_task_scope(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "api-memory.db")
            store.initialize()
            task_id = TaskManager(store).create_task("Recall", PrivacyClass.REPO_SENSITIVE,
                                                      "repo:connectd")
            ledger = MemoryLedger(store)
            claim = ledger.capture("repo:connectd", "Grounded fact", "worker", sources=[{
                "source_uri": "evidence.md", "source_hash": "abc"}])
            ledger.promote(claim, "operator", "verified")
            operator_token = "o" * 40
            worker_token = AuthService(store, operator_token).issue_worker(task_id, "worker")
            client = TestClient(create_app(ConnectdConfig(), store,
                                           Ed25519PrivateKey.generate(), operator_token))
            full = client.post("/recall", json={"scope": "repo:connectd"},
                headers={"Authorization": "Bearer " + operator_token})
            self.assertEqual(full.status_code, 200, full.text)
            self.assertEqual(full.json()["items"][0]["sources"][0]["source_uri"], "evidence.md")
            brief = client.post(f"/api/v1/tasks/{task_id}/memory/recall",
                json={"scope": "repo:connectd", "profile": "worker_brief"},
                headers={"Authorization": "Bearer " + worker_token})
            self.assertEqual(brief.json()["items"], [{"text": "Grounded fact",
                "scope": {"type": "repo", "id": "connectd"}, "trusted": True}])
            denied = client.post(f"/api/v1/tasks/{task_id}/memory/recall",
                json={"scope": "repo:other"},
                headers={"Authorization": "Bearer " + worker_token})
            self.assertEqual(denied.status_code, 403)
            store.dispose()
