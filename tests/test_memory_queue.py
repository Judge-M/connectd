"""Independent librarian review cannot be replaced by worker confidence."""

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from connectd.api import create_app
from connectd.auth import AuthService
from connectd.config import ConnectdConfig
from connectd.memory_evaluator import EvaluationResult
from connectd.memory_queue import MemoryEvaluationQueue
from connectd.store import Store


class FixedEvaluator:
    def __init__(self, score: float, corroborated: bool = True):
        self.score = score
        self.corroborated = corroborated
        self.calls = []

    async def evaluate_claim(self, claim_text, provenance_context, existing_org_claims):
        self.calls.append((claim_text, provenance_context, existing_org_claims))
        return EvaluationResult(confidence_score=self.score,
            is_corroborated=self.corroborated, contradiction_detected=False,
            reasoning_summary="Independent evidence check")


class MemoryQueueTests(unittest.TestCase):
    def test_remote_evaluator_requires_daemon_and_organization_consent(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "consent.db")
            store.initialize()
            from connectd.task import TaskManager
            from connectd.compute import PrivacyClass
            from connectd.memory import MemoryLedger

            task_id = TaskManager(store).create_task("Task", PrivacyClass.PUBLIC,
                "repo:example", execution_profile="dev_fast")
            with store.connect() as db:
                db.execute("UPDATE organizations SET memory_authority='session_auto' WHERE org_id='default'")
            MemoryLedger(store).capture(f"task:{task_id}", "Private org claim", "worker",
                task_id=task_id, auto_promote=True, queue_for_librarian=True,
                sources=[{"source_uri": "artifact:evidence", "source_hash": "abc"}])
            evaluator = FixedEvaluator(0.99)
            settings = {"type": "http_json", "endpoint_url": "https://evaluator.example/review"}
            daemon_off = ConnectdConfig(memory={"evaluator": settings})
            self.assertFalse(MemoryEvaluationQueue(store, daemon_off, evaluator).process_one())
            with store.connect() as db:
                self.assertIn("consent", db.execute(
                    "SELECT reason FROM memory_evaluation_jobs").fetchone()["reason"])
                db.execute("UPDATE organizations SET allow_remote_librarian=TRUE WHERE org_id='default'")
            self.assertFalse(MemoryEvaluationQueue(store, daemon_off, evaluator).process_one())
            daemon_on = ConnectdConfig(memory={"evaluator": {
                **settings, "allow_remote_https": True}})
            self.assertTrue(MemoryEvaluationQueue(store, daemon_on, evaluator).process_one())
            self.assertEqual(len(evaluator.calls), 1)
            store.dispose()

    def test_worker_confidence_cannot_promote_without_independent_review(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "queue.db")
            config = ConnectdConfig(default_execution_profile="dev_fast")
            operator_token = "o" * 40
            client = TestClient(create_app(config, store, Ed25519PrivateKey.generate(),
                                           operator_token))
            with store.connect() as db:
                db.execute("""UPDATE organizations SET memory_authority='session_auto'
                    WHERE org_id='default'""")
            operator = {"Authorization": "Bearer " + operator_token}
            task_id = client.post("/api/v1/tasks", headers=operator, json={
                "title": "Evidence task", "privacy_class": "public",
                "memory_scope": "repo:example"}).json()["task_id"]
            auth = AuthService(store, operator_token)
            worker = {"Authorization": "Bearer " + auth.issue_worker(task_id, "worker")}
            captured = client.post(f"/api/v1/tasks/{task_id}/memory/capture",
                headers=worker, json={"claim_text": "A proposed fact", "confidence": 1.0,
                    "confidence_label": "verified", "sources": [{
                        "source_uri": "artifact:test", "source_hash": "abc"}]})
            self.assertEqual(captured.status_code, 201, captured.text)
            with store.connect() as db:
                job = db.execute("SELECT * FROM memory_evaluation_jobs").fetchone()
                candidate = db.execute("SELECT * FROM memory_claims WHERE claim_id=?",
                                       (job["candidate_claim_id"],)).fetchone()
            self.assertFalse(candidate["is_trusted"])
            self.assertIsNone(candidate["confidence"])
            self.assertEqual(candidate["scope"], "org:default")
            self.assertFalse(MemoryEvaluationQueue(store, config).process_one())
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT status FROM memory_evaluation_jobs").fetchone()["status"],
                                 "pending")
            review_config = ConnectdConfig(default_execution_profile="dev_fast",
                memory={"evaluator": {"type": "http_json",
                    "endpoint_url": "http://127.0.0.1:8799/evaluate"}})
            low = FixedEvaluator(0.89)
            self.assertTrue(MemoryEvaluationQueue(store, review_config, low).process_one())
            self.assertEqual(len(low.calls), 1)
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT status FROM memory_evaluation_jobs").fetchone()["status"],
                                 "review_required")
                self.assertFalse(db.execute("SELECT is_trusted FROM memory_claims WHERE claim_id=?",
                    (job["candidate_claim_id"],)).fetchone()["is_trusted"])
            store.dispose()

    def test_high_independent_score_promotes_only_in_session_auto(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "queue.db")
            store.initialize()
            from connectd.task import TaskManager
            from connectd.compute import PrivacyClass
            from connectd.memory import MemoryLedger

            task_id = TaskManager(store).create_task("Task", PrivacyClass.PUBLIC,
                "repo:example", execution_profile="dev_fast")
            with store.connect() as db:
                db.execute("UPDATE organizations SET memory_authority='session_auto' WHERE org_id='default'")
            claim_id = MemoryLedger(store).capture(f"task:{task_id}", "Grounded", "worker",
                task_id=task_id, auto_promote=True, queue_for_librarian=True,
                sources=[{"source_uri": "artifact:test", "source_hash": "abc"}])
            config = ConnectdConfig(memory={"evaluator": {"type": "http_json",
                "endpoint_url": "http://127.0.0.1:8799/evaluate"}})
            evaluator = FixedEvaluator(0.95)
            self.assertTrue(MemoryEvaluationQueue(store, config, evaluator).process_one())
            with store.connect() as db:
                job = db.execute("SELECT * FROM memory_evaluation_jobs").fetchone()
                candidate = db.execute("SELECT * FROM memory_claims WHERE claim_id=?",
                                       (job["candidate_claim_id"],)).fetchone()
            self.assertEqual(job["source_claim_id"], claim_id)
            self.assertEqual(job["status"], "promoted")
            self.assertTrue(candidate["is_trusted"])
            self.assertEqual(candidate["confidence"], 0.95)
            self.assertIn("Grounded", MemoryLedger(store).recall("repo:example"))
            second = MemoryLedger(store).capture(f"task:{task_id}", "Do not promote",
                "worker", task_id=task_id, auto_promote=True,
                queue_for_librarian=True,
                sources=[{"source_uri": "artifact:other", "source_hash": "def"}])
            with store.connect() as db:
                db.execute("UPDATE organizations SET memory_authority='hybrid' WHERE org_id='default'")
            calls_before = len(evaluator.calls)
            self.assertTrue(MemoryEvaluationQueue(store, config, evaluator).process_one())
            self.assertEqual(len(evaluator.calls), calls_before)
            with store.connect() as db:
                blocked = db.execute("""SELECT j.status,c.is_trusted FROM memory_evaluation_jobs j
                    JOIN memory_claims c ON c.claim_id=j.candidate_claim_id
                    WHERE j.source_claim_id=?""", (second,)).fetchone()
            self.assertEqual(blocked["status"], "review_required")
            self.assertFalse(blocked["is_trusted"])
            store.dispose()


if __name__ == "__main__":
    unittest.main()
