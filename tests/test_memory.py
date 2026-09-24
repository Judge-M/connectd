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
from connectd.memory import MemoryLedger, _validity, effective_memory_authority
from connectd.store import Store
from connectd.task import TaskManager


class MemoryTests(unittest.TestCase):
    def test_genesis_expires_bootstrap_and_only_daemon_admin_promotes_global(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "genesis.db")
            bootstrap_token = "b" * 40
            client = TestClient(create_app(ConnectdConfig(), store,
                Ed25519PrivateKey.generate(), bootstrap_token))
            bootstrap = {"Authorization": "Bearer " + bootstrap_token}
            auth = AuthService(store, bootstrap_token)
            _, org_admin_token = auth.issue_operator("default", "Org admin", "admin")
            org_admin = {"Authorization": "Bearer " + org_admin_token}
            self.assertEqual(client.get("/api/v1/me", headers=bootstrap).status_code, 200)
            admin_id, system_token = auth.genesis("System owner")
            system = {"Authorization": "Bearer " + system_token}
            self.assertEqual(client.get("/api/v1/me", headers=bootstrap).status_code, 403)
            self.assertEqual(client.get("/api/v1/me", headers=system).json()["user_id"],
                             admin_id)
            with self.assertRaises(ValueError):
                auth.genesis("Again")
            self.assertEqual(client.post("/api/v1/memory/global/capture",
                headers=org_admin, json={"claim_text": "System baseline"}).status_code, 403)
            captured = client.post("/api/v1/memory/global/capture",
                headers=system, json={"claim_text": "System baseline"})
            self.assertEqual(captured.status_code, 201, captured.text)
            claim_id = captured.json()["claim_id"]
            self.assertEqual([item["claim_id"] for item in client.get(
                "/api/v1/memory/global/candidates", headers=system).json()], [claim_id])
            self.assertEqual(client.post("/api/v1/memory/global/promote",
                headers=org_admin, json={"claim_id": claim_id}).status_code, 403)
            self.assertEqual(client.post("/api/v1/memory/global/promote",
                headers=system, json={"claim_id": claim_id}).status_code, 200)
            store.dispose()

    def test_validity_labels_do_not_guess_timezones(self):
        self.assertEqual(_validity("2000-01-01T00:00:00Z"), "stale")
        self.assertEqual(_validity("2000-01-01T00:00:00"), "unknown")
        self.assertEqual(_validity("bad-date"), "unknown")
        self.assertEqual(_validity(None, "2099-01-01T00:00:00Z"), "not_yet_valid")

    def test_task_memory_uses_stricter_policy_and_never_leaks_to_other_tasks(self):
        self.assertEqual(effective_memory_authority("hybrid", "session_auto"), "hybrid")
        self.assertEqual(effective_memory_authority("session_auto", "human_gated"),
                         "human_gated")
        with self.assertRaises(ValueError):
            effective_memory_authority("unknown", "hybrid")
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "task-memory.db")
            store.initialize()
            manager = TaskManager(store)
            task_a = manager.create_task("A", PrivacyClass.PUBLIC, "repo:shared",
                                         execution_profile="dev_fast")
            task_b = manager.create_task("B", PrivacyClass.PUBLIC, "repo:shared")
            token = "o" * 40
            auth = AuthService(store, token)
            worker_a = {"Authorization": "Bearer " + auth.issue_worker(task_a, "a")}
            worker_b = {"Authorization": "Bearer " + auth.issue_worker(task_b, "b")}
            client = TestClient(create_app(ConnectdConfig(), store,
                                           Ed25519PrivateKey.generate(), token))
            captured = client.post(f"/api/v1/tasks/{task_a}/memory/capture",
                headers=worker_a, json={"claim_text": "Only A should know"})
            self.assertEqual(captured.status_code, 201, captured.text)
            self.assertEqual(captured.json()["memory_authority"], "hybrid")
            self.assertEqual(captured.json()["status"], "promoted")
            with store.connect() as db:
                claim = db.execute("SELECT task_id,scope,is_trusted FROM memory_claims WHERE claim_id=?",
                                   (captured.json()["claim_id"],)).fetchone()
            self.assertEqual(claim["task_id"], task_a)
            self.assertEqual(claim["scope"], f"task:{task_a}")
            self.assertTrue(claim["is_trusted"])
            self.assertIn("Only A should know", client.get(
                f"/api/v1/tasks/{task_a}/context-pack", headers=worker_a).json()["memory"])
            self.assertNotIn("Only A should know", client.get(
                f"/api/v1/tasks/{task_b}/context-pack", headers=worker_b).json()["memory"])
            with store.connect() as db:
                db.execute("UPDATE tasks SET is_terminal=TRUE,status='completed' WHERE task_id=?",
                           (task_a,))
            self.assertNotIn("Only A should know", client.get(
                f"/api/v1/tasks/{task_a}/context-pack", headers=worker_a).json()["memory"])
            self.assertEqual(client.post(f"/api/v1/tasks/{task_a}/memory/capture",
                headers=worker_a, json={"claim_text": "Too late"}).status_code, 409)
            with store.connect() as db:
                db.execute("UPDATE organizations SET memory_authority='human_gated' WHERE org_id='default'")
            gated = client.post(f"/api/v1/tasks/{task_b}/memory/capture",
                headers=worker_b, json={"claim_text": "Needs admin"})
            self.assertEqual(gated.json()["status"], "pending")
            self.assertNotIn("Needs admin", client.get(
                f"/api/v1/tasks/{task_b}/context-pack", headers=worker_b).json()["memory"])
            claim_id = gated.json()["claim_id"]
            _, admin_token = auth.issue_operator("default", "Memory admin", "admin")
            admin = {"Authorization": "Bearer " + admin_token}
            bootstrap = {"Authorization": "Bearer " + token}
            self.assertEqual(client.post(f"/api/v1/memory/claims/{claim_id}/promote",
                headers=bootstrap).status_code, 403)
            self.assertEqual(client.post(f"/api/v1/memory/claims/{claim_id}/promote",
                headers=admin).status_code, 200)
            self.assertIn("Needs admin", client.get(
                f"/api/v1/tasks/{task_b}/context-pack", headers=worker_b).json()["memory"])
            permanent = client.post(
                f"/api/v1/memory/claims/{claim_id}/promote-to-org", headers=admin)
            self.assertEqual(permanent.status_code, 201, permanent.text)
            self.assertNotEqual(permanent.json()["claim_id"], claim_id)
            self.assertEqual(permanent.json()["scope"], "org:default")
            self.assertIn("Needs admin", client.get(
                f"/api/v1/tasks/{task_a}/context-pack", headers=worker_a).json()["memory"])
            with store.connect() as db:
                original = db.execute("SELECT scope FROM memory_claims WHERE claim_id=?",
                    (claim_id,)).fetchone()
            self.assertEqual(original["scope"], f"task:{task_b}")
            store.dispose()

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
            stale = ledger.capture("repo:connectd", "Expired fact", "worker",
                valid_until="2000-01-01T00:00:00Z")
            old = ledger.capture("repo:connectd", "Superseded fact", "worker")
            global_claim = ledger.capture("global", "Global fact", "operator")
            pending = ledger.capture("repo:connectd", "Unreviewed fact", "worker")
            for identifier in (stale, old, global_claim):
                ledger.promote(identifier, "operator")
            with store.connect() as db:
                db.execute("UPDATE memory_claims SET superseded_by=? WHERE claim_id=?", (claim, old))
            operator_token = "o" * 40
            worker_token = AuthService(store, operator_token).issue_worker(task_id, "worker")
            client = TestClient(create_app(ConnectdConfig(), store,
                                           Ed25519PrivateKey.generate(), operator_token))
            full = client.post("/recall", json={"scope": "repo:connectd"},
                headers={"Authorization": "Bearer " + operator_token})
            self.assertEqual(full.status_code, 200, full.text)
            full_items = {item["id"]: item for item in full.json()["items"]}
            self.assertEqual(full_items[claim]["sources"][0]["source_uri"], "evidence.md")
            self.assertEqual(full_items[stale]["validity"], "stale")
            self.assertEqual(full_items[old]["validity"], "superseded")
            self.assertFalse(full_items[pending]["trusted"])
            brief = client.post(f"/api/v1/tasks/{task_id}/memory/recall",
                json={"scope": "repo:connectd", "profile": "worker_brief"},
                headers={"Authorization": "Bearer " + worker_token})
            self.assertEqual(brief.json()["items"], [{"text": "Grounded fact",
                "scope": {"type": "repo", "id": "connectd"}, "trusted": True},
                {"text": "Global fact", "scope": {"type": "global", "id": ""},
                 "trusted": True}])
            context = client.get(f"/api/v1/tasks/{task_id}/context-pack",
                headers={"Authorization": "Bearer " + worker_token})
            self.assertEqual(context.json()["memory"], ["Grounded fact", "Global fact"])
            denied = client.post(f"/api/v1/tasks/{task_id}/memory/recall",
                json={"scope": "repo:other"},
                headers={"Authorization": "Bearer " + worker_token})
            self.assertEqual(denied.status_code, 403)
            store.dispose()
