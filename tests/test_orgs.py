"""Organization roles and task/memory isolation."""

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from connectd.api import create_app
from connectd.auth import AuthService
from connectd.config import ConnectdConfig
from connectd.compute import PlacementDenied, PrivacyClass, place
from connectd.governance import AuthorizationError, Governance, utcnow
from connectd.memory import MemoryLedger
from connectd.store import Store


class OrganizationTests(unittest.TestCase):
    def test_role_and_task_isolation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "connectd.db")
            app = create_app(ConnectdConfig(), store, Ed25519PrivateKey.generate(),
                             "b" * 40)
            client = TestClient(app)
            bootstrap = {"Authorization": "Bearer " + "b" * 40}
            org_a = client.post("/api/v1/orgs", headers=bootstrap,
                                json={"name": "Alpha"}).json()["org_id"]
            org_b = client.post("/api/v1/orgs", headers=bootstrap,
                                json={"name": "Beta"}).json()["org_id"]
            def user(org_id, name, role):
                result = client.post(f"/api/v1/orgs/{org_id}/users", headers=bootstrap,
                                     json={"display_name": name, "role": role})
                self.assertEqual(result.status_code, 201)
                return {"Authorization": "Bearer " + result.json()["token"]}
            admin_a = user(org_a, "Admin A", "admin")
            operator_a = user(org_a, "Operator A", "operator")
            viewer_a = user(org_a, "Viewer A", "viewer")
            operator_b = user(org_b, "Operator B", "operator")
            payload = {"title": "Owned task", "privacy_class": "repo_sensitive",
                       "memory_scope": "repo:shared"}
            task_a = client.post("/api/v1/tasks", headers=operator_a,
                                 json=payload).json()["task_id"]
            task_b = client.post("/api/v1/tasks", headers=operator_b,
                                 json=payload).json()["task_id"]
            self.assertEqual(client.get("/api/v1/tasks", headers=viewer_a).json()[0]["task_id"],
                             task_a)
            self.assertEqual(client.get(f"/api/v1/tasks/{task_b}",
                                        headers=viewer_a).status_code, 404)
            created_step = client.post(f"/api/v1/tasks/{task_a}/steps",
                                       headers=operator_a,
                                       json={"instruction": "Inspect files"})
            self.assertEqual(created_step.status_code, 201)
            self.assertEqual(len(client.get(f"/api/v1/tasks/{task_a}/steps",
                                            headers=viewer_a).json()), 1)
            self.assertEqual(client.get(f"/api/v1/tasks/{task_b}/steps",
                                        headers=viewer_a).status_code, 404)
            self.assertEqual(client.post("/api/v1/tasks", headers=viewer_a,
                                         json=payload).status_code, 403)
            self.assertEqual(client.post(f"/api/v1/tasks/{task_b}/steps", headers=operator_a,
                                         json={"instruction": "Cross tenant"}).status_code, 404)
            node_payload = {"node_id": "alpha-node", "provider_type": "local",
                "privacy_tier": "local_only", "billing_mode": "free",
                "endpoint_url": "http://127.0.0.1:8090/v1", "model_id": "model"}
            self.assertEqual(client.post("/api/v1/compute/nodes", headers=operator_a,
                                         json=node_payload).status_code, 403)
            self.assertEqual(client.post("/api/v1/compute/nodes", headers=admin_a,
                                         json=node_payload).status_code, 201)
            self.assertEqual([row["node_id"] for row in client.get(
                "/api/v1/compute/nodes", headers=viewer_a).json()], ["alpha-node"])
            self.assertEqual(client.get("/api/v1/compute/nodes",
                                        headers=operator_b).json(), [])
            tool_payload = {"tool_id": "alpha-tool", "name": "alpha tool",
                "domain_path": "test/alpha", "schema": {"type": "object"},
                "effect_tier": 0}
            self.assertEqual(client.post("/api/v1/tools", headers=operator_a,
                                         json=tool_payload).status_code, 403)
            self.assertEqual(client.post("/api/v1/tools", headers=admin_a,
                                         json=tool_payload).status_code, 201)
            self.assertEqual([row["tool_id"] for row in client.get(
                "/api/v1/tools", headers=viewer_a).json()], ["alpha-tool"])
            self.assertEqual(client.get("/api/v1/tools", headers=operator_b).json(), [])
            settings_path = f"/api/v1/orgs/{org_a}/settings"
            self.assertFalse(client.get(settings_path, headers=admin_a).json()[
                "allow_unquoted_runpod"])
            self.assertEqual(client.put(settings_path, headers=operator_a,
                                        json={"allow_unquoted_runpod": True}).status_code, 403)
            self.assertEqual(client.put(settings_path, headers=admin_a,
                                        json={"allow_unquoted_runpod": True}).status_code, 200)
            self.assertTrue(client.get(settings_path, headers=admin_a).json()[
                "allow_unquoted_runpod"])
            self.assertEqual(client.get(settings_path, headers=operator_b).status_code, 403)
            self.assertEqual(client.post(f"/api/v1/orgs/{org_b}/users", headers=admin_a,
                                         json={"display_name": "Intruder", "role": "admin"}).status_code,
                             404)
            self.assertEqual(client.get(f"/api/v1/tasks/{task_a}",
                                        headers=viewer_a).json()["org_id"], org_a)
            self.assertEqual(client.get(f"/api/v1/tasks/{task_b}",
                                        headers=operator_b).json()["org_id"], org_b)
            new_user = client.post(f"/api/v1/orgs/{org_a}/users", headers=admin_a,
                json={"display_name": "Temporary", "role": "viewer"}).json()
            temporary = {"Authorization": "Bearer " + new_user["token"]}
            self.assertEqual(client.get("/api/v1/me", headers=temporary).status_code, 200)
            self.assertEqual(client.delete(
                f"/api/v1/orgs/{org_a}/users/{new_user['user_id']}",
                headers=admin_a).status_code, 200)
            self.assertEqual(client.get("/api/v1/me", headers=temporary).status_code, 403)
            store.dispose()

    def test_registry_shares_gate_placement_and_grant_redemption(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "connectd.db")
            store.initialize()
            with store.connect() as db:
                db.execute("INSERT INTO organizations(org_id,name,created_at) VALUES (?,?,?)",
                           ("org-a", "Alpha", utcnow().isoformat()))
                db.execute("""INSERT INTO tasks(task_id,org_id,title,privacy_class,memory_scope,
                    created_at) VALUES (?,?,?,?,?,?)""",
                    ("task-a", "org-a", "Work", "public", "repo:test", utcnow().isoformat()))
                db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,
                    healthy,billing_mode,endpoint_url,model_id) VALUES (?,?,?,?,?,?,?)""",
                    ("gpu-a", "local", "local_only", True, "free",
                     "http://localhost:8090/v1", "model"))
                db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,
                    effect_tier,active) VALUES (?,?,?,?,?,?)""",
                    ("echo", "echo", "test/echo", "{}", 0, True))
            with self.assertRaises(PlacementDenied):
                place(store, PrivacyClass.PUBLIC, org_id="org-a")
            governance = Governance(store, Ed25519PrivateKey.generate(),
                                    ConnectdConfig().profile("dev_fast"))
            with self.assertRaises(AuthorizationError):
                governance.issue("task-a", "worker-a", "echo", {})
            with store.connect() as db:
                db.execute("""INSERT INTO registry_shares(owner_org_id,target_org_id,
                    resource_kind,resource_id,created_by,created_at) VALUES (?,?,?,?,?,?)""",
                    ("default", "org-a", "node", "gpu-a", "bootstrap",
                     utcnow().isoformat()))
                db.execute("""INSERT INTO registry_shares(owner_org_id,target_org_id,
                    resource_kind,resource_id,created_by,created_at) VALUES (?,?,?,?,?,?)""",
                    ("default", "org-a", "tool", "echo", "bootstrap",
                     utcnow().isoformat()))
            self.assertEqual(place(store, PrivacyClass.PUBLIC, org_id="org-a"), "gpu-a")
            grant = governance.issue("task-a", "worker-a", "echo", {})
            with store.connect() as db:
                db.execute("""DELETE FROM registry_shares WHERE owner_org_id='default'
                    AND target_org_id='org-a' AND resource_kind='tool'""")
            with self.assertRaisesRegex(AuthorizationError, "revoked"):
                governance.redeem(grant, "task-a", "worker-a", "echo", {})
            with store.connect() as db:
                db.execute("""DELETE FROM registry_shares WHERE owner_org_id='default'
                    AND target_org_id='org-a' AND resource_kind='node'""")
                db.execute("""INSERT INTO registry_shares(owner_org_id,target_org_id,
                    resource_kind,resource_id,created_by,created_at) VALUES (?,?,?,?,?,?)""",
                    ("default", "org-a", "node", "*", "bootstrap",
                     utcnow().isoformat()))
            self.assertEqual(place(store, PrivacyClass.PUBLIC, org_id="org-a"), "gpu-a")
            store.dispose()

    def test_worker_context_reads_only_its_organization(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "connectd.db")
            app = create_app(ConnectdConfig(), store, Ed25519PrivateKey.generate(),
                             "b" * 40)
            client = TestClient(app)
            bootstrap = {"Authorization": "Bearer " + "b" * 40}
            org_a = client.post("/api/v1/orgs", headers=bootstrap,
                                json={"name": "Alpha"}).json()["org_id"]
            org_b = client.post("/api/v1/orgs", headers=bootstrap,
                                json={"name": "Beta"}).json()["org_id"]
            task_a = client.post("/api/v1/tasks", headers=bootstrap,
                json={"title": "A", "privacy_class": "repo_sensitive",
                      "memory_scope": "repo:shared"}).json()["task_id"]
            with store.connect() as db:
                db.execute("UPDATE tasks SET org_id=? WHERE task_id=?", (org_a, task_a))
            task_b = client.post("/api/v1/tasks", headers=bootstrap,
                json={"title": "B", "privacy_class": "repo_sensitive",
                      "memory_scope": "repo:shared"}).json()["task_id"]
            with store.connect() as db:
                db.execute("UPDATE tasks SET org_id=? WHERE task_id=?", (org_b, task_b))
            memory = MemoryLedger(store)
            claim = memory.capture("repo:shared", "Only Alpha knows", "tester", org_id=org_a)
            memory.promote(claim, "bootstrap")
            auth = AuthService(store, "b" * 40)
            token_a = auth.issue_worker(task_a, "a")
            token_b = auth.issue_worker(task_b, "b")
            self.assertEqual(client.get(f"/api/v1/tasks/{task_a}/context-pack",
                headers={"Authorization": "Bearer " + token_a}).json()["memory"],
                ["Only Alpha knows"])
            self.assertEqual(client.get(f"/api/v1/tasks/{task_b}/context-pack",
                headers={"Authorization": "Bearer " + token_b}).json()["memory"], [])
            store.dispose()


if __name__ == "__main__":
    unittest.main()
