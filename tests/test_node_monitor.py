"""Registered compute nodes must pass authenticated capacity checks."""

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import httpx

from connectd.node_monitor import NodeMonitor
from connectd.config import ConnectdConfig, ComputeSettings, NodeManagerSettings
from connectd.api import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from connectd.store import Store


class NodeMonitorTests(unittest.TestCase):
    def test_health_report_controls_placement_eligibility(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "nodes.db")
            store.initialize()
            with store.connect() as db:
                db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                    billing_mode,endpoint_url,model_id,health_url) VALUES (?,?,?,?,?,?,?,?)""",
                    ("gpu-1", "remote-manager", "local_only", False, "free",
                     "http://127.0.0.1:8090/v1", "chosen-model",
                     "http://127.0.0.1:8090/health"))
            slots = [2]
            calls = []

            def respond(request):
                calls.append(str(request.url))
                return httpx.Response(200, json={"status": "healthy",
                    "available_slots": slots[0], "loaded_models": ["chosen-model"]})

            monitor = NodeMonitor(store, client_factory=lambda _tls: httpx.Client(
                transport=httpx.MockTransport(respond)))
            self.assertEqual(monitor.poll_once(), {"gpu-1": True})
            with store.connect() as db:
                row = db.execute("SELECT healthy,capacity_json,last_health_at FROM compute_nodes").fetchone()
            self.assertTrue(row["healthy"])
            self.assertIn('"available_slots": 2', row["capacity_json"])
            self.assertTrue(row["last_health_at"])
            slots[0] = 0
            self.assertFalse(monitor.probe("gpu-1"))
            with store.connect() as db:
                self.assertFalse(db.execute("SELECT healthy FROM compute_nodes").fetchone()[0])
            self.assertEqual(calls, ["http://127.0.0.1:8090/health"] * 2)
            store.dispose()

    def test_manager_only_admits_approved_registered_nodes(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "nodes.db")
            store.initialize()
            with store.connect() as db:
                for node_id in ("approved", "absent"):
                    db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,
                        healthy,billing_mode,endpoint_url,model_id,manager_id)
                        VALUES (?,?,?,?,?,?,?,?)""",
                        (node_id, "remote-manager", "private_rented", False, "free",
                         "https://gpu.example/v1", "chosen-model", "manager-1"))
            manager = NodeManagerSettings(manager_id="manager-1",
                endpoint_url="https://manager.example/v1/nodes",
                ca_cert_path=Path(scratch) / "ca.pem",
                client_cert_path=Path(scratch) / "client.pem",
                client_key_path=Path(scratch) / "key.pem",
                allowed_node_ids=frozenset({"approved", "absent"}))
            def respond(request):
                self.assertEqual(str(request.url), manager.endpoint_url)
                return httpx.Response(200, json={"nodes": [
                    {"node_id": "approved", "status": "healthy",
                     "available_slots": 2, "loaded_models": ["chosen-model"]},
                    {"node_id": "unknown", "status": "healthy",
                     "available_slots": 9, "loaded_models": ["chosen-model"]}]})
            class FakeContext:
                check_hostname = False
                def load_cert_chain(self, cert, key):
                    self.asserted = (cert, key)
            context = FakeContext()
            monitor = NodeMonitor(store, client_factory=lambda tls: httpx.Client(
                transport=httpx.MockTransport(respond)), managers=[manager])
            with patch("connectd.node_monitor.ssl.create_default_context",
                       return_value=context):
                self.assertEqual(monitor.poll_once(), {"approved": True, "absent": False})
            self.assertTrue(context.check_hostname)
            with store.connect() as db:
                rows = {row["node_id"]: row for row in db.execute(
                    "SELECT node_id,healthy,capacity_json FROM compute_nodes")}
            self.assertTrue(rows["approved"]["healthy"])
            self.assertFalse(rows["absent"]["healthy"])
            self.assertIsNone(rows["absent"]["capacity_json"])
            store.dispose()

    def test_registration_requires_manager_allowlist(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "nodes.db")
            manager = NodeManagerSettings(manager_id="manager-1",
                endpoint_url="https://manager.example/v1/nodes",
                ca_cert_path=Path(scratch) / "ca.pem",
                client_cert_path=Path(scratch) / "client.pem",
                client_key_path=Path(scratch) / "key.pem",
                allowed_node_ids=frozenset({"approved"}))
            app = create_app(ConnectdConfig(compute=ComputeSettings(node_managers=[manager])),
                             store, Ed25519PrivateKey.generate(), "o" * 40)
            client = TestClient(app)
            record = {"node_id": "approved", "provider_type": "node-manager",
                "privacy_tier": "private_rented", "billing_mode": "free",
                "endpoint_url": "https://gpu.example/v1", "model_id": "chosen-model",
                "allowed_privacy_classes": ["public"], "ca_cert_path": "ca.pem",
                "client_cert_path": "client.pem", "client_key_path": "key.pem",
                "manager_id": "manager-1"}
            headers = {"Authorization": "Bearer " + "o" * 40}
            self.assertEqual(client.post("/api/v1/compute/nodes",
                                        json=dict(record, node_id="unapproved"),
                                        headers=headers).status_code, 422)
            self.assertEqual(client.post("/api/v1/compute/nodes", json=record,
                                        headers=headers).status_code, 201)
            with store.connect() as db:
                row = db.execute("SELECT manager_id,healthy FROM compute_nodes").fetchone()
            self.assertEqual(row["manager_id"], "manager-1")
            self.assertFalse(row["healthy"])
            store.dispose()

    def test_remote_node_without_mtls_is_not_probed(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "nodes.db")
            store.initialize()
            with store.connect() as db:
                db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                    billing_mode,endpoint_url,model_id,health_url) VALUES (?,?,?,?,?,?,?,?)""",
                    ("remote", "remote-manager", "private_rented", False, "free",
                     "https://gpu.example/v1", "chosen-model", "https://gpu.example/health"))
            monitor = NodeMonitor(store, client_factory=lambda _tls: self.fail("network call made"))
            self.assertFalse(monitor.probe("remote"))
            store.dispose()
