"""Registered compute nodes must pass authenticated capacity checks."""

import tempfile
import unittest
from pathlib import Path

import httpx

from connectd.node_monitor import NodeMonitor
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
