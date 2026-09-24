"""RunPod transport remains separate from inference and resolves keys at call time."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from connectd.provisioning import (
    LocalSecretResolver, PodRequest, ProvisioningError, RunPodAdapter,
)


class ProvisioningTests(unittest.TestCase):
    def test_runpod_reference_transport(self):
        calls = []
        def respond(request):
            calls.append((request.method, str(request.url),
                          request.headers.get("Authorization")))
            if request.method == "POST":
                return httpx.Response(201, json={"id": "pod-123", "costPerHr": "0.74",
                                                  "desiredStatus": "RUNNING"})
            if request.method == "GET":
                return httpx.Response(200, json={"id": "pod-123", "costPerHr": "0.74",
                                                  "desiredStatus": "RUNNING"})
            return httpx.Response(204)
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                adapter = RunPodAdapter(LocalSecretResolver(), client=client)
                created = adapter.create(PodRequest(name="model node",
                    gpu_type_id="operator-selected-gpu",
                    image_name="operator-selected-image"))
                self.assertEqual(created.pod_id, "pod-123")
                self.assertEqual(str(created.hourly_usd), "0.74")
                self.assertEqual(adapter.get("pod-123"), created)
                adapter.delete("pod-123")
                with self.assertRaises(ProvisioningError):
                    adapter.delete("../another-pod")
        self.assertEqual([item[0] for item in calls], ["POST", "GET", "DELETE"])
        self.assertEqual(calls[0][1], "https://rest.runpod.io/v1/pods")
        self.assertTrue(all(item[2] == "Bearer test-secret" for item in calls))

    def test_local_env_file_secret_and_missing_key(self):
        with tempfile.TemporaryDirectory() as temp:
            secret = Path(temp) / "connectd.env"
            secret.write_text("RUNPOD_API_KEY=from-file\n", encoding="utf-8")
            if os.name != "nt":
                secret.chmod(0o600)
            with patch.dict(os.environ, {"RUNPOD_API_KEY": ""}):
                self.assertEqual(LocalSecretResolver(secret).resolve("RUNPOD_API_KEY"),
                                 "from-file")
                with self.assertRaises(ProvisioningError):
                    LocalSecretResolver().resolve("RUNPOD_API_KEY")

