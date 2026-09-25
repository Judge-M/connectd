"""RunPod transport remains separate from inference and resolves keys at call time."""

import json
import os
import tempfile
from decimal import Decimal
from datetime import datetime, timezone
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

from connectd.provisioning import (
    BoundedProvisioner, LocalSecretResolver, PodInfo, PodQuote, PodRequest,
    ProvisioningError, RunPodAdapter,
)


class ProvisioningTests(unittest.TestCase):
    def test_runpod_reference_transport(self):
        calls = []
        def respond(request):
            calls.append((request.method, str(request.url),
                          request.headers.get("Authorization")))
            if request.method == "POST":
                return httpx.Response(201, json={"id": "pod-123", "cost": "0.74",
                                                  "status": "RUNNING"})
            if request.method == "GET":
                return httpx.Response(200, json={"id": "pod-123", "cost": "0.74",
                                                  "status": "RUNNING"})
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
        self.assertEqual(calls[0][1], "https://api.runpod.io/v2/pods")
        self.assertTrue(all(item[2] == "Bearer test-secret" for item in calls))

    def test_v2_create_shape_and_paginated_name_recovery(self):
        calls = []
        def respond(request):
            calls.append(request)
            if request.method == "POST":
                return httpx.Response(201, json={"id": "pod-a", "cost": 0.7,
                                                   "status": "RUNNING"})
            cursor = request.url.params.get("cursor")
            if not cursor:
                return httpx.Response(200, json={"pods": [], "pagination": {
                    "hasNextPage": True, "nextCursor": "page-two"}})
            return httpx.Response(200, json={"pods": [
                {"id": "pod-a", "name": "connectd-lease", "cost": 0.7,
                 "status": "RUNNING"}], "pagination": {
                    "hasNextPage": False, "nextCursor": None}})
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                adapter = RunPodAdapter(LocalSecretResolver(), client=client)
                request = PodRequest(name="connectd-lease", gpu_type_id="gpu",
                                     image_name="image", volume_gb=20)
                adapter.create(request)
                self.assertEqual(adapter.find_by_name("connectd-lease")[0].pod_id,
                                 "pod-a")
        body = json.loads(calls[0].content)
        self.assertEqual(body["gpu"], {"id": "gpu", "count": 1})
        self.assertEqual(body["mounts"], {"persistent": {"size": 20,
                                                          "path": "/workspace"}})
        self.assertEqual(calls[2].url.params["cursor"], "page-two")

    def test_runpod_gpu_catalog_quote_is_read_only(self):
        calls = []
        def respond(request):
            calls.append(request)
            return httpx.Response(200, json={"id": "RTX 4090",
                "availability": "HIGH", "maxCount": {"secure": 8},
                "price": {"secure": "0.44"}})
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                adapter = RunPodAdapter(LocalSecretResolver(), client=client)
                result = adapter.quote(PodRequest(name="quoted", gpu_type_id="RTX 4090",
                    image_name="operator/image", gpu_count=2))
        self.assertEqual(str(result.gpu_hourly_usd), "0.88")
        self.assertEqual(result.source, "runpod_gpu_catalog_list_price")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].method, "GET")
        self.assertEqual(calls[0].url.path, "/v2/catalog/gpus/RTX 4090")
        self.assertEqual(calls[0].url.params["count"], "2")
        self.assertEqual(calls[0].url.params["product"], "POD")

    def test_runpod_quote_fails_closed_without_available_pricing(self):
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            with httpx.Client(transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"id": "gpu",
                    "availability": "NONE", "maxCount": {"secure": 8},
                    "price": {"secure": "0.44"}}))) as client:
                with self.assertRaises(ProvisioningError):
                    RunPodAdapter(LocalSecretResolver(), client=client).quote(
                        PodRequest(name="quoted", gpu_type_id="gpu",
                                   image_name="operator/image"))

    def test_bounded_provisioner_requires_quote_and_deletes_over_cap(self):
        request = PodRequest(name="model", gpu_type_id="gpu", image_name="image")
        adapter = Mock()
        adapter.quote.return_value = PodQuote(Decimal("0.50"), "HIGH")
        adapter.create.return_value = PodInfo("pod-123", Decimal("0.80"), "RUNNING")
        with self.assertRaisesRegex(ProvisioningError, "created Pod rate"):
            BoundedProvisioner(adapter).create(request, Decimal("0.75"))
        adapter.delete.assert_called_once_with("pod-123")
        adapter.create.reset_mock()
        adapter.delete.reset_mock()
        adapter.quote.side_effect = ProvisioningError("quote unavailable")
        with self.assertRaisesRegex(ProvisioningError, "quote unavailable"):
            BoundedProvisioner(adapter).create(request, Decimal("0.75"))
        adapter.create.assert_not_called()
        adapter.create.return_value = PodInfo("pod-456", Decimal("0.60"), "RUNNING")
        self.assertEqual(BoundedProvisioner(adapter).create(
            request, Decimal("0.75"), allow_unquoted=True).pod_id, "pod-456")
        adapter.create.assert_called_once_with(request)
        adapter.delete.assert_not_called()

    def test_bounded_provisioner_rejects_high_quote_before_create(self):
        request = PodRequest(name="model", gpu_type_id="gpu", image_name="image")
        adapter = Mock()
        adapter.quote.return_value = PodQuote(Decimal("1.00"), "HIGH")
        with self.assertRaisesRegex(ProvisioningError, "catalog quote exceeds"):
            BoundedProvisioner(adapter).create(request, Decimal("0.75"))
        adapter.create.assert_not_called()

    def test_bounded_provisioner_deletes_pod_without_positive_post_create_rate(self):
        request = PodRequest(name="model", gpu_type_id="gpu", image_name="image")
        adapter = Mock()
        adapter.quote.return_value = PodQuote(Decimal("0.50"), "HIGH")
        adapter.create.return_value = PodInfo("pod-unpriced", Decimal("0"), "CREATED")
        with self.assertRaisesRegex(ProvisioningError, "rate is missing"):
            BoundedProvisioner(adapter).create(request, Decimal("0.75"))
        adapter.delete.assert_called_once_with("pod-unpriced")

    def test_runpod_billing_validates_pod_specific_provider_totals(self):
        calls = []
        def respond(request):
            calls.append(request)
            return httpx.Response(200, json={"records": [{"podId": "pod-123",
                "totalAmount": "0.12", "gpuAmount": "0.10", "diskAmount": "0.02",
                "cpuAmount": "0"}], "metadata": {"query": {"podId": "pod-123",
                "bucketSize": "hour", "startTime": "2026-09-24T10:00:00Z",
                "endTime": "2026-09-24T12:00:00Z"}, "recordCount": 1,
                "totals": {"totalAmount": "0.12", "gpuAmount": "0.10",
                           "diskAmount": "0.02", "cpuAmount": "0"}}})
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                adapter = RunPodAdapter(LocalSecretResolver(), client=client)
                bill = adapter.billing("pod-123",
                    datetime(2026, 9, 24, 10, 7, tzinfo=timezone.utc),
                    datetime(2026, 9, 24, 11, 2, tzinfo=timezone.utc))
                self.assertEqual(bill.total_usd, Decimal("0.12"))
                self.assertEqual(bill.disk_usd, Decimal("0.02"))
        self.assertEqual(calls[0].url.params["podId"], "pod-123")
        self.assertEqual(calls[0].url.params["startTime"], "2026-09-24T10:00:00Z")
        self.assertEqual(calls[0].url.params["endTime"], "2026-09-24T12:00:00Z")

    def test_runpod_billing_rejects_missing_or_cross_pod_records(self):
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "test-secret"}):
            for records in ([], [{"podId": "other", "totalAmount": 0,
                                  "gpuAmount": 0, "diskAmount": 0, "cpuAmount": 0}]):
                body = {"records": records, "metadata": {"query": {"podId": "pod-123",
                    "bucketSize": "hour", "startTime": "2026-09-24T10:00:00Z",
                    "endTime": "2026-09-24T12:00:00Z"}, "recordCount": len(records),
                    "totals": {"totalAmount": 0, "gpuAmount": 0,
                               "diskAmount": 0, "cpuAmount": 0}}}
                with httpx.Client(transport=httpx.MockTransport(
                        lambda _request: httpx.Response(200, json=body))) as client:
                    with self.assertRaises(ProvisioningError):
                        RunPodAdapter(LocalSecretResolver(), client=client).billing(
                            "pod-123", datetime(2026, 9, 24, 10, tzinfo=timezone.utc),
                            datetime(2026, 9, 24, 11, 2, tzinfo=timezone.utc))

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

