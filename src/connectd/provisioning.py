"""Provider-neutral Pod lifecycle contract and RunPod REST reference adapter."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProvisioningError(RuntimeError):
    pass


class PodRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    gpu_type_id: str = Field(min_length=1)
    image_name: str = Field(min_length=1)
    gpu_count: int = Field(default=1, ge=1, le=16)
    container_disk_gb: int = Field(default=50, ge=20)
    volume_gb: int = Field(default=20, ge=0)
    ports: list[str] = Field(default_factory=list)
    cloud_type: str = "SECURE"

    @model_validator(mode="after")
    def valid_options(self):
        if self.cloud_type not in {"SECURE", "COMMUNITY"}:
            raise ValueError("invalid RunPod cloud type")
        if len(self.ports) > 16 or any(not re.fullmatch(r"[1-9][0-9]{0,4}/(http|tcp)", item)
                                      for item in self.ports):
            raise ValueError("invalid Pod ports")
        return self


@dataclass(frozen=True)
class PodInfo:
    pod_id: str
    hourly_usd: Decimal
    status: str


@dataclass(frozen=True)
class PodBilling:
    pod_id: str
    total_usd: Decimal
    gpu_usd: Decimal
    disk_usd: Decimal
    cpu_usd: Decimal


@dataclass(frozen=True)
class PodQuote:
    gpu_hourly_usd: Decimal
    availability: str
    source: str = "runpod_gpu_catalog_list_price"


class ProvisioningAdapter(Protocol):
    def quote(self, request: PodRequest) -> PodQuote: ...
    def create(self, request: PodRequest) -> PodInfo: ...
    def get(self, pod_id: str) -> PodInfo: ...
    def delete(self, pod_id: str) -> None: ...
    def billing(self, pod_id: str, started_at: datetime, ended_at: datetime) -> PodBilling: ...


class LocalSecretResolver:
    """Resolve an API key at call time; never persist it in the database."""

    def __init__(self, env_file: Path | None = None):
        self.env_file = env_file

    def resolve(self, name: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ProvisioningError("invalid secret name")
        value = os.environ.get(name)
        if value:
            return value
        if self.env_file is None:
            raise ProvisioningError(f"{name} is not configured")
        path = self.env_file
        try:
            if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise ProvisioningError("secret file must be private to its owner")
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ProvisioningError("secret file is unavailable") from exc
        matches = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, separator, secret = stripped.partition("=")
            if not separator:
                raise ProvisioningError("secret file contains an invalid assignment")
            if key.strip() == name:
                matches.append(secret.strip().strip('"').strip("'"))
        if len(matches) != 1 or not matches[0]:
            raise ProvisioningError(f"{name} is missing or ambiguous")
        return matches[0]


class RunPodAdapter:
    """RunPod's documented REST v1 Pod create, read, and delete operations."""

    base_url = "https://rest.runpod.io/v1"

    def __init__(self, resolver: LocalSecretResolver, *, api_key_env: str = "RUNPOD_API_KEY",
                 client: httpx.Client | None = None):
        self.resolver = resolver
        self.api_key_env = api_key_env
        self.client = client or httpx.Client(timeout=30)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.resolver.resolve(self.api_key_env)}

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = self.client.request(method, self.base_url + path,
                                           headers=self._headers(), **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPError as exc:
            raise ProvisioningError("RunPod lifecycle request failed") from exc

    @staticmethod
    def _pod_id(value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ProvisioningError("invalid Pod ID")
        return value

    @classmethod
    def _info(cls, value: dict) -> PodInfo:
        if not isinstance(value, dict):
            raise ProvisioningError("RunPod returned invalid Pod data")
        try:
            pod_id = cls._pod_id(value["id"])
            rate = Decimal(str(value["costPerHr"]))
            if not rate.is_finite() or rate < 0:
                raise ValueError("invalid hourly cost")
            return PodInfo(pod_id, rate, str(value.get("desiredStatus") or "unknown"))
        except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
            raise ProvisioningError("RunPod returned invalid Pod pricing or identity") from exc

    def quote(self, request: PodRequest) -> PodQuote:
        """Read RunPod's GPU list price; storage and final Pod billing are separate."""
        url = "https://api.runpod.io/v2/catalog/gpus/" + quote(request.gpu_type_id, safe="")
        try:
            response = self.client.get(url, headers=self._headers(),
                params={"include": "AVAILABILITY", "product": "POD",
                        "count": request.gpu_count, "cloud": request.cloud_type})
            response.raise_for_status()
            value = response.json()
            cloud = request.cloud_type.lower()
            if (not isinstance(value, dict) or value.get("id") != request.gpu_type_id or
                    value.get("availability") not in {"LOW", "MEDIUM", "HIGH"}):
                raise ValueError("GPU type or availability is invalid")
            max_count = value["maxCount"][cloud]
            unit_rate = Decimal(str(value["price"][cloud]))
            if (type(max_count) is not int or max_count < request.gpu_count or
                    not unit_rate.is_finite() or unit_rate <= 0):
                raise ValueError("GPU price or count is invalid")
            return PodQuote(unit_rate * request.gpu_count, value["availability"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError, InvalidOperation) as exc:
            raise ProvisioningError("RunPod GPU list price is unavailable") from exc

    def create(self, request: PodRequest) -> PodInfo:
        payload = {
            "name": request.name,
            "gpuTypeIds": [request.gpu_type_id],
            "gpuCount": request.gpu_count,
            "imageName": request.image_name,
            "containerDiskInGb": request.container_disk_gb,
            "volumeInGb": request.volume_gb,
            "ports": request.ports,
            "cloudType": request.cloud_type,
            "computeType": "GPU",
        }
        response = self._request("POST", "/pods", json=payload)
        try:
            return self._info(response.json())
        except ValueError as exc:
            raise ProvisioningError("RunPod returned invalid Pod JSON") from exc

    def get(self, pod_id: str) -> PodInfo:
        response = self._request("GET", "/pods/" + self._pod_id(pod_id))
        try:
            return self._info(response.json())
        except ValueError as exc:
            raise ProvisioningError("RunPod returned invalid Pod JSON") from exc

    def delete(self, pod_id: str) -> None:
        self._request("DELETE", "/pods/" + self._pod_id(pod_id))

    def billing(self, pod_id: str, started_at: datetime, ended_at: datetime) -> PodBilling:
        """Read provider charges for one Pod after its bounded lease ends.

        RunPod rounds query times to hour buckets. A Pod ID is unique to the
        lease, so bucket widening cannot include charges for another Pod.
        An empty or malformed report is not proof of a zero-dollar charge.
        """
        pod_id = self._pod_id(pod_id)
        if (started_at.tzinfo is None or ended_at.tzinfo is None or
                ended_at <= started_at):
            raise ProvisioningError("billing requires an ordered timezone-aware lease")
        start = started_at.astimezone(timezone.utc).replace(minute=0, second=0,
                                                            microsecond=0)
        end = ended_at.astimezone(timezone.utc)
        if end.minute or end.second or end.microsecond:
            end = end.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        params = {"podId": pod_id, "bucketSize": "hour",
                  "startTime": start.isoformat().replace("+00:00", "Z"),
                  "endTime": end.isoformat().replace("+00:00", "Z")}
        try:
            response = self.client.get("https://api.runpod.io/v2/billing/pods",
                                       headers=self._headers(), params=params)
            response.raise_for_status()
            body = response.json()
            records = body["records"]
            query = body["metadata"]["query"]
            totals = body["metadata"]["totals"]
            if (not isinstance(records, list) or not records or
                    query["podId"] != pod_id or query["bucketSize"] != "hour" or
                    query["startTime"] != params["startTime"] or
                    query["endTime"] != params["endTime"] or
                    body["metadata"]["recordCount"] != len(records)):
                raise ValueError("incomplete Pod billing report")
            amounts = {}
            for key in ("totalAmount", "gpuAmount", "diskAmount", "cpuAmount"):
                values = [Decimal(str(row[key])) for row in records]
                total = Decimal(str(totals[key]))
                if (any(not value.is_finite() or value < 0 for value in values) or
                        not total.is_finite() or total < 0 or sum(values) != total):
                    raise ValueError("invalid Pod billing amounts")
                amounts[key] = total
            if any(row["podId"] != pod_id for row in records):
                raise ValueError("mixed Pod billing identities")
            if (amounts["gpuAmount"] + amounts["diskAmount"] +
                    amounts["cpuAmount"] > amounts["totalAmount"]):
                raise ValueError("billing components exceed total")
            return PodBilling(pod_id, amounts["totalAmount"], amounts["gpuAmount"],
                              amounts["diskAmount"], amounts["cpuAmount"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError, InvalidOperation) as exc:
            raise ProvisioningError("RunPod Pod billing is unavailable or invalid") from exc



class BoundedProvisioner:
    """Require a catalog quote before create and verify the reported Pod rate."""

    def __init__(self, adapter: ProvisioningAdapter):
        self.adapter = adapter

    def create(self, request: PodRequest, max_hourly_usd: Decimal,
               *, allow_unquoted: bool = False) -> PodInfo:
        if (not isinstance(max_hourly_usd, Decimal) or
                not max_hourly_usd.is_finite() or max_hourly_usd <= 0):
            raise ProvisioningError("a positive operator hourly USD cap is required")
        try:
            gpu_quote = self.adapter.quote(request)
        except ProvisioningError:
            if not allow_unquoted:
                raise
            gpu_quote = None
        if gpu_quote is not None and gpu_quote.gpu_hourly_usd > max_hourly_usd:
            raise ProvisioningError("GPU catalog quote exceeds the operator hourly cap")
        pod = self.adapter.create(request)
        if pod.hourly_usd > max_hourly_usd:
            try:
                self.adapter.delete(pod.pod_id)
            except ProvisioningError as exc:
                raise ProvisioningError(
                    f"Pod {pod.pod_id} exceeds the hourly cap and automatic deletion failed"
                ) from exc
            raise ProvisioningError("created Pod rate exceeds the operator hourly cap")
        return pod
