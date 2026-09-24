"""Validated execution profiles. A profile never overrides privacy restrictions."""

from enum import Enum
import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator


class GrantMode(str, Enum):
    AUTO_GRANT = "auto_grant"
    RISK_TIERED = "risk_tiered"
    STRICT_ED25519 = "strict_ed25519"


class MemoryAuthority(str, Enum):
    SESSION_AUTO = "session_auto"
    HYBRID = "hybrid"
    HUMAN_GATED = "human_gated"


class WorkerRuntime(str, Enum):
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    PODMAN = "podman"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"


class DaemonSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(default=8790, ge=1, le=65535)
    database_url: str = "sqlite:///connectd.db"
    signing_key_path: Path | None = None
    cedar_policy_path: Path | None = None
    operator_token_env: str = "CONNECTD_OPERATOR_TOKEN"


class RouterSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = "laya"
    base_url: str = "http://127.0.0.1:8000"
    min_confidence: float = Field(default=0.90, ge=0, le=1)
    api_key_env: str = "TYPESAFE_API_KEY"
    tree_registry_path: Path = Path("config/oag_tree_registry.json")


class WorkerModelSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str | None = None
    model_id: str | None = None
    uses_proxy: bool = False


class ModelAPISettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine_type: str = "openai_compatible"
    container_image: str | None = None
    port: int = Field(default=8090, ge=1, le=65535)
    allowed_local_hosts: set[str] = Field(default_factory=lambda: {"localhost", "127.0.0.1", "model-engine"})


class TaskDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_privacy_class: str = "repo_sensitive"

    @model_validator(mode="after")
    def valid_privacy(self):
        if self.default_privacy_class not in {"public", "low_sensitive", "repo_sensitive", "secret_sensitive"}:
            raise ValueError("invalid default privacy class")
        return self


class SpendSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reset_timezone: str = "UTC"

    @model_validator(mode="after")
    def valid_timezone(self):
        try:
            ZoneInfo(self.reset_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("unknown spend reset timezone") from exc
        return self


class NodeManagerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manager_id: str = Field(min_length=1)
    endpoint_url: str
    ca_cert_path: Path
    client_cert_path: Path
    client_key_path: Path
    allowed_node_ids: frozenset[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_transport(self):
        from urllib.parse import urlsplit
        parsed = urlsplit(self.endpoint_url)
        if (parsed.scheme != "https" or not parsed.hostname or not parsed.path or
                parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("node manager requires a plain HTTPS endpoint URL")
        return self


class ComputeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    health_interval_seconds: int = Field(default=30, ge=1, le=3600)
    node_managers: list[NodeManagerSettings] = Field(default_factory=list)


class ProvisioningSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runpod_secret_file: Path | None = None


class LibrarianSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["fail_closed", "http_json"] = "fail_closed"
    endpoint_url: str | None = None
    token_env: str | None = None
    allow_private_http: bool = False
    allow_remote_https: bool = False
    local_hostnames: frozenset[str] = Field(default_factory=lambda: frozenset({
        "localhost", "127.0.0.1", "::1", "connectd-router", "model-api"}))
    allowed_privacy_classes: frozenset[str] = Field(default_factory=lambda: frozenset({"public"}))
    confidence_threshold: float = Field(default=0.90, ge=0, le=1)
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    poll_interval_seconds: int = Field(default=5, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_evaluator(self):
        known = {"public", "low_sensitive", "repo_sensitive", "secret_sensitive"}
        if not self.allowed_privacy_classes <= known:
            raise ValueError("invalid librarian privacy class")
        if self.type == "http_json":
            parsed = urlsplit(self.endpoint_url or "")
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                    parsed.username or parsed.password or parsed.query or parsed.fragment):
                raise ValueError("librarian requires a plain HTTP(S) endpoint")
            if parsed.scheme == "http":
                if parsed.hostname not in self.local_hostnames:
                    raise ValueError("remote librarian endpoints require HTTPS")
                if (parsed.hostname not in {"127.0.0.1", "localhost", "::1"} and
                        not self.allow_private_http):
                    raise ValueError("internal container HTTP requires explicit opt-in")
        elif self.endpoint_url is not None:
            raise ValueError("fail-closed librarian must not have an endpoint")
        return self

    def remote_endpoint(self) -> bool:
        return (self.type == "http_json" and
                urlsplit(self.endpoint_url or "").hostname not in self.local_hostnames)


class MemorySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evaluator: LibrarianSettings = Field(default_factory=LibrarianSettings)


class ExecutionProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_mode: GrantMode
    memory_authority: MemoryAuthority
    worktree_sandbox: bool = True
    worker_runtime: WorkerRuntime = WorkerRuntime.SUBPROCESS


def default_profiles() -> dict[str, ExecutionProfile]:
    return {
        "dev_fast": ExecutionProfile(grant_mode=GrantMode.AUTO_GRANT, memory_authority=MemoryAuthority.SESSION_AUTO),
        "balanced": ExecutionProfile(grant_mode=GrantMode.RISK_TIERED, memory_authority=MemoryAuthority.HYBRID),
        "prod_secure": ExecutionProfile(grant_mode=GrantMode.STRICT_ED25519, memory_authority=MemoryAuthority.HUMAN_GATED, worker_runtime=WorkerRuntime.DOCKER),
    }


class ConnectdConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    daemon: DaemonSettings = Field(default_factory=DaemonSettings)
    router: RouterSettings = Field(default_factory=RouterSettings)
    worker_model: WorkerModelSettings = Field(default_factory=WorkerModelSettings)
    model_api: ModelAPISettings = Field(default_factory=ModelAPISettings)
    task_defaults: TaskDefaults = Field(default_factory=TaskDefaults)
    spend: SpendSettings = Field(default_factory=SpendSettings)
    compute: ComputeSettings = Field(default_factory=ComputeSettings)
    provisioning: ProvisioningSettings = Field(default_factory=ProvisioningSettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    default_execution_profile: str = "balanced"
    execution_profiles: dict[str, ExecutionProfile] = Field(default_factory=default_profiles)
    # Secret-sensitive tasks use only air-gapped local nodes by default.
    # Operators can explicitly name additional trusted node IDs, including
    # rented and cloud nodes, after evaluating their own security posture.
    secret_sensitive_allowed_node_ids: frozenset[str] = Field(default_factory=frozenset)

    @model_validator(mode="after")
    def validate_default(self) -> "ConnectdConfig":
        if self.default_execution_profile not in self.execution_profiles:
            raise ValueError("default_execution_profile is absent from execution_profiles")
        if (self.default_execution_profile == "prod_secure" and
                not self.worker_model.uses_proxy):
            raise ValueError("prod_secure requires the authenticated model proxy")
        secure = self.execution_profiles.get("prod_secure")
        if secure is not None and (secure.grant_mode != GrantMode.STRICT_ED25519 or
                                   secure.worker_runtime == WorkerRuntime.SUBPROCESS):
            raise ValueError("prod_secure requires strict Ed25519 grants and a containerized worker")
        manager_ids = [manager.manager_id for manager in self.compute.node_managers]
        if len(manager_ids) != len(set(manager_ids)):
            raise ValueError("node manager IDs must be unique")
        for profile in self.execution_profiles.values():
            if profile.grant_mode == GrantMode.STRICT_ED25519 and profile.worker_runtime == WorkerRuntime.SUBPROCESS:
                raise ValueError("strict Ed25519 profile cannot use subprocess workers")
        return self

    def profile(self, name: str | None = None) -> ExecutionProfile:
        return self.execution_profiles[name or self.default_execution_profile]


def load_config(path: str | Path) -> ConnectdConfig:
    import yaml

    value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    model_id = os.environ.get("CONNECTD_WORKER_MODEL_ID")
    model_url = os.environ.get("CONNECTD_WORKER_MODEL_BASE_URL")
    if model_id or model_url:
        value.setdefault("worker_model", {})
        if model_id:
            value["worker_model"]["model_id"] = model_id
        if model_url:
            value["worker_model"]["base_url"] = model_url
    return ConnectdConfig.model_validate(value)
