"""Authenticated local REST surface around the in-process control-plane core."""

from typing import Annotated
import json
import os
import hashlib
from decimal import Decimal
from typing import Literal
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from connectd import __version__
from connectd.auth import AuthService, AuthenticationError, OperatorIdentity, WorkerIdentity
from connectd.compute import PlacementDenied, PrivacyClass, place
from connectd.config import ConnectdConfig
from connectd.governance import AuthorizationError, Governance
from connectd.memory import MemoryLedger
from connectd.policy import CedarPolicy
from connectd.store import Store
from connectd.task import Lease, LeaseError, TaskManager
from connectd.tools import ToolError, ToolGateway
from connectd.model import TypedDecisionRouter
from connectd.router import RouteError
from connectd.registry_access import visible_to, grant_share, revoke_share
from connectd.provisioning import LocalSecretResolver, PodRequest, ProvisioningError, RunPodAdapter
from connectd.workbench import WORKBENCH_TOOL
from connectd.governance import utcnow
from connectd.control_ui import CONTROL_HTML
from connectd.spend import SpendError, usd_to_cents
from connectd.spend import metered_quote


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OperatorCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    role: Literal["admin", "operator", "viewer"]


class OrganizationSettingsUpdate(BaseModel):
    allow_unquoted_runpod: bool


class ShareCreate(BaseModel):
    target_org_id: str = Field(min_length=1)
    resource_kind: Literal["tool", "node"]
    resource_id: str = Field(min_length=1)


class PodQuoteRequest(BaseModel):
    gpu_type_id: str = Field(min_length=1)
    gpu_count: int = Field(default=1, ge=1, le=16)
    cloud_type: Literal["SECURE", "COMMUNITY"] = "SECURE"


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    privacy_class: PrivacyClass
    memory_scope: str = Field(min_length=1, max_length=500)
    execution_profile: str | None = None


class LegacyTaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    goal: str = ""
    priority: str = "normal"
    created_by: str = "operator"
    privacy_class: PrivacyClass | None = None
    memory_scope: str = "repo:default"
    execution_profile: str | None = None
    metadata: dict = Field(default_factory=dict)


class StepCreate(BaseModel):
    instruction: str = Field(min_length=1)


class SessionCreate(BaseModel):
    worker_id: str = Field(min_length=1)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)


class ClaimRequest(BaseModel):
    lease_seconds: int = Field(default=360, ge=1, le=3600)


class ClaimCreate(BaseModel):
    claim_text: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_label: Literal["low", "medium", "high", "verified"] | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    tags: list[str] = Field(default_factory=list)
    sources: list[dict] = Field(default_factory=list)


class RecallRequest(BaseModel):
    scope: str = Field(min_length=1)
    query: str = ""
    profile: str = "full"
    max_items: int = Field(default=8, ge=1, le=100)


class PromoteRequest(BaseModel):
    confidence_label: Literal["low", "medium", "high", "verified"] | None = None


class StepComplete(BaseModel):
    lease: dict
    summary: str
    status: str = "done"


class GrantRequest(BaseModel):
    task_id: str
    tool_id: str
    args: dict


class LegacyGrantRequest(BaseModel):
    tool_id: str | None = None
    source_id: str | None = None
    name: str | None = None
    args: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)


class ApprovalRequest(GrantRequest):
    principal_id: str


class ToolCreate(BaseModel):
    tool_id: str
    name: str
    domain_path: str
    input_schema: dict = Field(alias="schema")
    effect_tier: int = Field(ge=0, le=2)
    provider_tier: str | None = None
    effect_class: str | None = None
    is_financial: bool = False
    cost_per_invocation_cents: int = Field(default=0, ge=0)
    pricing_model: dict | None = None


class ToolInvoke(BaseModel):
    task_id: str
    tool_id: str
    args: dict
    grant: dict | None = None


class NodeCreate(BaseModel):
    node_id: str
    provider_type: str
    privacy_tier: str
    airgapped: bool = False
    billing_mode: Literal["free", "paid"]
    endpoint_url: str | None = None
    model_id: str | None = None
    max_context: int | None = Field(default=None, ge=1)
    allowed_privacy_classes: set[PrivacyClass] | None = None
    ca_cert_path: str | None = None
    client_cert_path: str | None = None
    client_key_path: str | None = None
    pricing: dict | None = None
    tokenizer: dict | None = None
    preflight_url: str | None = None
    health_url: str | None = None
    manager_id: str | None = None


class RouteRequest(BaseModel):
    task_id: str
    objective: str = Field(min_length=1)


class BudgetCreate(BaseModel):
    amount_usd: Decimal


def create_app(config: ConnectdConfig, store: Store, signing_key: Ed25519PrivateKey,
               operator_token: str, decision_router=TypedDecisionRouter,
               tool_handlers: dict | None = None, provisioning_adapter=None) -> FastAPI:
    store.initialize()
    auth = AuthService(store, operator_token)
    tasks = TaskManager(store)
    memory = MemoryLedger(store)
    policy = (CedarPolicy.from_file(config.daemon.cedar_policy_path)
              if config.daemon.cedar_policy_path else CedarPolicy(""))
    governance = Governance(store, signing_key, config.profile(), policy.permit,
                            profiles=config.execution_profiles, policy_evaluator=policy.evaluate,
                            spend_reset_timezone=config.spend.reset_timezone)
    gateway = ToolGateway(store, governance)
    gateway.register_handler("echo", lambda args: {"echo": args})
    for tool_id, handler in (tool_handlers or {}).items():
        gateway.register_handler(tool_id, handler)
    bearer = HTTPBearer(auto_error=False)
    app = FastAPI(title="connectd", version=__version__)

    def raw_token(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> str:
        if credentials is None:
            raise HTTPException(status_code=401, detail="bearer token required")
        return credentials.credentials

    def require_role(token: str, role: str) -> OperatorIdentity:
        try:
            return auth.require_operator(token, role)
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def tenant_operator(token: Annotated[str, Depends(raw_token)]) -> OperatorIdentity:
        return require_role(token, "operator")

    def operator(token: Annotated[str, Depends(raw_token)]) -> OperatorIdentity:
        identity = require_role(token, "operator")
        if not identity.bootstrap:
            raise HTTPException(status_code=403, detail="global operation requires bootstrap operator")
        return identity

    def reader(token: Annotated[str, Depends(raw_token)]) -> OperatorIdentity:
        return require_role(token, "viewer")

    def admin(token: Annotated[str, Depends(raw_token)]) -> OperatorIdentity:
        return require_role(token, "admin")

    def bootstrap(identity: Annotated[OperatorIdentity, Depends(admin)]) -> OperatorIdentity:
        if not identity.bootstrap:
            raise HTTPException(status_code=403, detail="bootstrap operator required")
        return identity

    def require_org(identity: OperatorIdentity, org_id: str) -> None:
        if not identity.bootstrap and identity.org_id != org_id:
            raise HTTPException(status_code=404, detail="organization not found")

    def require_org_admin(identity: OperatorIdentity, org_id: str) -> None:
        if identity.bootstrap:
            raise HTTPException(status_code=403,
                                detail="target organization admin token required")
        require_org(identity, org_id)

    def worker(token: Annotated[str, Depends(raw_token)]) -> WorkerIdentity:
        try:
            return auth.require_worker(token)
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def task_row(task_id: str, identity: OperatorIdentity | None = None):
        with store.connect() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None or (identity is not None and not identity.bootstrap and
                           row["org_id"] != identity.org_id):
            raise HTTPException(status_code=404, detail="task not found")
        return row

    @app.get("/api/v1/me")
    def current_operator(identity: Annotated[OperatorIdentity, Depends(reader)]):
        return identity.__dict__

    @app.post("/api/v1/orgs", status_code=201)
    def create_organization(body: OrganizationCreate,
                            _bootstrap: Annotated[OperatorIdentity, Depends(bootstrap)]):
        org_id = str(uuid4())
        with store.connect() as db:
            db.execute("INSERT INTO organizations(org_id,name,created_at) VALUES (?,?,?)",
                       (org_id, body.name, utcnow().isoformat()))
        return {"org_id": org_id, "name": body.name}

    @app.get("/api/v1/orgs")
    def list_organizations(_bootstrap: Annotated[OperatorIdentity, Depends(bootstrap)]):
        with store.connect() as db:
            rows = db.execute("SELECT * FROM organizations ORDER BY created_at").fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.get("/api/v1/orgs/{org_id}/settings")
    def get_organization_settings(org_id: str,
                                  identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        with store.connect() as db:
            row = db.execute("""SELECT org_id,allow_unquoted_runpod FROM organizations
                WHERE org_id=?""", (org_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="organization not found")
        return {"org_id": org_id, "allow_unquoted_runpod": bool(row["allow_unquoted_runpod"])}

    @app.put("/api/v1/orgs/{org_id}/settings")
    def update_organization_settings(org_id: str, body: OrganizationSettingsUpdate,
                                     identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org_admin(identity, org_id)
        with store.connect() as db:
            updated = db.execute("""UPDATE organizations SET allow_unquoted_runpod=?
                WHERE org_id=?""", (body.allow_unquoted_runpod, org_id))
        if updated.rowcount != 1:
            raise HTTPException(status_code=404, detail="organization not found")
        return {"org_id": org_id, "allow_unquoted_runpod": body.allow_unquoted_runpod}

    @app.post("/api/v1/orgs/{org_id}/provisioning/runpod/quote")
    def quote_runpod_pod(org_id: str, body: PodQuoteRequest,
                         identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        with store.connect() as db:
            if db.execute("SELECT 1 FROM organizations WHERE org_id=?",
                          (org_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail="organization not found")
        adapter = provisioning_adapter or RunPodAdapter(
            LocalSecretResolver(config.provisioning.runpod_secret_file))
        request = PodRequest(name="quote-preview", gpu_type_id=body.gpu_type_id,
                             gpu_count=body.gpu_count, image_name="quote-only",
                             cloud_type=body.cloud_type)
        try:
            quote = adapter.quote(request)
        except ProvisioningError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"gpu_hourly_usd": str(quote.gpu_hourly_usd),
                "availability": quote.availability, "source": quote.source,
                "includes_storage": False, "binding_price": False}

    @app.get("/api/v1/orgs/{org_id}/shares")
    def list_registry_shares(org_id: str,
                             identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        with store.connect() as db:
            if db.execute("SELECT 1 FROM organizations WHERE org_id=?",
                          (org_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail="organization not found")
            rows = db.execute("""SELECT owner_org_id,target_org_id,resource_kind,
                resource_id,created_by,created_at FROM registry_shares
                WHERE owner_org_id=? ORDER BY resource_kind,resource_id,target_org_id""",
                (org_id,)).fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.post("/api/v1/orgs/{org_id}/shares", status_code=201)
    def create_registry_share(org_id: str, body: ShareCreate,
                              identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org_admin(identity, org_id)
        with store.connect() as db:
            try:
                grant_share(db, org_id, body.target_org_id, body.resource_kind,
                            body.resource_id, identity.user_id, utcnow().isoformat())
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"owner_org_id": org_id, **body.model_dump()}

    @app.delete("/api/v1/orgs/{org_id}/shares/{resource_kind}/{resource_id}/{target_org_id}")
    def delete_registry_share(org_id: str, resource_kind: Literal["tool", "node"],
                              resource_id: str, target_org_id: str,
                              identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org_admin(identity, org_id)
        with store.connect() as db:
            deleted = revoke_share(db, org_id, target_org_id, resource_kind,
                                   resource_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="share not found")
        return {"owner_org_id": org_id, "target_org_id": target_org_id,
                "resource_kind": resource_kind, "resource_id": resource_id,
                "revoked": True}

    @app.post("/api/v1/orgs/{org_id}/users", status_code=201)
    def create_operator(org_id: str, body: OperatorCreate,
                        identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        with store.connect() as db:
            if db.execute("SELECT 1 FROM organizations WHERE org_id=?", (org_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail="organization not found")
        user_id, token = auth.issue_operator(org_id, body.display_name, body.role)
        return {"user_id": user_id, "org_id": org_id, "role": body.role, "token": token}

    @app.get("/api/v1/orgs/{org_id}/users")
    def list_operators(org_id: str, identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        with store.connect() as db:
            rows = db.execute("""SELECT user_id,org_id,display_name,role,active,created_at
                FROM operator_users WHERE org_id=? ORDER BY created_at""", (org_id,)).fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.delete("/api/v1/orgs/{org_id}/users/{user_id}")
    def revoke_operator(org_id: str, user_id: str,
                        identity: Annotated[OperatorIdentity, Depends(admin)]):
        require_org(identity, org_id)
        if identity.user_id == user_id:
            raise HTTPException(status_code=409, detail="cannot revoke own token")
        if not auth.revoke_operator(org_id, user_id):
            raise HTTPException(status_code=404, detail="active user not found")
        return {"user_id": user_id, "active": False}

    @app.get("/health")
    @app.get("/healthz")
    def health():
        with store.connect() as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "healthy", "version": __version__,
                "active_profile": config.default_execution_profile}

    @app.get("/control", response_class=HTMLResponse)
    def control_workspace():
        return CONTROL_HTML

    @app.post("/api/v1/tasks", status_code=201)
    def create_task(body: TaskCreate, identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        profile_name = body.execution_profile or config.default_execution_profile
        if profile_name not in config.execution_profiles:
            raise HTTPException(status_code=422, detail="unknown execution profile")
        return {"task_id": tasks.create_task(body.title, body.privacy_class, body.memory_scope,
                                             profile_name, org_id=identity.org_id or "default",
                                             created_by=identity.user_id)}

    @app.post("/tasks", status_code=201)
    def legacy_create_task(body: LegacyTaskCreate,
                           identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        profile_name = body.execution_profile or config.default_execution_profile
        if profile_name not in config.execution_profiles:
            raise HTTPException(status_code=422, detail="unknown execution profile")
        privacy = body.privacy_class or PrivacyClass(config.task_defaults.default_privacy_class)
        return {"task_id": tasks.create_task(body.title, privacy, body.memory_scope,
                profile_name, goal=body.goal, priority=body.priority,
                created_by=identity.user_id, metadata_json=json.dumps(body.metadata, sort_keys=True),
                org_id=identity.org_id or "default")}

    @app.get("/api/v1/tasks/{task_id}")
    def get_task(task_id: str, identity: Annotated[OperatorIdentity, Depends(reader)]):
        return dict(task_row(task_id, identity).row._mapping)

    @app.get("/api/v1/tasks")
    @app.get("/work_requests")
    def list_tasks(identity: Annotated[OperatorIdentity, Depends(reader)], limit: int = 100):
        if not 1 <= limit <= 1000:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
        with store.connect() as db:
            if identity.bootstrap:
                rows = db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
                                  (limit,)).fetchall()
            else:
                rows = db.execute("""SELECT * FROM tasks WHERE org_id=?
                    ORDER BY created_at DESC LIMIT ?""", (identity.org_id, limit)).fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.get("/planes")
    def planes(_operator: Annotated[None, Depends(operator)]):
        return {"work": "ready", "governance": "ready", "tools": "ready",
                "memory": "ready", "compute": "ready", "router": config.router.provider}

    @app.get("/api/v1/tasks/{task_id}/audit")
    def task_audit(task_id: str, identity: Annotated[OperatorIdentity, Depends(reader)]):
        task_row(task_id, identity)
        with store.connect() as db:
            decisions = db.execute("SELECT * FROM governance_decisions WHERE task_id=? ORDER BY created_at",
                                   (task_id,)).fetchall()
            grants = db.execute("SELECT grant_id,decision_id,task_id,principal_id,tool_id,status,issued_at,expires_at FROM governance_grants WHERE task_id=? ORDER BY issued_at",
                                (task_id,)).fetchall()
            invocations = db.execute("SELECT * FROM tool_invocation_logs WHERE task_id=? ORDER BY created_at",
                                     (task_id,)).fetchall()
            legacy = db.execute("SELECT seq,kind,body_hash,created_at,prev_hash,record_hash,grant_id FROM legacy_tool_audit WHERE task_id=? ORDER BY seq",
                                (task_id,)).fetchall()
        return {"decisions": [dict(item.row._mapping) for item in decisions],
                "grants": [dict(item.row._mapping) for item in grants],
                "invocations": [dict(item.row._mapping) for item in invocations],
                "legacy_tool_audit": [dict(item.row._mapping) for item in legacy]}

    @app.put("/api/v1/tasks/{task_id}/budgets/{period}")
    def set_budget(task_id: str, period: str, body: BudgetCreate,
                   identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        if period not in {"daily", "weekly", "monthly"}:
            raise HTTPException(status_code=422, detail="invalid budget period")
        if task_row(task_id, identity)["is_terminal"]:
            raise HTTPException(status_code=409, detail="task is terminal")
        try:
            cents = usd_to_cents(body.amount_usd)
        except SpendError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if store.engine.dialect.name == "postgresql":
                db.execute("SELECT task_id FROM tasks WHERE task_id=? FOR UPDATE", (task_id,)).fetchone()
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,approved_by,created_at)
                VALUES (?,?,?,?,?,?) ON CONFLICT (task_id,period) DO UPDATE SET
                amount_cents=excluded.amount_cents,approved_by=excluded.approved_by,
                created_at=excluded.created_at""",
                (str(uuid4()), task_id, period, cents, "operator", utcnow().isoformat()))
            db.commit()
        return {"task_id": task_id, "period": period, "amount_usd": str(body.amount_usd)}

    @app.get("/api/v1/tasks/{task_id}/budgets")
    def list_budgets(task_id: str, identity: Annotated[OperatorIdentity, Depends(reader)]):
        task_row(task_id, identity)
        with store.connect() as db:
            budgets = db.execute("SELECT period,amount_cents,approved_by,created_at FROM quota_budgets WHERE task_id=?",
                                 (task_id,)).fetchall()
            records = db.execute("SELECT tool_id,grant_id,amount_cents,created_at FROM quota_records WHERE task_id=?",
                                 (task_id,)).fetchall()
        return {"budgets": [dict(row.row._mapping) for row in budgets],
                "records": [dict(row.row._mapping) for row in records]}

    @app.get("/audit")
    def legacy_audit_integrity(_operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            rows = db.execute("SELECT * FROM legacy_tool_audit ORDER BY seq").fetchall()
        previous = "0" * 64
        payloads_verified = True
        for row in rows:
            if row["prev_hash"] != previous:
                return {"chain_links_valid": False, "payloads_verified": False,
                        "broken_at": row["seq"]}
            if row["body_json"] is not None:
                expected = hashlib.sha256(f"{row['kind']}\x1f{row['body_json']}\x1f{row['created_at']}\x1f{row['prev_hash']}".encode()).hexdigest()
                if expected != row["record_hash"]:
                    return {"chain_links_valid": False, "payloads_verified": False,
                            "broken_at": row["seq"]}
            else:
                payloads_verified = False
            previous = row["record_hash"]
        return {"chain_links_valid": True, "payloads_verified": payloads_verified,
                "entries": len(rows), "head_hash": previous}

    @app.post("/api/v1/tasks/{task_id}/steps", status_code=201)
    def add_step(task_id: str, body: StepCreate,
                 identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        task_row(task_id, identity)
        try:
            return {"step_id": tasks.add_step(task_id, body.instruction)}
        except LeaseError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/tasks/{task_id}/steps")
    def list_steps(task_id: str, identity: Annotated[OperatorIdentity, Depends(reader)]):
        task_row(task_id, identity)
        with store.connect() as db:
            rows = db.execute("""SELECT step_id,task_id,step_number,instruction,status,
                assigned_worker_id,lease_expires_at,result_summary FROM task_steps
                WHERE task_id=? ORDER BY step_number""", (task_id,)).fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.get("/api/v1/steps/{step_id}")
    def get_step(step_id: str, identity: Annotated[OperatorIdentity, Depends(reader)]):
        with store.connect() as db:
            row = db.execute("SELECT * FROM task_steps WHERE step_id=?", (step_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="step not found")
        task_row(row["task_id"], identity)
        return dict(row.row._mapping)

    @app.post("/api/v1/tasks/{task_id}/worker-sessions", status_code=201)
    def issue_session(task_id: str, body: SessionCreate,
                      identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        if task_row(task_id, identity)["is_terminal"]:
            raise HTTPException(status_code=409, detail="task is terminal")
        return {"token": auth.issue_worker(task_id, body.worker_id, body.ttl_seconds)}

    @app.post("/api/v1/steps/{step_id}/claim")
    def claim_step(step_id: str, body: ClaimRequest,
                   identity: Annotated[WorkerIdentity, Depends(worker)]):
        with store.connect() as db:
            row = db.execute("SELECT task_id FROM task_steps WHERE step_id=?", (step_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="step not found")
        if identity.task_id != row["task_id"]:
            raise HTTPException(status_code=403, detail="wrong task scope")
        try:
            return tasks.claim(step_id, identity.worker_id, body.lease_seconds).__dict__
        except LeaseError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/steps/{step_id}/complete")
    def complete_step(step_id: str, body: StepComplete,
                      identity: Annotated[OperatorIdentity, Depends(tenant_operator)]):
        with store.connect() as db:
            step = db.execute("SELECT task_id FROM task_steps WHERE step_id=?", (step_id,)).fetchone()
        if step is None:
            raise HTTPException(status_code=404, detail="step not found")
        task_row(step["task_id"], identity)
        try:
            lease = Lease(**body.lease)
            if lease.step_id != step_id:
                raise ValueError("step ID mismatch")
            tasks.finish(lease, body.summary, body.status)
        except (LeaseError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": body.status}

    @app.get("/api/v1/tasks/{task_id}/context-pack")
    def context_pack(task_id: str, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        row = task_row(task_id)
        return {"task_id": task_id, "title": row["title"], "privacy_class": row["privacy_class"],
                "memory": memory.recall(row["memory_scope"], org_id=row["org_id"])}

    @app.post("/api/v1/tasks/{task_id}/memory/capture", status_code=201)
    def capture(task_id: str, body: ClaimCreate, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        row = task_row(task_id)
        try:
            claim_id = memory.capture(row["memory_scope"], body.claim_text, identity.worker_id,
                confidence=body.confidence, confidence_label=body.confidence_label,
                valid_from=body.valid_from, valid_until=body.valid_until,
                tags=body.tags, sources=body.sources, org_id=row["org_id"])
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"claim_id": claim_id}

    @app.post("/api/v1/tasks/{task_id}/memory/recall")
    def worker_recall(task_id: str, body: RecallRequest,
                      identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != task_id or body.scope != task_row(task_id)["memory_scope"]:
            raise HTTPException(status_code=403, detail="wrong task scope")
        if body.profile not in {"full", "worker_brief"}:
            raise HTTPException(status_code=422, detail="unknown recall profile")
        row = task_row(task_id)
        items = memory.recall_records(body.scope, active_only=True,
                                      max_items=body.max_items, org_id=row["org_id"])
        if body.profile == "worker_brief":
            items = [{"text": item["text"], "scope": item["scope"],
                      "trusted": item["trusted"]} for item in items]
        return {"query": body.query, "profile": body.profile, "items": items,
                "warnings": [], "retrieval_mode": "ledger_scope"}

    @app.post("/api/v1/memory/recall")
    @app.post("/recall")
    def legacy_recall(body: RecallRequest, _operator: Annotated[None, Depends(operator)]):
        return {"query": body.query, "profile": "full",
                "items": memory.recall_records(body.scope, include_pending=True,
                    trusted_only=False, max_items=body.max_items),
                "warnings": [], "retrieval_mode": "ledger_scope"}

    @app.post("/api/v1/memory/claims/{claim_id}/promote")
    @app.post("/candidates/{claim_id}/promote")
    def promote(claim_id: str, _operator: Annotated[None, Depends(operator)],
                body: PromoteRequest | None = None):
        try:
            memory.promote(claim_id, "operator", body.confidence_label if body else None)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "promoted"}

    @app.get("/api/v1/memory/candidates")
    @app.get("/candidates")
    def candidates(_operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            rows = db.execute("SELECT * FROM memory_claims WHERE status='pending' ORDER BY created_at").fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.post("/api/v1/compute/nodes", status_code=201)
    def register_node(body: NodeCreate, identity: Annotated[OperatorIdentity, Depends(admin)]):
        if body.privacy_tier not in ("local_only", "private_rented", "external"):
            raise HTTPException(status_code=422, detail="invalid privacy tier")
        from urllib.parse import urlsplit
        import json

        if body.endpoint_url:
            parsed = urlsplit(body.endpoint_url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise HTTPException(status_code=422, detail="invalid node endpoint URL")
            if (body.privacy_tier == "local_only" and
                    parsed.hostname not in config.model_api.allowed_local_hosts):
                raise HTTPException(status_code=422, detail="local node endpoint host is not allowed")
        if body.privacy_tier != "local_only":
            if not body.endpoint_url or not body.model_id or not body.allowed_privacy_classes or not (body.health_url or body.manager_id):
                raise HTTPException(status_code=422, detail="remote node needs endpoint, model, privacy classes, and health source")
            if not body.endpoint_url.startswith("https://") or not all((body.ca_cert_path,
                    body.client_cert_path, body.client_key_path)):
                raise HTTPException(status_code=422, detail="remote node requires HTTPS and mTLS paths")
        if body.manager_id:
            if body.privacy_tier == "local_only":
                raise HTTPException(status_code=422, detail="local nodes use direct health checks")
            manager = next((item for item in config.compute.node_managers
                            if item.manager_id == body.manager_id), None)
            if manager is None or body.node_id not in manager.allowed_node_ids:
                raise HTTPException(status_code=422, detail="node is not approved in the configured manager")
            if body.health_url:
                raise HTTPException(status_code=422, detail="managed nodes use manager health reports")
        if body.billing_mode == "paid" and not body.pricing:
            raise HTTPException(status_code=422, detail="paid nodes require registry pricing and cap")
        if body.billing_mode == "paid" and not body.preflight_url:
            raise HTTPException(status_code=422, detail="paid nodes require a token-count preflight URL")
        if body.tokenizer:
            try:
                from connectd.token_count import validate_tokenizer, TokenizerError
                validate_tokenizer(body.tokenizer)
            except TokenizerError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        for checked_url, purpose in ((body.preflight_url, "preflight"), (body.health_url, "health")):
            if not checked_url:
                continue
            if not body.endpoint_url:
                raise HTTPException(status_code=422, detail=f"{purpose} needs an inference endpoint")
            endpoint = urlsplit(body.endpoint_url)
            checked = urlsplit(checked_url)
            try:
                same_origin = ((checked.scheme, checked.hostname, checked.port) ==
                               (endpoint.scheme, endpoint.hostname, endpoint.port))
            except ValueError:
                same_origin = False
            if (not same_origin or not checked.path or checked.query or checked.fragment or
                    checked.username or checked.password):
                raise HTTPException(status_code=422,
                    detail=f"{purpose} URL must share the inference endpoint origin")
        if body.preflight_url:
            if not body.endpoint_url or body.billing_mode != "paid":
                raise HTTPException(status_code=422, detail="preflight is only for paid inference endpoints")
        if body.pricing:
            try:
                from connectd.spend import model_quote
                model_quote(body.pricing)
            except SpendError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        if body.billing_mode == "free" and (body.pricing or body.tokenizer or body.preflight_url):
            raise HTTPException(status_code=422, detail="free nodes cannot declare paid pricing or preflight")
        with store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,owner_org_id,provider_type,privacy_tier,healthy,airgapped,billing_mode,
                endpoint_url,model_id,max_context,allowed_privacy_json,ca_cert_path,client_cert_path,client_key_path,
                pricing_model,tokenizer_json,preflight_url,health_url,manager_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (body.node_id, identity.org_id or "default", body.provider_type, body.privacy_tier,
                 body.privacy_tier == "local_only" and not body.health_url,
                 body.airgapped, body.billing_mode,
                 body.endpoint_url, body.model_id, body.max_context,
                 json.dumps(sorted(item.value for item in body.allowed_privacy_classes))
                 if body.allowed_privacy_classes else None,
                 body.ca_cert_path, body.client_cert_path, body.client_key_path,
                 json.dumps(body.pricing, sort_keys=True) if body.pricing else None,
                 json.dumps(body.tokenizer, sort_keys=True) if body.tokenizer else None,
                 body.preflight_url, body.health_url, body.manager_id))
        return {"node_id": body.node_id}

    @app.get("/api/v1/compute/nodes/{node_id}")
    def get_node(node_id: str, identity: Annotated[OperatorIdentity, Depends(admin)]):
        with store.connect() as db:
            row = db.execute("SELECT * FROM compute_nodes WHERE node_id=?", (node_id,)).fetchone()
        if row is None or (not identity.bootstrap and row["owner_org_id"] != identity.org_id):
            raise HTTPException(status_code=404, detail="node not found")
        return dict(row.row._mapping)

    @app.get("/api/v1/compute/nodes")
    def list_nodes(identity: Annotated[OperatorIdentity, Depends(reader)]):
        with store.connect() as db:
            rows = db.execute("""SELECT node_id,owner_org_id,provider_type,privacy_tier,healthy,
                model_id,last_health_at,capacity_json,manager_id FROM compute_nodes ORDER BY node_id""").fetchall()
            visible = [row for row in rows if identity.bootstrap or visible_to(
                db, row["owner_org_id"], identity.org_id, "node", row["node_id"])]
        return [dict(row.row._mapping) for row in visible]

    @app.post("/api/v1/compute/nodes/{node_id}/probe")
    def probe_node(node_id: str, identity: Annotated[OperatorIdentity, Depends(admin)]):
        from connectd.node_monitor import NodeMonitor
        with store.connect() as db:
            node = db.execute("SELECT manager_id,owner_org_id FROM compute_nodes WHERE node_id=?",
                              (node_id,)).fetchone()
        if node is None or (not identity.bootstrap and node["owner_org_id"] != identity.org_id):
            raise HTTPException(status_code=404, detail="node not found")
        monitor = NodeMonitor(store)
        if node["manager_id"]:
            manager = next((item for item in config.compute.node_managers
                            if item.manager_id == node["manager_id"]), None)
            if manager is None or not monitor.probe_manager(manager).get(node_id):
                raise HTTPException(status_code=503, detail="manager failed authenticated health or capacity check")
        elif not monitor.probe(node_id):
            raise HTTPException(status_code=503, detail="node failed authenticated health or capacity check")
        return {"node_id": node_id, "healthy": True}

    @app.post("/api/v1/tools", status_code=201)
    def register_tool(body: ToolCreate, identity: Annotated[OperatorIdentity, Depends(admin)]):
        import json

        financial = (body.is_financial or body.provider_tier in {"external_paid", "private_rented"}
                     or body.effect_class in {"external_mutation", "billing_impact"}
                     or body.cost_per_invocation_cents > 0 or body.pricing_model is not None)
        if financial and body.effect_tier != 2:
            raise HTTPException(status_code=422, detail="financial tools must be Tier 2")
        if body.pricing_model:
            try:
                metered_quote(body.pricing_model)
            except SpendError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        bound = body.tool_id in gateway.handlers
        with store.connect() as db:
            db.execute("""INSERT INTO tool_registry(tool_id,owner_org_id,name,domain_path,schema_json,effect_tier,active,
                status,provider_tier,effect_class,is_financial,cost_per_invocation_cents,pricing_model)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (body.tool_id, identity.org_id or "default", body.name, body.domain_path,
                        json.dumps(body.input_schema, sort_keys=True), body.effect_tier, bound,
                        "active" if bound else "disabled_unbound",
                        body.provider_tier, body.effect_class, body.is_financial,
                        body.cost_per_invocation_cents,
                        json.dumps(body.pricing_model, sort_keys=True) if body.pricing_model else None))
        return {"tool_id": body.tool_id, "status": "active" if bound else "disabled_unbound"}

    @app.get("/api/v1/tools/binding-proposals")
    def binding_proposals(_operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            rows = db.execute("""SELECT tool_id,name,domain_path,schema_json,effect_tier,origin
                FROM tool_registry WHERE origin!='connectd' AND active=FALSE
                ORDER BY name,tool_id""").fetchall()
        proposals = []
        for row in rows:
            candidate = row["name"] if row["name"] in gateway.handlers else None
            proposals.append({
                "tool_id": row["tool_id"], "legacy_name": row["name"],
                "source": row["domain_path"], "schema": json.loads(row["schema_json"]),
                "effect_tier": row["effect_tier"],
                "suggested_handler_id": candidate,
                "review_status": "awaiting_operator_review" if candidate else "needs_handler",
            })
        return proposals

    @app.get("/api/v1/tools")
    def list_tools(identity: Annotated[OperatorIdentity, Depends(reader)]):
        with store.connect() as db:
            rows = db.execute("""SELECT tool_id,owner_org_id,name,domain_path,effect_tier,active,status,origin
                FROM tool_registry ORDER BY name,tool_id""").fetchall()
            visible = [row for row in rows if identity.bootstrap or visible_to(
                db, row["owner_org_id"], identity.org_id, "tool", row["tool_id"])]
        return [dict(row.row._mapping) for row in visible]

    @app.post("/api/v1/tools/{tool_id}/activate")
    def activate_tool(tool_id: str, _operator: Annotated[None, Depends(operator)]):
        if tool_id not in gateway.handlers:
            raise HTTPException(status_code=409, detail="tool has no reviewed execution handler")
        with store.connect() as db:
            updated = db.execute("""UPDATE tool_registry SET active=TRUE,status='active'
                WHERE tool_id=? AND active=FALSE""", (tool_id,))
            if updated.rowcount != 1:
                raise HTTPException(status_code=404, detail="inactive tool not found")
        return {"tool_id": tool_id, "status": "active"}

    @app.get("/api/v1/tools/{tool_id}")
    def get_tool(tool_id: str, identity: Annotated[WorkerIdentity, Depends(worker)]):
        with store.connect() as db:
            row = db.execute("SELECT * FROM tool_registry WHERE tool_id=? AND active=TRUE", (tool_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="tool not found")
        task = task_row(identity.task_id)
        with store.connect() as db:
            if not visible_to(db, row["owner_org_id"], task["org_id"], "tool", tool_id):
                raise HTTPException(status_code=404, detail="tool not found")
        import json
        return {"tool_id": row["tool_id"], "name": row["name"],
                "effect_tier": row["effect_tier"], "schema": json.loads(row["schema_json"])}

    @app.post("/api/v1/router/route")
    def route_task(body: RouteRequest, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != body.task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        row = task_row(body.task_id)
        if row["privacy_class"] == "secret_sensitive" and config.router.provider != "laya":
            raise HTTPException(status_code=403, detail="secret-sensitive routing requires local Laya")
        api_key = os.environ.get(config.router.api_key_env) if config.router.provider == "jev" else None
        try:
            tree = json.loads(config.router.tree_registry_path.read_text(encoding="utf-8"))["trees"]["tool_routing"]
            router = decision_router(config.router.provider, config.router.base_url,
                                         config.router.min_confidence, api_key=api_key)
            decision = router.route(tree, body.objective)
            tool_id = decision.route.leaf["resolved_tool_id"]
        except (OSError, KeyError, ValueError, RouteError) as exc:
            with store.connect() as db:
                db.execute("""INSERT INTO routing_decisions(routing_id,task_id,provider,resolved_tool_id,
                    status,reason,hops_json,confidences_json,latency_ms,created_at)
                    VALUES (?,?,?,NULL,?,?,?,?,?,?)""", (str(uuid4()), body.task_id,
                    config.router.provider, "denied", str(exc)[:300], "[]", "{}", 0,
                    utcnow().isoformat()))
                if row["execution_profile"] != "prod_secure":
                    db.execute("UPDATE tasks SET status='pending_clarification' WHERE task_id=? AND is_terminal=FALSE",
                               (body.task_id,))
            raise HTTPException(status_code=409 if row["execution_profile"] != "prod_secure" else 403,
                                detail="routing requires operator clarification" if row["execution_profile"] != "prod_secure"
                                else "routing denied") from exc
        if tool_id == "workbench":
            schema = WORKBENCH_TOOL
            effect_tier = 1
        else:
            with store.connect() as db:
                tool_row = db.execute("SELECT * FROM tool_registry WHERE tool_id=? AND active=TRUE",
                                      (tool_id,)).fetchone()
            if tool_row is None:
                raise HTTPException(status_code=503, detail="route resolves to inactive tool")
            with store.connect() as db:
                allowed_tool = visible_to(db, tool_row["owner_org_id"], row["org_id"],
                                          "tool", tool_id)
            if not allowed_tool:
                raise HTTPException(status_code=403, detail="route resolves to an unshared tool")
            schema = {"type": "function", "function": {"name": tool_id,
                      "description": tool_row["name"],
                      "parameters": json.loads(tool_row["schema_json"])}}
            effect_tier = tool_row["effect_tier"]
        with store.connect() as db:
            db.execute("""INSERT INTO routing_decisions(routing_id,task_id,provider,resolved_tool_id,
                status,reason,hops_json,confidences_json,latency_ms,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (str(uuid4()), body.task_id, decision.provider, tool_id, "resolved", None,
                 json.dumps([hop.__dict__ for hop in decision.route.hops], sort_keys=True),
                 json.dumps(decision.confidences, sort_keys=True),
                 round(decision.latency_ms), utcnow().isoformat()))
            db.execute("UPDATE tasks SET status='active' WHERE task_id=? AND status='pending_clarification'",
                       (body.task_id,))
        return {"tool_id": tool_id, "tool": schema, "effect_tier": effect_tier,
                "latency_ms": decision.latency_ms, "confidences": decision.confidences}

    @app.post("/api/v1/governance/approvals", status_code=201)
    def approve_action(body: ApprovalRequest, _operator: Annotated[None, Depends(operator)]):
        return {"approval_id": governance.approve(body.task_id, body.principal_id,
                                                    body.tool_id, body.args, "operator")}

    @app.get("/api/v1/tasks/{task_id}/placement")
    def placement(task_id: str, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        row = task_row(task_id)
        try:
            node_id = place(store, PrivacyClass(row["privacy_class"]),
                            config.secret_sensitive_allowed_node_ids,
                            max_health_age_seconds=config.compute.health_interval_seconds * 3,
                            org_id=row["org_id"])
        except PlacementDenied as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        with store.connect() as db:
            node = db.execute("SELECT privacy_tier,airgapped,provider_type FROM compute_nodes WHERE node_id=?",
                              (node_id,)).fetchone()
        return {"node_id": node_id, "privacy_tier": node["privacy_tier"],
                "airgapped": bool(node["airgapped"]), "provider_type": node["provider_type"]}

    @app.post("/api/v1/governance/grants", status_code=201)
    def authorize(body: GrantRequest, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != body.task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        if body.tool_id not in gateway.handlers:
            raise HTTPException(status_code=409, detail="tool has no bound execution handler")
        try:
            return governance.issue(body.task_id, identity.worker_id, body.tool_id, body.args)
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def legacy_grant_input(body: LegacyGrantRequest, identity: WorkerIdentity):
        task_id = body.context.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise HTTPException(status_code=400, detail={"error": "missing_task_context",
                "message": "context.task_id is required for live authorization"})
        if task_id != identity.task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        tool_id = body.tool_id
        if tool_id is None and body.source_id and body.name:
            with store.connect() as db:
                matches = db.execute("""SELECT tool_id FROM tool_registry WHERE domain_path=?
                    AND name=? AND active=TRUE""",
                    (f"legacy/{body.source_id}", body.name)).fetchall()
            if len(matches) != 1:
                raise HTTPException(status_code=404 if not matches else 409,
                                    detail="legacy tool is missing, inactive, or ambiguous")
            tool_id = matches[0]["tool_id"]
        elif tool_id is None:
            tool_id = body.name
        if not tool_id:
            raise HTTPException(status_code=400, detail="tool_id or name is required")
        return task_id, tool_id

    @app.post("/authorize", status_code=201)
    def legacy_authorize(body: LegacyGrantRequest, identity: Annotated[WorkerIdentity, Depends(worker)]):
        task_id, tool_id = legacy_grant_input(body, identity)
        if tool_id not in gateway.handlers:
            raise HTTPException(status_code=409, detail="tool has no bound execution handler")
        try:
            grant = governance.issue(task_id, identity.worker_id, tool_id, body.args)
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return {"status": "PERMIT", "grant_id": grant["grant_id"], "grant": grant,
                "execution": {"gateway_required": True,
                              "invoke_endpoint": "/api/v1/tools/invoke"}}

    @app.post("/authorize_and_invoke")
    def legacy_authorize_and_invoke(body: LegacyGrantRequest,
                                    identity: Annotated[WorkerIdentity, Depends(worker)]):
        task_id, tool_id = legacy_grant_input(body, identity)
        try:
            return {"result": gateway.invoke(task_id, identity.worker_id, tool_id, body.args)}
        except ToolError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/decisions/{decision_id}/outcome")
    def legacy_outcome(decision_id: str,
                       _identity: Annotated[WorkerIdentity, Depends(worker)]):
        raise HTTPException(status_code=409, detail={
            "error": "gateway_execution_required",
            "message": "Off-gateway execution cannot be verified or recorded as a connectd tool outcome."
        })

    @app.post("/api/v1/tools/invoke")
    def invoke_tool(body: ToolInvoke, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != body.task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        try:
            return {"result": gateway.invoke(body.task_id, identity.worker_id, body.tool_id,
                                             body.args, body.grant)}
        except ToolError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return app
