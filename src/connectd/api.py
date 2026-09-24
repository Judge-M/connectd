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
from connectd.auth import AuthService, AuthenticationError, WorkerIdentity
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
from connectd.workbench import WORKBENCH_TOOL
from connectd.governance import utcnow
from connectd.control_ui import CONTROL_HTML
from connectd.spend import SpendError, usd_to_cents
from connectd.spend import metered_quote


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


class RouteRequest(BaseModel):
    task_id: str
    objective: str = Field(min_length=1)


class BudgetCreate(BaseModel):
    amount_usd: Decimal


def create_app(config: ConnectdConfig, store: Store, signing_key: Ed25519PrivateKey,
               operator_token: str, decision_router=TypedDecisionRouter,
               tool_handlers: dict | None = None) -> FastAPI:
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

    def operator(token: Annotated[str, Depends(raw_token)]) -> None:
        try:
            auth.require_operator(token)
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def worker(token: Annotated[str, Depends(raw_token)]) -> WorkerIdentity:
        try:
            return auth.require_worker(token)
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def task_row(task_id: str):
        with store.connect() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="task not found")
        return row

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
    def create_task(body: TaskCreate, _operator: Annotated[None, Depends(operator)]):
        profile_name = body.execution_profile or config.default_execution_profile
        if profile_name not in config.execution_profiles:
            raise HTTPException(status_code=422, detail="unknown execution profile")
        return {"task_id": tasks.create_task(body.title, body.privacy_class, body.memory_scope,
                                             profile_name)}

    @app.post("/tasks", status_code=201)
    def legacy_create_task(body: LegacyTaskCreate, _operator: Annotated[None, Depends(operator)]):
        profile_name = body.execution_profile or config.default_execution_profile
        if profile_name not in config.execution_profiles:
            raise HTTPException(status_code=422, detail="unknown execution profile")
        privacy = body.privacy_class or PrivacyClass(config.task_defaults.default_privacy_class)
        return {"task_id": tasks.create_task(body.title, privacy, body.memory_scope,
                profile_name, goal=body.goal, priority=body.priority,
                created_by=body.created_by, metadata_json=json.dumps(body.metadata, sort_keys=True))}

    @app.get("/api/v1/tasks/{task_id}")
    def get_task(task_id: str, _operator: Annotated[None, Depends(operator)]):
        return dict(task_row(task_id).row._mapping)

    @app.get("/api/v1/tasks")
    @app.get("/work_requests")
    def list_tasks(_operator: Annotated[None, Depends(operator)], limit: int = 100):
        if not 1 <= limit <= 1000:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
        with store.connect() as db:
            rows = db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row.row._mapping) for row in rows]

    @app.get("/planes")
    def planes(_operator: Annotated[None, Depends(operator)]):
        return {"work": "ready", "governance": "ready", "tools": "ready",
                "memory": "ready", "compute": "ready", "router": config.router.provider}

    @app.get("/api/v1/tasks/{task_id}/audit")
    def task_audit(task_id: str, _operator: Annotated[None, Depends(operator)]):
        task_row(task_id)
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
                   _operator: Annotated[None, Depends(operator)]):
        if period not in {"daily", "weekly", "monthly"}:
            raise HTTPException(status_code=422, detail="invalid budget period")
        if task_row(task_id)["is_terminal"]:
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
    def list_budgets(task_id: str, _operator: Annotated[None, Depends(operator)]):
        task_row(task_id)
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
    def add_step(task_id: str, body: StepCreate, _operator: Annotated[None, Depends(operator)]):
        task_row(task_id)
        try:
            return {"step_id": tasks.add_step(task_id, body.instruction)}
        except LeaseError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/steps/{step_id}")
    def get_step(step_id: str, _operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            row = db.execute("SELECT * FROM task_steps WHERE step_id=?", (step_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="step not found")
        return dict(row.row._mapping)

    @app.post("/api/v1/tasks/{task_id}/worker-sessions", status_code=201)
    def issue_session(task_id: str, body: SessionCreate, _operator: Annotated[None, Depends(operator)]):
        if task_row(task_id)["is_terminal"]:
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
    def complete_step(step_id: str, body: StepComplete, _operator: Annotated[None, Depends(operator)]):
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
                "memory": memory.recall(row["memory_scope"])}

    @app.post("/api/v1/tasks/{task_id}/memory/capture", status_code=201)
    def capture(task_id: str, body: ClaimCreate, identity: Annotated[WorkerIdentity, Depends(worker)]):
        if identity.task_id != task_id:
            raise HTTPException(status_code=403, detail="wrong task scope")
        row = task_row(task_id)
        try:
            claim_id = memory.capture(row["memory_scope"], body.claim_text, identity.worker_id,
                confidence=body.confidence, confidence_label=body.confidence_label,
                valid_from=body.valid_from, valid_until=body.valid_until,
                tags=body.tags, sources=body.sources)
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
        items = memory.recall_records(body.scope, max_items=body.max_items)
        if body.profile == "worker_brief":
            items = [{"text": item["text"], "scope": item["scope"],
                      "trusted": item["trusted"]} for item in items]
        return {"query": body.query, "profile": body.profile, "items": items,
                "warnings": [], "retrieval_mode": "ledger_scope"}

    @app.post("/recall")
    def legacy_recall(body: RecallRequest, _operator: Annotated[None, Depends(operator)]):
        return {"query": body.query, "profile": "full",
                "items": memory.recall_records(body.scope, max_items=body.max_items),
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
    def register_node(body: NodeCreate, _operator: Annotated[None, Depends(operator)]):
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
            if not body.endpoint_url or not body.model_id or not body.allowed_privacy_classes:
                raise HTTPException(status_code=422, detail="remote node needs endpoint, model, and privacy classes")
            if not body.endpoint_url.startswith("https://") or not all((body.ca_cert_path,
                    body.client_cert_path, body.client_key_path)):
                raise HTTPException(status_code=422, detail="remote node requires HTTPS and mTLS paths")
        if body.billing_mode == "paid" and not body.pricing:
            raise HTTPException(status_code=422, detail="paid nodes require registry pricing and cap")
        if body.billing_mode == "paid":
            try:
                from connectd.token_count import validate_tokenizer, TokenizerError
                validate_tokenizer(body.tokenizer)
            except TokenizerError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        if body.pricing:
            try:
                from connectd.spend import model_quote
                model_quote(body.pricing)
            except SpendError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        if body.billing_mode == "free" and (body.pricing or body.tokenizer):
            raise HTTPException(status_code=422, detail="free nodes cannot declare paid pricing or tokenizer")
        with store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,airgapped,billing_mode,
                endpoint_url,model_id,max_context,allowed_privacy_json,ca_cert_path,client_cert_path,client_key_path,
                pricing_model,tokenizer_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (body.node_id, body.provider_type, body.privacy_tier, True, body.airgapped, body.billing_mode,
                 body.endpoint_url, body.model_id, body.max_context,
                 json.dumps(sorted(item.value for item in body.allowed_privacy_classes))
                 if body.allowed_privacy_classes else None,
                 body.ca_cert_path, body.client_cert_path, body.client_key_path,
                 json.dumps(body.pricing, sort_keys=True) if body.pricing else None,
                 json.dumps(body.tokenizer, sort_keys=True) if body.tokenizer else None))
        return {"node_id": body.node_id}

    @app.get("/api/v1/compute/nodes/{node_id}")
    def get_node(node_id: str, _operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            row = db.execute("SELECT * FROM compute_nodes WHERE node_id=?", (node_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="node not found")
        return dict(row.row._mapping)

    @app.post("/api/v1/tools", status_code=201)
    def register_tool(body: ToolCreate, _operator: Annotated[None, Depends(operator)]):
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
            db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,active,
                status,provider_tier,effect_class,is_financial,cost_per_invocation_cents,pricing_model)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (body.tool_id, body.name, body.domain_path,
                        json.dumps(body.input_schema, sort_keys=True), body.effect_tier, bound,
                        "active" if bound else "disabled_unbound",
                        body.provider_tier, body.effect_class, body.is_financial,
                        body.cost_per_invocation_cents,
                        json.dumps(body.pricing_model, sort_keys=True) if body.pricing_model else None))
        return {"tool_id": body.tool_id, "status": "active" if bound else "disabled_unbound"}

    @app.get("/api/v1/tools")
    def list_tools(_operator: Annotated[None, Depends(operator)]):
        with store.connect() as db:
            rows = db.execute("""SELECT tool_id,name,domain_path,effect_tier,active,status,origin
                FROM tool_registry ORDER BY name,tool_id""").fetchall()
        return [dict(row.row._mapping) for row in rows]

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
            node_id = place(store, PrivacyClass(row["privacy_class"]), config.secret_sensitive_allowed_node_ids)
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
