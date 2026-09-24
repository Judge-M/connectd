"""Authenticated model transport broker; remote inference uses per-node mTLS."""

import ssl
from decimal import Decimal, ROUND_CEILING
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from connectd.auth import AuthService, AuthenticationError
from connectd.compute import PlacementDenied, PrivacyClass, place
from connectd.config import ConnectdConfig
from connectd.governance import utcnow
from connectd.store import Store
from connectd.spend import SpendError, budget_requires_approval, model_quote


def create_model_proxy(config: ConnectdConfig, store: Store, operator_token: str,
                       client_factory=None) -> FastAPI:
    store.initialize()
    auth = AuthService(store, operator_token)
    app = FastAPI(title="connectd model transport")

    @app.get("/health")
    def health():
        return {"status": "healthy"}

    @app.post("/v1/chat/completions")
    def chat(payload: dict, authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="worker token required")
        try:
            identity = auth.require_worker(authorization[7:])
        except AuthenticationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        with store.connect() as db:
            task = db.execute("SELECT privacy_class FROM tasks WHERE task_id=?", (identity.task_id,)).fetchone()
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        try:
            node_id = place(store, PrivacyClass(task["privacy_class"]),
                            config.secret_sensitive_allowed_node_ids)
        except PlacementDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        with store.connect() as db:
            node = db.execute("SELECT * FROM compute_nodes WHERE node_id=?", (node_id,)).fetchone()
        if node is None or not node["endpoint_url"] or not node["model_id"]:
            raise HTTPException(status_code=503, detail="selected node has no inference endpoint")
        node_host = urlsplit(node["endpoint_url"]).hostname
        if (node["privacy_tier"] == "local_only" and
                node_host not in config.model_api.allowed_local_hosts):
            raise HTTPException(status_code=503, detail="local node endpoint host is not allowed")
        if payload.get("model") != node["model_id"]:
            raise HTTPException(status_code=403, detail="model is not registered for selected node")
        if payload.get("stream"):
            raise HTTPException(status_code=422, detail="streaming is not enabled for this proxy")
        reservation_id = None
        quote = None
        if node["billing_mode"] == "paid":
            try:
                quote = model_quote(node["pricing_model"])
            except SpendError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            output_limit = payload.get("max_tokens", payload.get("max_completion_tokens"))
            if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 0 < output_limit <= quote.max_total_tokens:
                raise HTTPException(status_code=422, detail="paid inference requires a bounded max_tokens")
        elif node["billing_mode"] != "free":
            raise HTTPException(status_code=503, detail="model node billing mode is invalid")
        is_remote = node["privacy_tier"] != "local_only"
        try:
            if is_remote:
                if not all(node[key] for key in ("ca_cert_path", "client_cert_path", "client_key_path")):
                    raise HTTPException(status_code=503, detail="remote node mTLS bundle is incomplete")
                context = ssl.create_default_context(cafile=node["ca_cert_path"])
                context.load_cert_chain(node["client_cert_path"], node["client_key_path"])
                context.check_hostname = True
            else:
                context = True
        except (OSError, ssl.SSLError) as exc:
            raise HTTPException(status_code=503, detail="model node TLS bundle cannot be loaded") from exc
        if quote is not None:
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if budget_requires_approval(db, identity.task_id, quote.reserve_cents,
                                            utcnow(), config.spend.reset_timezone):
                    raise HTTPException(status_code=403, detail="paid inference requires an operator budget or approval")
                reservation_id = str(uuid4())
                db.execute("""INSERT INTO quota_records(record_id,task_id,node_id,source_type,
                    amount_cents,reserved_cents,status,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                    (reservation_id, identity.task_id, node_id, "model_inference",
                     quote.reserve_cents, quote.reserve_cents, "reserved", utcnow().isoformat()))
        target = node["endpoint_url"].rstrip("/")
        if not target.endswith("/v1"):
            target += "/v1"
        try:
            client = client_factory(context) if client_factory else httpx.Client(verify=context, timeout=120)
            with client:
                response = client.post(target + "/chat/completions", json=payload)
                response.raise_for_status()
                result = response.json()
        except (httpx.HTTPError, ValueError, OSError, ssl.SSLError) as exc:
            raise HTTPException(status_code=502, detail="model node request failed") from exc
        if reservation_id is not None:
            usage = result.get("usage") if isinstance(result, dict) else None
            if isinstance(usage, dict):
                prompt_units = usage.get("prompt_tokens")
                completion_units = usage.get("completion_tokens")
                if (type(prompt_units) is int and type(completion_units) is int and
                        prompt_units >= 0 and completion_units >= 0 and
                        prompt_units + completion_units <= quote.max_total_tokens):
                    cost = (Decimal(prompt_units) * quote.input_rate_per_1k_usd +
                            Decimal(completion_units) * quote.output_rate_per_1k_usd) / Decimal(10)
                    settled_cents = int(cost.to_integral_value(rounding=ROUND_CEILING))
                    if settled_cents <= quote.reserve_cents:
                        with store.connect() as db:
                            db.execute("""UPDATE quota_records SET amount_cents=?,actual_units=?,status='settled'
                                WHERE record_id=? AND status='reserved'""",
                                (settled_cents, prompt_units + completion_units, reservation_id))
        with store.connect() as db:
            db.execute("""INSERT INTO workload_placements
                (placement_id,task_id,node_id,model_id,status,created_at)
                VALUES (?,?,?,?,?,?)""",
                (str(uuid4()), identity.task_id, node_id, node["model_id"],
                 "completed", utcnow().isoformat()))
        return JSONResponse(result)

    return app
