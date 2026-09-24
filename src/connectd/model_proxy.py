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
from connectd.spend import SpendError, bounded_model_call, budget_requires_approval, model_quote
from connectd.token_count import TokenizerError, count_prompt_tokens


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
                            config.secret_sensitive_allowed_node_ids,
                            model_id=payload.get("model"),
                            max_health_age_seconds=config.compute.health_interval_seconds * 3)
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
        prompt_bound = None
        reserved_cents = None
        call_payload = dict(payload)
        if node["billing_mode"] == "paid":
            allowed_fields = {"model", "messages", "tools", "tool_choice", "max_tokens", "stream"}
            if set(payload) - allowed_fields:
                raise HTTPException(status_code=422, detail="paid inference payload contains unsupported fields")
            try:
                quote = model_quote(node["pricing_model"])
            except SpendError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            output_limit = payload.get("max_tokens")
            if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 0 < output_limit <= quote.max_total_tokens:
                raise HTTPException(status_code=422, detail="paid inference requires a bounded max_tokens")
            preflight_url = node["preflight_url"]
            try:
                inference_origin = urlsplit(node["endpoint_url"])
                preflight_origin = urlsplit(preflight_url) if preflight_url else None
                valid_preflight = (preflight_origin is not None and
                    (preflight_origin.scheme, preflight_origin.hostname, preflight_origin.port) ==
                    (inference_origin.scheme, inference_origin.hostname, inference_origin.port) and
                    bool(preflight_origin.path) and not preflight_origin.query and
                    not preflight_origin.fragment and not preflight_origin.username and
                    not preflight_origin.password)
            except ValueError:
                valid_preflight = False
            if not valid_preflight:
                raise HTTPException(status_code=503, detail="paid node has no trusted token-count preflight")
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
            try:
                counter = client_factory(context) if client_factory else httpx.Client(verify=context, timeout=30)
                with counter:
                    preflight = counter.post(preflight_url, json=payload)
                    preflight.raise_for_status()
                    counted = preflight.json()
                prompt_bound = counted.get("input_tokens") if isinstance(counted, dict) else None
                if type(prompt_bound) is not int or prompt_bound < 0:
                    raise ValueError("invalid preflight token count")
                if node["tokenizer_json"]:
                    prompt_bound = max(prompt_bound, count_prompt_tokens(payload, node["tokenizer_json"]))
            except (httpx.HTTPError, ValueError, OSError, ssl.SSLError, TokenizerError) as exc:
                raise HTTPException(status_code=503, detail="paid model token preflight failed") from exc
            try:
                clamped_output, reserved_cents = bounded_model_call(quote, prompt_bound, output_limit)
            except SpendError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            call_payload["max_tokens"] = clamped_output
        if quote is not None:
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if store.engine.dialect.name == "postgresql":
                    db.execute("SELECT task_id FROM tasks WHERE task_id=? FOR UPDATE",
                               (identity.task_id,)).fetchone()
                if budget_requires_approval(db, identity.task_id, reserved_cents,
                                            utcnow(), config.spend.reset_timezone):
                    raise HTTPException(status_code=403, detail="paid inference requires an operator budget or approval")
                reservation_id = str(uuid4())
                db.execute("""INSERT INTO quota_records(record_id,task_id,node_id,source_type,
                    amount_cents,reserved_cents,status,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                    (reservation_id, identity.task_id, node_id, "model_inference",
                     reserved_cents, reserved_cents, "reserved", utcnow().isoformat()))
        target = node["endpoint_url"].rstrip("/")
        if not target.endswith("/v1"):
            target += "/v1"
        try:
            client = client_factory(context) if client_factory else httpx.Client(verify=context, timeout=120)
            with client:
                response = client.post(target + "/chat/completions", json=call_payload)
                response.raise_for_status()
                result = response.json()
        except (httpx.HTTPError, ValueError, OSError, ssl.SSLError) as exc:
            raise HTTPException(status_code=502, detail="model node request failed") from exc
        if reservation_id is not None:
            usage = result.get("usage") if isinstance(result, dict) else None
            prompt_units = usage.get("prompt_tokens") if isinstance(usage, dict) else None
            completion_units = usage.get("completion_tokens") if isinstance(usage, dict) else None
            if (type(prompt_units) is not int or type(completion_units) is not int or
                    prompt_units < 0 or completion_units < 0 or
                    prompt_units > prompt_bound or completion_units > call_payload["max_tokens"]):
                with store.connect() as db:
                    db.execute("UPDATE compute_nodes SET healthy=FALSE WHERE node_id=?", (node_id,))
                raise HTTPException(status_code=502, detail="model usage violated the registered token bound")
            cost = (Decimal(prompt_units) * quote.input_rate_per_1k_usd +
                    Decimal(completion_units) * quote.output_rate_per_1k_usd) / Decimal(10)
            settled_cents = int(cost.to_integral_value(rounding=ROUND_CEILING))
            if settled_cents > reserved_cents:
                with store.connect() as db:
                    db.execute("UPDATE compute_nodes SET healthy=FALSE WHERE node_id=?", (node_id,))
                raise HTTPException(status_code=502, detail="model charge exceeded the reserved cap")
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
