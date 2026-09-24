# connectd

`connectd` is a unified control plane for task-bound agent work. It provides one relational ledger, in-process governance, typed System-1 routing, a model transport broker, and ephemeral System-2 workers. The [master handoff](docs/connectd-master-handoff.md) records the agreed architecture and the remaining operator choices.

## What runs in V1

- SQLite and PostgreSQL through the same SQLAlchemy schema and Alembic migration.
- Authenticated `/api/v1` REST endpoints and a local operator workspace at `/control`.
- Scoped worker tokens, Cedar policy checks, exact operator approvals, and single-use Ed25519 grants verified at the Tool Gateway.
- Task steps with exclusive leases, promoted-only memory recall, and privacy-aware compute node selection.
- Typed Laya or Jev `/v1/systemone` routing with a bounded tree and one tool schema passed to each worker turn.
- A five-turn maximum, native OpenAI-compatible worker loop using a configurable capable model endpoint.
- Subprocess and Docker workers in `dev_fast`/`balanced`; an internal Docker network in `prod_secure`.
- A remote model proxy with per-node mTLS and no worker bearer forwarded to the remote node.
- Selective read-only import from AgentConnect, Connect-Governance, ToolConnect, and BrainConnect SQLite files. Historical grants are marked `legacy_expired`, and ToolConnect audit chain fields are retained.
- Task-scoped daily, weekly, and monthly spend budgets. Paid model calls and financial Tier 2 tools reserve registry-declared worst-case costs. Unconfigured or exceeded budgets block dispatch until an operator sets a budget or approves the exact tool action.

## Install and configure

Use Python 3.11 or newer:

```sh
python -m pip install -e '.[api,postgres]'
```

Edit `config/connectd.yaml` for the database URL, a persistent signing key path, a capable worker model URL and ID, and a routing confidence threshold. Start a warmed [Laya server](https://github.com/NandhaKishorM/laya) at the configured router URL, or configure Jev and its API key. The model is operator-supplied; no small CPU worker model is imposed.

Create a key and operator token in a secure location. Do not commit either:

```sh
connectd init-key --path /secure/path/connectd-signing.pem
export CONNECTD_OPERATOR_TOKEN='replace-with-a-long-random-token'
connectd db upgrade
connectd serve
```

Set `daemon.signing_key_path` to the key path. The API binds to loopback by default. Visit `http://127.0.0.1:8790/control` and enter the bootstrap operator token for the current tab. The organization setup panel creates an organization and issues one-time local user tokens with `admin`, `operator`, or `viewer` roles. Organization admins can issue and revoke users in their own organization. Organization members see only their tasks, steps, budgets, and audit timelines; operators can add steps directly from the task workspace. Workers read memory from their task's organization. Organization admins can register tools and compute nodes owned by their organization. Registry discovery, worker routing, model placement, and grant redemption check organization ownership or an explicit share. Existing and migrated entries belong to the Default organization; other organizations need a share before use. Share-management endpoints are being added. The API also supports direct clients with `Authorization: Bearer <token>`.

Register a healthy compute node before dispatching a step. A `secret_sensitive` task uses only an air-gapped local node by default. Local inference endpoint hostnames must appear in `model_api.allowed_local_hosts` (loopback and the bundled `model-engine` name by default). Direct worker inference is limited to a matching registered free local node. Paid and remote nodes use the authenticated model proxy, which shares the task spend ledger with tool calls. Remote node records need an HTTPS endpoint, model ID, allowed privacy classes, and per-node mTLS CA/client certificate/key paths. Explicitly allowlist any remote node permitted to receive secret-sensitive requests.

Remote nodes need a health source. A same-origin `health_url` is polled over the node's mTLS connection every `compute.health_interval_seconds`; the endpoint reports `status`, `available_slots`, and `loaded_models`. Alternatively, configure `compute.node_managers` with an HTTPS inventory URL, mTLS CA/client certificate/key paths, and an operator-approved `allowed_node_ids` set. Register each managed node with its `manager_id` and operator-owned endpoint, model, privacy, and pricing metadata. A manager's `GET` inventory returns `{"nodes":[{"node_id":"...","status":"healthy","available_slots":1,"loaded_models":["..."]}]}`. Unknown IDs and manager-supplied endpoints or prices never enter the registry. Missing, unhealthy, or zero-capacity nodes fail closed. Monitored nodes also require a health report from within the last three polling intervals before placement. `/control` shows the last probe and capacity report, and operators can trigger a probe directly.

Paid nodes require operator-owned pricing and a same-origin token-count preflight endpoint. The endpoint accepts the intended OpenAI-compatible chat request and returns `{"input_tokens": 123}` before inference. A provider adapter can implement this contract for any chosen model; paid inference fails closed if preflight is missing or fails. An optional local tokenizer mapping can raise the conservative bound using `tiktoken` or a SHA-256-pinned Hugging Face tokenizer JSON file. The proxy rejects prompts that reach the registered cost or context cap, clamps `max_tokens` to the remaining budget, and reserves the bounded maximum. It quarantines a node if upstream usage exceeds the admitted bound. The preflight adapter must count the exact request format used for inference and must be nonbillable; model-specific provider credentials remain behind that adapter.

The default `connectd worker run-step` path asks Laya/Jev to route the step, then launches the worker with the single selected tool schema. A specific `--tool` can be supplied to bypass routing for a controlled run. `workbench` supports bounded worktree reads, writes, and local commands. New registry entries without an in-process handler remain `disabled_unbound`; an operator can activate a reviewed handler through `/api/v1/tools/{tool_id}/activate` once the daemon has bound it. The `/api/v1/tools/binding-proposals` response and `/control` panel show imported tools, their schemas, and exact-name trusted-handler suggestions. Generating a suggestion does not activate the tool.

## Production container boundary

`compose.prod-secure.yaml` places gateway and model proxy on a named internal Docker network. Workers launched by the host attach only to that network and reach `connectd-gateway` and `model-api` through Docker DNS. The model engine image, model ID, signing key, and operator token are required deployment inputs. For example:

```sh
docker build -f Dockerfile.worker -t connectd-worker:local .
docker compose -f compose.prod-secure.yaml config
docker compose -f compose.prod-secure.yaml up --build -d
```

The host-side `connectd worker run-step` command needs access to the Docker engine; the gateway container does not mount its socket. `prod_secure` fails closed if its container runtime or internal network is missing. The routing target of under 100 ms for local Laya is a measurement goal, not a guaranteed latency on every host.

Selecting the `gvisor` worker runtime requires Docker to report an installed `runsc` runtime; otherwise dispatch stops before launching a worker. gVisor is a sandboxed container runtime. `firecracker` is a pluggable `MicroVMAdapter` contract for Linux hosts with writable `/dev/kvm`; dispatch fails closed unless an adapter is explicitly installed. The host plugin must provide its own jailed guest image and isolated transport.

The provider-neutral `ProvisioningAdapter` contract has a RunPod REST v1 reference implementation for Pod create, read, and delete operations. Its read-only quote method fetches the RunPod GPU catalog list price and availability for the requested cloud and GPU count; it excludes storage and is not a binding Pod rate. Its API key is resolved at call time from `RUNPOD_API_KEY` or an explicitly configured local env file such as `secrets/connectd.env`; the `secrets/` directory is ignored by Git. Provisioned Pods do not become trusted inference nodes automatically: operator-owned node registry metadata and mTLS health admission still apply. Paid automatic lifecycle dispatch remains gated until the pre-create price guarantee is selected.

## Legacy import

`connectd db migrate-legacy` needs all four source paths plus explicit choices for tasks without privacy metadata and retention of audit payloads. Source databases are opened read-only. The importer verifies ToolConnect hash links and records the original `prev_hash` and `record_hash`. Hash-only retention keeps those fields while omitting raw audit bodies from the unified database; full retention allows read-time payload hash verification. The source files remain available as the original evidence.

```sh
connectd db migrate-legacy \
  --agentconnect-db /legacy/agentconnect.db \
  --governance-db /legacy/governance.db \
  --toolconnect-db /legacy/toolconnect.db \
  --brainconnect-db /legacy/brainconnect.db \
  --missing-privacy-class secret_sensitive \
  --audit-payload hash-only
```

The example's privacy and payload values are explicit operator inputs, not silent importer defaults. The importer maps AgentConnect execution-record links to governance work requests and creates terminal audit-only stubs for unmatched work requests. It imports only promoted BrainConnect claims. Repeating an import against a database with legacy records is rejected without changing the imported state.

Memory recall retains confidence, validity dates, tags, source provenance, supersession, and contradiction warnings. Worker context and task-scoped recall include only currently valid, trusted promoted claims from the task or global scope. `worker_brief` projects a smaller payload. Operator `/recall`, `/api/v1/memory/recall`, and the `/control` memory ledger keep stale, superseded, and pending claims visible for audit.

## Tests

```sh
python -m unittest discover -s tests -v
```

Set `CONNECTD_TEST_POSTGRES_URL` to an isolated PostgreSQL database URL to include that integration test. CI runs both engines. Containerized Laya/model execution and the local routing latency target require deployment hardware and an operator-configured model endpoint.
