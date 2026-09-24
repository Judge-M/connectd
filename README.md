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
- Task-scoped daily, weekly, and monthly spend budgets. Financial Tier 2 grants reserve registry-declared fixed costs; missing or exceeded budgets require an exact operator approval in every profile.

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

Set `daemon.signing_key_path` to the key path. The API binds to loopback by default. Visit `http://127.0.0.1:8790/control` and enter the operator token for the current tab. Operators can create tasks, inspect audit timelines, and promote candidate memories there. The API also supports direct clients with `Authorization: Bearer <token>`.

Register a healthy compute node before dispatching a step. A `secret_sensitive` task uses only an air-gapped local node by default. Remote node records need an HTTPS endpoint, model ID, allowed privacy classes, and per-node mTLS CA/client certificate/key paths. Explicitly allowlist any remote node permitted to receive secret-sensitive requests.

The default `connectd worker run-step` path asks Laya/Jev to route the step, then launches the worker with the single selected tool schema. A specific `--tool` can be supplied to bypass routing for a controlled run. `workbench` supports bounded worktree reads, writes, and local commands; additional external handlers must be registered by the daemon application before they are callable.

## Production container boundary

`compose.prod-secure.yaml` places gateway and model proxy on a named internal Docker network. Workers launched by the host attach only to that network and reach `connectd-gateway` and `model-api` through Docker DNS. The model engine image, model ID, signing key, and operator token are required deployment inputs. For example:

```sh
docker build -f Dockerfile.worker -t connectd-worker:local .
docker compose -f compose.prod-secure.yaml config
docker compose -f compose.prod-secure.yaml up --build -d
```

The host-side `connectd worker run-step` command needs access to the Docker engine; the gateway container does not mount its socket. `prod_secure` fails closed if its container runtime or internal network is missing. The routing target of under 100 ms for local Laya is a measurement goal, not a guaranteed latency on every host.

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

## Tests

```sh
python -m unittest discover -s tests -v
```

Set `CONNECTD_TEST_POSTGRES_URL` to an isolated PostgreSQL database URL to include that integration test. CI runs both engines. Containerized Laya/model execution and the local routing latency target require deployment hardware and an operator-configured model endpoint.
