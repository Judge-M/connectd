# connectd master handoff (V1)

This specification incorporates the operator's architecture correction of 24 September 2026. It supersedes older handoff notes wherever they prescribe a 3B–4B generative model at the gateway, a 3B/7B CPU worker ceiling, or a hard sub-100 ms target for hosted Jev. It is the implementation contract for the five phases below.

## 1. Gateway: System-1 decisions

The gateway classifies intent and traverses a bounded Ontological Augmented Generation (OAG) tree. It uses a typed decision adapter for [local Laya](https://github.com/NandhaKishorM/laya) by default or [TypeSafe Jev](https://api.typesafe.ai/docs) when configured. It does not run an open-ended text generation pass. Each hop accepts only a declared option; each route has two or three hops and resolves exactly one active tool schema for the worker turn. A malformed, low-confidence, or unavailable decision fails closed or enters an explicitly configured deterministic fallback or human review path.

Local Laya routing targets under 100 ms at steady state with warmed model weights. This is a measured target, not an assumed guarantee: latency is recorded at p50 and p95 on the deployment hardware. Hosted Jev is best effort and has no sub-100 ms guarantee. Classification is advisory for routing. Cedar, identity checks, privacy gates, and budget rules remain deterministic authority.

The claim that routing saves 90% or more prompt tokens is a benchmark hypothesis. V1 records before and after schema counts, prompt token estimates, routing latency, and misroute rates so the claim can be evaluated.

## 2. Workers: System-2 execution

Ephemeral workers receive a task-bound, Seam-compatible `Ticket`, scoped session token, one selected tool schema per turn, and a model endpoint selected under privacy policy. V1 requires the operator to configure a capable OpenAI-compatible System-2 endpoint. Smart cloud models and 32B/70B GPU models are eligible when the task's privacy policy permits them. The worker is not limited to a 3B/7B CPU model.

The default for `secret_sensitive` tasks remains an air-gapped local inference node. An operator may explicitly authorize individual rented or cloud node IDs after evaluating their security posture. Remote nodes are registry records with URL, model/context capabilities, allowed privacy classes, and per-node mTLS CA/client certificate/key paths. Remote inference uses mTLS with server hostname verification. Provider provisioning credentials stay in the secrets manager and are never forwarded in prompts or inference headers.

The default worker loop is native Python using `httpx`, `pydantic`, and OpenAI `/v1/chat/completions` tool calls. It has a bounded turn count, receives only promoted context, and returns a compact task report. `smolagents` is an optional adapter, not a mandatory dependency.

## 3. Execution profiles and network boundaries

| Profile | Runtime | Tier 2 grant path | Docker network |
| --- | --- | --- | --- |
| `dev_fast` | Subprocess or Docker | Auto-allow; signed single-use grant still records the effect | Standard bridge |
| `balanced` | Subprocess or Docker; Tier 2 upgrades to Docker | Deterministic Cedar `PERMIT` signs automatically, except an explicit human-approval rule or spend threshold | Standard bridge |
| `prod_secure` | Docker, Podman, or another configured container boundary; no subprocess | Exact operator approval plus policy permit before signing | User-defined `--internal` network |

`prod_secure` workers have no WAN route. The Tool Gateway and model API run as containers on the internal network. Workers resolve `connectd-gateway:8790` and `model-api:8090` through container DNS, with no hardcoded bridge IP. External effects pass through the Tool Gateway and require an Ed25519 grant bound to task, principal, tool, exact canonical arguments, expiry, and one redemption attempt. The gateway verifies at the point of effect and writes the audit outcome. The control-plane container has no Docker socket; a host-side launcher starts workers.

## 4. Unified storage and selective migration

V1 supports **both SQLite and PostgreSQL** at runtime through one relational schema and Alembic migrations. Foreign keys bind tasks, steps, decisions, grants, tool invocations, memory provenance, and compute placement. Cross-domain writes use database transactions.

`connectd db migrate-legacy` opens legacy 0.1.0 databases read-only and leaves their bytes untouched. V1 imports only:

1. AgentConnect tasks, steps, and linked artifacts.
2. Connect-Governance decisions and grants.
3. ToolConnect registry entries and audit logs.
4. BrainConnect promoted trusted memory claims and their provenance.

Unpromoted candidates remain in their source databases. Imported historical grants have `status='legacy_expired'` and can never be redeemed. The importer retains source identity mappings, records payload hashes, and validates foreign keys. A repeated import is rejected before changing destination records. The CLI requires explicit privacy classification for old tasks with missing metadata and explicit audit payload retention mode. New tool registry rows remain disabled until a reviewed execution handler is bound and an operator activates them.

## 5. Delivery phases

1. **Package and configuration:** consolidated `control`, `governance`, `task`, `tools`, `memory`, `compute`, `router`, and `worker` modules; reference repositories remain read-only.
2. **Storage and ETL:** unified SQLAlchemy schema, SQLite and PostgreSQL migrations, selective read-only source ETL, and import verification.
3. **Governance and APIs:** in-process Cedar PDP, task-bound identity, profiles, Ed25519 grants, operator approval, and backward-compatible external route aliases.
4. **OAG router:** typed Jev/Laya adapters, bounded choice tree, one resolved tool schema, latency/misroute telemetry, and deterministic policy separation.
5. **Worker execution:** host-side container/subprocess launcher, internal secure network, worktree-bounded worker, model-node placement with mTLS, direct tool loop, task report, and audit trail.

## Acceptance checks

- A task can be created, claimed, routed, executed, audited, and completed through the unified API using SQLite and PostgreSQL.
- A worker token cannot perform operator actions. Grants reject altered arguments, expired signatures, and replay.
- `balanced` policy permits Tier 2 without a routine human pause. `prod_secure` requires exact operator approval and rejects subprocess workers.
- A `prod_secure` worker can resolve gateway/model service names on the internal network and cannot reach the WAN directly.
- Secret-sensitive model placement is local and air-gapped by default; each remote exception is node-specific and uses mTLS.
- Legacy sources remain unchanged, historical grants cannot redeem, and unpromoted memory never enters recall.
- Routing tests assert one active schema, bounded hops, malformed-response rejection, and recorded latency. The local sub-100 ms target is verified on the target hardware before it is claimed as achieved.
