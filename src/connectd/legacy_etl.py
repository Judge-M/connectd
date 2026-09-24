"""Read-only, selective import of the 0.1.0 SQLite ledgers.

All destination writes happen in one transaction. Source connections use SQLite
URI read-only mode, and no source schema is created or modified.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from connectd.governance import utcnow
from connectd.store import Store


class LegacyImportError(ValueError):
    pass


@dataclass(frozen=True)
class LegacySources:
    agentconnect: Path
    governance: Path
    toolconnect: Path
    brainconnect: Path


def _legacy_id(source: str, table: str, key: object) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"connectd-legacy:{source}:{table}:{key}"))


def _timestamp(value: object) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    return str(value or utcnow().isoformat())


def _rows(source: sqlite3.Connection, table: str) -> list[dict]:
    if not table.replace("_", "").isalnum():
        raise LegacyImportError("invalid source table")
    exists = source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if not exists:
        return []
    return [dict(row) for row in source.execute(f'SELECT * FROM "{table}"')]


def _require_tables(source: sqlite3.Connection, names: tuple[str, ...], label: str) -> None:
    for name in names:
        if not source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                              (name,)).fetchone():
            raise LegacyImportError(f"{label} database is missing required table {name}")


def _open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise LegacyImportError(f"legacy database not found: {path}")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _record(db, source: str, table: str, key: object, row: dict, retain_payload: bool) -> None:
    if db.execute("SELECT 1 FROM legacy_records WHERE source=? AND table_name=? AND record_key=?",
                  (source, table, str(key))).fetchone():
        return
    serialized = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    db.execute("""INSERT INTO legacy_records(source,table_name,record_key,payload_json,payload_hash,imported_at)
        VALUES (?,?,?,?,?,?)""", (source, table, str(key), serialized if retain_payload else None,
                              hashlib.sha256(serialized.encode()).hexdigest(), utcnow().isoformat()))


def _stub(db, work_request_id: str) -> str:
    task_id = _legacy_id("governance", "work_requests", work_request_id)
    if not db.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone():
        db.execute("""INSERT INTO tasks(task_id,title,goal,privacy_class,memory_scope,execution_profile,
            status,is_terminal,origin,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (task_id, f"Legacy Work Request {work_request_id[:8]}",
             f"Historical audit stub for work_request {work_request_id}", "secret_sensitive",
             f"legacy:governance:{work_request_id}", "prod_secure", "legacy_audit_stub", True,
             "connect_governance_etl", utcnow().isoformat()))
    return task_id


def _audit_tool(db, source: str, name: str) -> str:
    tool_id = _legacy_id(source, "tools", name)
    if not db.execute("SELECT 1 FROM tool_registry WHERE tool_id=?", (tool_id,)).fetchone():
        db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,active,
            status,origin) VALUES (?,?,?,?,?,FALSE,?,?)""",
            (tool_id, name, f"legacy/{source}", "{}", 2, "disabled_unbound", f"{source}_etl"))
    return tool_id


def migrate_legacy(store: Store, sources: LegacySources, *, missing_privacy_class: str,
                   retain_audit_payload: bool) -> dict[str, int]:
    """Import four core domains; a rerun is rejected before any destination write."""
    allowed_privacy = {"public", "low_sensitive", "repo_sensitive", "secret_sensitive"}
    if missing_privacy_class not in allowed_privacy:
        raise LegacyImportError("missing_privacy_class must be an explicit privacy class")
    paths = [sources.agentconnect, sources.governance, sources.toolconnect, sources.brainconnect]
    if len({path.resolve() for path in paths}) != 4:
        raise LegacyImportError("each legacy source must be a distinct database")
    if store.engine.dialect.name == "sqlite":
        target = Path(store.engine.url.database).resolve()
        if target in {path.resolve() for path in paths}:
            raise LegacyImportError("a source database cannot be the destination")
    store.initialize()
    counts = {"tasks": 0, "steps": 0, "artifacts": 0, "tools": 0, "decisions": 0,
              "grants": 0, "tool_audit": 0, "memory_claims": 0, "audit_stubs": 0}
    with ExitStack() as stack:
        connections = [_open_read_only(path) for path in paths]
        for connection in connections:
            stack.callback(connection.close)
        agent, gov, tools, brain = connections
        _require_tables(agent, ("tasks",), "AgentConnect")
        _require_tables(gov, ("decision_records", "execution_grant_records"), "Connect-Governance")
        _require_tables(tools, ("audit",), "ToolConnect")
        _require_tables(brain, ("claims", "sources"), "BrainConnect")
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM legacy_records LIMIT 1").fetchone():
                raise LegacyImportError("legacy records already imported; use a fresh unified database")
            task_map: dict[str, str] = {}
            work_request_map: dict[str, str] = {}
            for row in _rows(agent, "tasks"):
                source_id = str(row["id"])
                task_id = _legacy_id("agentconnect", "tasks", source_id)
                metadata = json.loads(row.get("metadata_json") or "{}")
                privacy = metadata.get("privacy_class") or metadata.get("privacy_tier")
                if privacy is None:
                    privacy = missing_privacy_class
                if privacy not in allowed_privacy:
                    raise LegacyImportError(f"unrecognized privacy class on task {source_id}")
                terminal = row.get("status") in {"completed", "failed", "cancelled", "done"}
                status = "completed" if row.get("status") in {"completed", "done"} else (
                    "failed" if terminal else "active")
                db.execute("""INSERT INTO tasks(task_id,title,goal,priority,created_by,metadata_json,
                    privacy_class,memory_scope,execution_profile,status,is_terminal,origin,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (task_id, row["title"], row.get("goal") or "", row.get("priority") or "normal",
                     row.get("created_by") or "legacy", row.get("metadata_json") or "{}", privacy,
                     f"legacy:agentconnect:{source_id}", "prod_secure", status, terminal,
                     "agentconnect_etl", _timestamp(row.get("created_at")),
                     _timestamp(row.get("updated_at") or row.get("created_at"))))
                _record(db, "agentconnect", "tasks", source_id, row, True)
                task_map[source_id] = task_id
                counts["tasks"] += 1
            for row in _rows(agent, "execution_records"):
                work_request = row.get("work_request_id")
                if work_request and str(row["task_id"]) in task_map:
                    mapped = task_map[str(row["task_id"])]
                    previous = work_request_map.setdefault(str(work_request), mapped)
                    if previous != mapped:
                        raise LegacyImportError(f"work request {work_request} maps to multiple tasks")
            for row in _rows(agent, "subtasks"):
                parent = task_map.get(str(row["parent_task_id"]))
                if parent is None:
                    raise LegacyImportError(f"subtask {row['id']} lacks a parent task")
                step_id = _legacy_id("agentconnect", "subtasks", row["id"])
                with_number = db.execute("SELECT COALESCE(MAX(step_number),0)+1 FROM task_steps WHERE task_id=?",
                                         (parent,)).fetchone()[0]
                status = "done" if row.get("status") in {"completed", "done"} else (
                    "failed" if row.get("status") in {"failed", "cancelled"} else "pending")
                db.execute("""INSERT INTO task_steps(step_id,task_id,step_number,instruction,status)
                    VALUES (?,?,?,?,?)""", (step_id, parent, with_number,
                    row.get("instructions") or row.get("title") or "Imported step", status))
                _record(db, "agentconnect", "subtasks", row["id"], row, True)
                counts["steps"] += 1
            for row in _rows(agent, "artifacts"):
                parent = task_map.get(str(row["task_id"]))
                if parent is None:
                    raise LegacyImportError(f"artifact {row['id']} lacks a parent task")
                db.execute("""INSERT INTO artifacts(artifact_id,task_id,kind,storage_path,content_hash,created_at)
                    VALUES (?,?,?,?,?,?)""", (_legacy_id("agentconnect", "artifacts", row["id"]), parent,
                    row["type"], row["path"], None, _timestamp(row.get("created_at"))))
                _record(db, "agentconnect", "artifacts", row["id"], row, True)
                counts["artifacts"] += 1
            def task_for(work_request: object) -> str:
                key = str(work_request or "missing-work-request")
                if key in work_request_map:
                    return work_request_map[key]
                task_id = _stub(db, key)
                if key not in work_request_map:
                    counts["audit_stubs"] += 1
                    work_request_map[key] = task_id
                return task_id

            for row in _rows(tools, "tools"):
                source_id, name = str(row["source_id"]), str(row["name"])
                source_key = f"{source_id}:{name}"
                tool_id = _legacy_id("toolconnect", "tools", source_key)
                schema = json.loads(row.get("input_schema") or "{}")
                if not isinstance(schema, dict):
                    raise LegacyImportError(f"legacy tool {source_key} has invalid input schema")
                db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,
                    active,status,origin) VALUES (?,?,?,?,?,FALSE,?,?)""",
                    (tool_id, name, f"legacy/{source_id}", json.dumps(schema, sort_keys=True),
                     2, "disabled_unbound", "toolconnect_etl"))
                _record(db, "toolconnect", "tools", source_key, row, True)
                counts["tools"] += 1

            decision_map: dict[str, str] = {}
            for row in _rows(gov, "decision_records"):
                source_id = str(row["id"])
                task_id = task_for(row.get("work_request_id") or f"decision:{source_id}")
                request = json.loads(row["request_json"])
                original = str(row.get("outcome") or "").lower()
                result = "permit" if original in {"allowed", "allow", "permit", "permitted"} else "deny"
                tool_name = str(request.get("tool_id") or request.get("action") or "governance-decision")
                tool_id = _audit_tool(db, "governance", tool_name)
                decision_id = _legacy_id("governance", "decision_records", source_id)
                db.execute("""INSERT INTO governance_decisions(decision_id,task_id,principal_id,tool_id,
                    result,reason,created_at) VALUES (?,?,?,?,?,?,?)""", (decision_id, task_id,
                    str(request.get("principal_id") or "legacy"), tool_id, result,
                    f"legacy_outcome:{row.get('outcome')}", _timestamp(row.get("evaluated_at"))))
                _record(db, "governance", "decision_records", source_id, row, retain_audit_payload)
                decision_map[source_id] = decision_id
                counts["decisions"] += 1
            grant_map: dict[str, str] = {}
            for row in _rows(gov, "execution_grant_records"):
                source_id = str(row["id"])
                decision_id = decision_map.get(str(row["decision_record_id"]))
                if decision_id is None:
                    raise LegacyImportError(f"grant {source_id} lacks a decision")
                grant = json.loads(row["grant_json"])
                decision = db.execute("SELECT task_id,tool_id FROM governance_decisions WHERE decision_id=?",
                                      (decision_id,)).fetchone()
                grant_id = _legacy_id("governance", "execution_grant_records", source_id)
                db.execute("""INSERT INTO governance_grants(grant_id,decision_id,task_id,principal_id,tool_id,
                    frozen_args_hash,signature,status,issued_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (grant_id, decision_id, decision["task_id"], str(grant.get("principal_id") or "legacy"),
                     decision["tool_id"], str(grant.get("frozen_args_hash") or "legacy-unavailable"),
                     str(grant.get("signature") or ""), "legacy_expired", _timestamp(row.get("issued_at")),
                     _timestamp(row.get("not_after") or row.get("issued_at"))))
                _record(db, "governance", "execution_grant_records", source_id, row, retain_audit_payload)
                grant_map[source_id] = grant_id
                counts["grants"] += 1
            prior_hash = "0" * 64
            for row in sorted(_rows(tools, "audit"), key=lambda item: item["seq"]):
                if row["prev_hash"] != prior_hash:
                    raise LegacyImportError(f"ToolConnect audit chain link broken at seq {row['seq']}")
                expected_hash = hashlib.sha256(
                    f"{row['kind']}\x1f{row['body']}\x1f{row['created_at']}\x1f{row['prev_hash']}".encode("utf-8")
                ).hexdigest()
                if expected_hash != row["record_hash"]:
                    raise LegacyImportError(f"ToolConnect audit hash mismatch at seq {row['seq']}")
                prior_hash = row["record_hash"]
                body = json.loads(row["body"])
                if not isinstance(body, dict):
                    raise LegacyImportError(f"ToolConnect audit body is not an object at seq {row['seq']}")
                source_grant = body.get("grant_id") or body.get("execution_grant_id")
                grant_id = grant_map.get(str(source_grant)) if source_grant else None
                if grant_id:
                    grant = db.execute("SELECT task_id,tool_id FROM governance_grants WHERE grant_id=?",
                                       (grant_id,)).fetchone()
                    task_id, tool_id = grant["task_id"], grant["tool_id"]
                else:
                    task_id = (task_for(f"tool-audit:{row['seq']}")
                               if row["kind"] in {"decision", "outcome"} else None)
                    tool_id = (_audit_tool(db, "toolconnect", str(body.get("name") or "unknown-tool"))
                               if task_id else None)
                db.execute("""INSERT INTO legacy_tool_audit(seq,kind,body_json,body_hash,created_at,
                    prev_hash,record_hash,task_id,grant_id) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (row["seq"], row["kind"], row["body"] if retain_audit_payload else None,
                     hashlib.sha256(row["body"].encode()).hexdigest(), row["created_at"],
                     row["prev_hash"], row["record_hash"], task_id, grant_id))
                if row["kind"] in {"decision", "outcome"}:
                    db.execute("""INSERT INTO tool_invocation_logs(invocation_id,grant_id,task_id,tool_id,outcome,created_at)
                        VALUES (?,?,?,?,?,?)""", (_legacy_id("toolconnect", "audit", row["seq"]),
                        grant_id, task_id, tool_id, str(body.get("outcome") or row["kind"]),
                        _timestamp(row.get("created_at"))))
                _record(db, "toolconnect", "audit", row["seq"], row, retain_audit_payload)
                counts["tool_audit"] += 1
            meta = {str(row["key"]): str(row["value"]) for row in _rows(tools, "meta")}
            recorded_head = meta.get("audit_head_hash")
            if recorded_head is not None and recorded_head != prior_hash:
                raise LegacyImportError("ToolConnect audit head hash differs from imported chain")
            head_seq = meta.get("audit_head_seq")
            if head_seq is not None and int(head_seq) != (row["seq"] if counts["tool_audit"] else 0):
                raise LegacyImportError("ToolConnect audit head sequence differs from imported chain")
            sources_by_id = {row["id"]: row for row in _rows(brain, "sources")}
            contradicted_ids = set()
            for contradiction in _rows(brain, "contradictions"):
                if contradiction.get("status") == "open":
                    contradicted_ids.add(contradiction["claim_a"])
                    contradicted_ids.add(contradiction["claim_b"])
            for row in _rows(brain, "claims"):
                if (row.get("status") != "promoted" or row["id"] in contradicted_ids or
                        ("is_trusted" in row and not row["is_trusted"])):
                    continue
                source = sources_by_id.get(row["source_id"])
                if source is None:
                    raise LegacyImportError(f"promoted claim {row['id']} lacks provenance")
                claim_id = _legacy_id("brainconnect", "claims", row["id"])
                scope = f"{row.get('scope_type') or 'global'}:{row.get('scope_id') or ''}"
                db.execute("""INSERT INTO memory_claims(claim_id,scope,claim_text,status,is_trusted,origin,
                    promoted_by,created_at) VALUES (?,?,?,?,?,?,?,?)""", (claim_id, scope, row["text"],
                    "promoted", True, str(row["origin"]), row["promoted_by"],
                    _timestamp(row.get("created_at"))))
                db.execute("""INSERT INTO claim_provenance(provenance_id,claim_id,source_uri,source_hash,created_at)
                    VALUES (?,?,?,?,?)""", (_legacy_id("brainconnect", "sources", f"{row['id']}:{source['id']}"),
                    claim_id, source.get("url") or source["path"], source["hash"],
                    _timestamp(row.get("created_at"))))
                _record(db, "brainconnect", "claims", row["id"], row, True)
                _record(db, "brainconnect", "sources", source["id"], source, True)
                counts["memory_claims"] += 1
            db.commit()
    return counts
