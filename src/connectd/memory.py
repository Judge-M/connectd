"""Human-promoted claims with provenance and validity metadata."""

import json
import hashlib
import uuid
from datetime import datetime

from connectd.governance import utcnow
from connectd.store import Store


def _parse_date(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _validity(valid_until: str | None, valid_from: str | None = None) -> str:
    start, end = _parse_date(valid_from), _parse_date(valid_until)
    if (valid_from and start is None) or (valid_until and end is None):
        return "unknown"
    now = utcnow()
    if start and start > now:
        return "not_yet_valid"
    if end and end < now:
        return "stale"
    return "current"


_AUTHORITY_RANK = {"session_auto": 1, "hybrid": 2, "human_gated": 3}


def effective_memory_authority(org_setting: str, profile_setting: str) -> str:
    """Choose the more restrictive policy; unknown values fail closed."""
    if org_setting not in _AUTHORITY_RANK or profile_setting not in _AUTHORITY_RANK:
        raise ValueError("unknown memory authority")
    return (org_setting if _AUTHORITY_RANK[org_setting] >= _AUTHORITY_RANK[profile_setting]
            else profile_setting)


class MemoryLedger:
    def __init__(self, store: Store):
        self.store = store

    def capture(self, scope: str, claim_text: str, origin: str, *,
                confidence: float | None = None, confidence_label: str | None = None,
                valid_from: str | None = None, valid_until: str | None = None,
                tags: list[str] | None = None, sources: list[dict] | None = None,
                org_id: str = "default", task_id: str | None = None,
                auto_promote: bool = False) -> str:
        if confidence is not None and not 0 <= confidence <= 1:
            raise ValueError("confidence must be in [0,1]")
        if confidence_label is not None and confidence_label not in {"low", "medium", "high", "verified"}:
            raise ValueError("invalid confidence label")
        if auto_promote and task_id is None:
            raise ValueError("automatic promotion requires a task")
        if task_id is not None and scope != f"task:{task_id}":
            raise ValueError("task claim must use its task scope")
        claim_id = str(uuid.uuid4())
        now = utcnow().isoformat()
        with self.store.connect() as db:
            if task_id is not None:
                task = db.execute("SELECT org_id,is_terminal FROM tasks WHERE task_id=?",
                                  (task_id,)).fetchone()
                if task is None or task["org_id"] != org_id or task["is_terminal"]:
                    raise ValueError("task memory requires an active task in the same organization")
            db.execute("""INSERT INTO memory_claims(claim_id,org_id,task_id,scope,claim_text,
                status,is_trusted,origin,promoted_by,created_at,confidence,confidence_label,
                valid_from,valid_until,last_verified_at,tags_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (claim_id, org_id, task_id, scope, claim_text,
                 "promoted" if auto_promote else "pending", auto_promote, origin,
                 "task_policy" if auto_promote else None, now, confidence,
                 confidence_label, valid_from, valid_until,
                 now if auto_promote else None, json.dumps(tags or [])))
            for source in sources or []:
                db.execute("""INSERT INTO claim_provenance(provenance_id,claim_id,source_uri,
                    source_hash,created_at,source_id,origin,title,location,mime_type)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), claim_id, source["source_uri"], source["source_hash"], now,
                     source.get("source_id"), source.get("origin"), source.get("title"),
                     source.get("location"), source.get("mime_type")))
        return claim_id

    def promote(self, claim_id: str, human_operator_id: str,
                confidence_label: str | None = None) -> None:
        if not human_operator_id:
            raise ValueError("human_operator_id is required")
        if confidence_label is not None and confidence_label not in {"low", "medium", "high", "verified"}:
            raise ValueError("invalid confidence label")
        with self.store.connect() as db:
            result = db.execute("""UPDATE memory_claims SET status='promoted', is_trusted=TRUE,
                promoted_by=?,confidence_label=COALESCE(?,confidence_label),last_verified_at=?
                WHERE claim_id=? AND status='pending'""",
                (human_operator_id, confidence_label, utcnow().isoformat(), claim_id))
            if result.rowcount != 1:
                raise ValueError("claim missing or no longer pending")

    def promote_to_organization(self, claim_id: str, org_id: str,
                                promoter_id: str) -> str:
        """Copy a reviewed claim into permanent org memory, preserving task history."""
        if not promoter_id:
            raise ValueError("promoter_id is required")
        new_id = str(uuid.uuid4())
        now = utcnow().isoformat()
        with self.store.connect() as db:
            source = db.execute("SELECT * FROM memory_claims WHERE claim_id=? AND org_id=?",
                                (claim_id, org_id)).fetchone()
            if source is None or source["scope"] in {"global", "global:"}:
                raise ValueError("claim is unavailable for organization promotion")
            db.execute("""INSERT INTO memory_claims(claim_id,org_id,scope,claim_text,status,
                is_trusted,origin,promoted_by,created_at,confidence,confidence_label,
                valid_from,valid_until,last_verified_at,tags_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (new_id, org_id, f"org:{org_id}", source["claim_text"], "promoted",
                 True, f"promotion:{claim_id}", promoter_id, now, source["confidence"],
                 source["confidence_label"], source["valid_from"], source["valid_until"],
                 now, source["tags_json"]))
            prior = db.execute("SELECT * FROM claim_provenance WHERE claim_id=?",
                               (claim_id,)).fetchall()
            for item in prior:
                db.execute("""INSERT INTO claim_provenance(provenance_id,claim_id,source_uri,
                    source_hash,created_at,source_id,origin,title,location,mime_type)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), new_id, item["source_uri"], item["source_hash"], now,
                     item["source_id"], item["origin"], item["title"], item["location"],
                     item["mime_type"]))
            db.execute("""INSERT INTO claim_provenance(provenance_id,claim_id,source_uri,
                source_hash,created_at,origin) VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), new_id, f"claim:{claim_id}",
                 hashlib.sha256(source["claim_text"].encode()).hexdigest(), now,
                 "promotion"))
        return new_id

    def recall_records(self, scope: str, *, include_pending: bool = False,
                       trusted_only: bool = True, active_only: bool = False,
                       max_items: int = 8, org_id: str = "default",
                       task_id: str | None = None) -> list[dict]:
        if not 1 <= max_items <= 100:
            raise ValueError("max_items must be in [1,100]")
        with self.store.connect() as db:
            scopes = [scope, f"org:{org_id}", "global", "global:"]
            if task_id is not None:
                task = db.execute("""SELECT org_id,is_terminal,memory_scope FROM tasks
                    WHERE task_id=?""", (task_id,)).fetchone()
                if task is None or task["org_id"] != org_id or task["memory_scope"] != scope:
                    raise ValueError("recall task and repository scope do not match")
                if not task["is_terminal"]:
                    scopes.append(f"task:{task_id}")
            scopes = list(dict.fromkeys(scopes))
            placeholders = ",".join("?" for _ in scopes)
            rows = db.execute(f"""SELECT * FROM memory_claims WHERE
                (org_id=? AND scope IN ({placeholders})) OR
                (scope IN ('global','global:') AND status='promoted'
                 AND is_trusted=TRUE)
                ORDER BY created_at,claim_id""",
                (org_id, *scopes)).fetchall()
            result = []
            for row in rows:
                claim = dict(row.row._mapping)
                contradictions = db.execute("""SELECT contradiction_id,status,resolution_notes
                    FROM claim_contradictions WHERE status='open'
                    AND (existing_claim_id=? OR new_claim_id=?)""",
                    (claim["claim_id"], claim["claim_id"])).fetchall()
                contradicted = bool(contradictions)
                validity = _validity(claim["valid_until"], claim["valid_from"])
                if claim["superseded_by"]:
                    validity = "superseded"
                trusted = bool(claim["is_trusted"] and claim["status"] == "promoted"
                               and not contradicted and not claim["superseded_by"])
                if trusted_only and not trusted:
                    continue
                if not include_pending and claim["status"] == "pending":
                    continue
                if active_only and validity != "current":
                    continue
                sources = db.execute("SELECT * FROM claim_provenance WHERE claim_id=? ORDER BY created_at",
                                     (claim["claim_id"],)).fetchall()
                until = claim["valid_until"]
                scope_type, _, scope_id = claim["scope"].partition(":")
                result.append({
                    "id": claim["claim_id"], "text": claim["claim_text"],
                    "status": claim["status"], "trusted": trusted,
                    "scope": {"type": scope_type, "id": scope_id},
                    "confidence": claim["confidence_label"], "confidence_score": claim["confidence"],
                    "validity": validity, "valid_from": claim["valid_from"],
                    "valid_until": until, "learned_at": claim["learned_at"],
                    "last_verified_at": claim["last_verified_at"],
                    "tags": json.loads(claim["tags_json"]),
                    "sources": [dict(source.row._mapping) for source in sources],
                    "contradicted": contradicted,
                    "contradiction_warnings": [dict(warning.row._mapping) for warning in contradictions],
                    "superseded_by": claim["superseded_by"],
                })
                if len(result) >= max_items:
                    break
        return result

    def recall(self, scope: str, org_id: str = "default",
               task_id: str | None = None) -> list[str]:
        return [item["text"] for item in self.recall_records(
            scope, active_only=True, org_id=org_id, task_id=task_id)]
