"""Human-promoted claims with provenance and validity metadata."""

import json
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


class MemoryLedger:
    def __init__(self, store: Store):
        self.store = store

    def capture(self, scope: str, claim_text: str, origin: str, *,
                confidence: float | None = None, confidence_label: str | None = None,
                valid_from: str | None = None, valid_until: str | None = None,
                tags: list[str] | None = None, sources: list[dict] | None = None,
                org_id: str = "default") -> str:
        if confidence is not None and not 0 <= confidence <= 1:
            raise ValueError("confidence must be in [0,1]")
        if confidence_label is not None and confidence_label not in {"low", "medium", "high", "verified"}:
            raise ValueError("invalid confidence label")
        claim_id = str(uuid.uuid4())
        now = utcnow().isoformat()
        with self.store.connect() as db:
            db.execute("""INSERT INTO memory_claims(claim_id,org_id,scope,claim_text,status,is_trusted,origin,
                created_at,confidence,confidence_label,valid_from,valid_until,tags_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (claim_id, org_id, scope, claim_text, "pending", False, origin, now,
                 confidence, confidence_label, valid_from, valid_until, json.dumps(tags or [])))
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

    def recall_records(self, scope: str, *, include_pending: bool = False,
                       trusted_only: bool = True, active_only: bool = False,
                       max_items: int = 8, org_id: str = "default") -> list[dict]:
        if not 1 <= max_items <= 100:
            raise ValueError("max_items must be in [1,100]")
        with self.store.connect() as db:
            rows = db.execute("""SELECT * FROM memory_claims WHERE org_id=? AND scope IN (?,?,?)
                ORDER BY created_at,claim_id""", (org_id, scope, "global", "global:")).fetchall()
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

    def recall(self, scope: str, org_id: str = "default") -> list[str]:
        return [item["text"] for item in self.recall_records(
            scope, active_only=True, org_id=org_id)]
