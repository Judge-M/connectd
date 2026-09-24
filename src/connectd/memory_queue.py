"""Durable, fail-closed evaluation of proposed cross-task memory."""

import asyncio
import json
import logging
from datetime import timedelta
from threading import Event

from connectd.config import ConnectdConfig
from connectd.governance import utcnow
from connectd.memory import _validity, effective_memory_authority
from connectd.memory_evaluator import LibrarianEvaluator, make_evaluator
from connectd.store import Store


logger = logging.getLogger(__name__)


class MemoryEvaluationQueue:
    def __init__(self, store: Store, config: ConnectdConfig,
                 evaluator: LibrarianEvaluator | None = None):
        self.store = store
        self.config = config
        self.evaluator = evaluator or make_evaluator(config.memory.evaluator)

    def _finish(self, job_id: str, status: str, reason: str,
                score: float | None = None) -> None:
        with self.store.connect() as db:
            db.execute("""UPDATE memory_evaluation_jobs SET status=?,reason=?,
                evaluator_score=?,updated_at=? WHERE job_id=? AND status='evaluating'""",
                (status, reason[:2000], score, utcnow().isoformat(), job_id))

    def process_one(self) -> bool:
        # No configured independent assessor means no candidate can gain authority.
        if self.config.memory.evaluator.type == "fail_closed":
            return False
        now = utcnow().isoformat()
        stale_before = (utcnow() - timedelta(minutes=5)).isoformat()
        with self.store.connect() as db:
            job = db.execute("""SELECT * FROM memory_evaluation_jobs
                WHERE status='pending' OR (status='evaluating' AND updated_at<?)
                ORDER BY created_at,job_id LIMIT 1""", (stale_before,)).fetchone()
            if job is None:
                return False
            claimed = db.execute("""UPDATE memory_evaluation_jobs SET status='evaluating',
                updated_at=? WHERE job_id=? AND (status='pending' OR
                (status='evaluating' AND updated_at<?))""",
                (now, job["job_id"], stale_before))
            if claimed.rowcount != 1:
                return False
            source = db.execute("""SELECT c.*,t.privacy_class,t.execution_profile,
                o.memory_authority,o.allow_remote_librarian FROM memory_claims c
                JOIN tasks t ON t.task_id=c.task_id
                JOIN organizations o ON o.org_id=c.org_id
                WHERE c.claim_id=? AND c.org_id=?""",
                (job["source_claim_id"], job["org_id"])).fetchone()
            candidate = db.execute("""SELECT claim_id,status,scope FROM memory_claims
                WHERE claim_id=? AND org_id=?""",
                (job["candidate_claim_id"], job["org_id"])).fetchone()
            sources = db.execute("""SELECT source_uri,source_hash,origin,title,location
                FROM claim_provenance WHERE claim_id=? ORDER BY created_at,provenance_id""",
                (job["source_claim_id"],)).fetchall()
            existing = db.execute("""SELECT claim_text FROM memory_claims WHERE org_id=?
                AND scope=? AND status='promoted' AND is_trusted=TRUE
                ORDER BY created_at,claim_id LIMIT 100""",
                (job["org_id"], f"org:{job['org_id']}")).fetchall()
            open_conflict = db.execute("""SELECT 1 FROM claim_contradictions
                WHERE status='open' AND (existing_claim_id IN (?,?) OR
                new_claim_id IN (?,?)) LIMIT 1""",
                (job["source_claim_id"], job["candidate_claim_id"],
                 job["source_claim_id"], job["candidate_claim_id"])).fetchone()
        if source is None or candidate is None or candidate["status"] != "pending":
            self._finish(job["job_id"], "review_required", "claim lineage is unavailable")
            return True
        if candidate["scope"] != f"org:{job['org_id']}":
            self._finish(job["job_id"], "review_required", "candidate scope changed")
            return True
        profile = self.config.execution_profiles.get(source["execution_profile"])
        try:
            authority = effective_memory_authority(
                source["memory_authority"], profile.memory_authority.value if profile else "")
        except ValueError:
            authority = "human_gated"
        if authority != "session_auto" or source["status"] != "promoted":
            self._finish(job["job_id"], "review_required", "automatic promotion is not permitted")
            return True
        if source["privacy_class"] not in self.config.memory.evaluator.allowed_privacy_classes:
            self._finish(job["job_id"], "review_required", "privacy class is not allowed for librarian")
            return True
        if self.config.memory.evaluator.remote_endpoint() and not (
                self.config.memory.evaluator.allow_remote_https and
                source["allow_remote_librarian"]):
            self._finish(job["job_id"], "pending",
                         "remote librarian requires daemon setting and organization admin consent")
            return False
        if _validity(source["valid_until"], source["valid_from"]) != "current" or source["superseded_by"]:
            self._finish(job["job_id"], "review_required", "source claim is not currently valid")
            return True
        if not sources:
            self._finish(job["job_id"], "review_required", "source provenance is required")
            return True
        if open_conflict is not None:
            self._finish(job["job_id"], "review_required", "claim has an open contradiction")
            return True
        try:
            assessment = asyncio.run(self.evaluator.evaluate_claim(
                source["claim_text"],
                json.dumps([dict(item.row._mapping) for item in sources], sort_keys=True),
                [item["claim_text"] for item in existing]))
        except Exception as exc:
            # Transport and parser failures never promote; a future poll may retry.
            self._finish(job["job_id"], "pending", f"evaluator unavailable: {type(exc).__name__}")
            return False
        approved = (assessment.is_corroborated and not assessment.contradiction_detected and
                    assessment.confidence_score >= self.config.memory.evaluator.confidence_threshold)
        reason = assessment.reasoning_summary
        if not approved:
            self._finish(job["job_id"], "review_required", reason,
                         assessment.confidence_score)
            return True
        with self.store.connect() as db:
            current = db.execute("""SELECT o.memory_authority,o.allow_remote_librarian,
                t.execution_profile,
                c.status AS source_status FROM memory_evaluation_jobs j
                JOIN memory_claims c ON c.claim_id=j.source_claim_id
                JOIN tasks t ON t.task_id=c.task_id
                JOIN organizations o ON o.org_id=j.org_id
                WHERE j.job_id=? AND j.status='evaluating'""",
                (job["job_id"],)).fetchone()
            profile = (self.config.execution_profiles.get(current["execution_profile"])
                       if current else None)
            if (current is None or profile is None or current["source_status"] != "promoted" or
                    (self.config.memory.evaluator.remote_endpoint() and not (
                        self.config.memory.evaluator.allow_remote_https and
                        current["allow_remote_librarian"])) or
                    effective_memory_authority(current["memory_authority"],
                                               profile.memory_authority.value) != "session_auto"):
                db.execute("""UPDATE memory_evaluation_jobs SET status='review_required',
                    reason=?,updated_at=? WHERE job_id=? AND status='evaluating'""",
                    ("automatic promotion policy changed", utcnow().isoformat(), job["job_id"]))
                return True
            promoted = db.execute("""UPDATE memory_claims SET status='promoted',
                is_trusted=TRUE,confidence=?,confidence_label='verified',
                promoted_by='independent_librarian',last_verified_at=?
                WHERE claim_id=? AND org_id=? AND status='pending'""",
                (assessment.confidence_score, utcnow().isoformat(),
                 job["candidate_claim_id"], job["org_id"]))
            if promoted.rowcount != 1:
                raise RuntimeError("memory candidate changed during evaluation")
            db.execute("""UPDATE memory_evaluation_jobs SET status='promoted',reason=?,
                evaluator_score=?,updated_at=? WHERE job_id=? AND status='evaluating'""",
                (reason[:2000], assessment.confidence_score,
                 utcnow().isoformat(), job["job_id"]))
        return True

    def run_until(self, stopped: Event) -> None:
        while not stopped.is_set():
            try:
                while self.process_one():
                    if stopped.is_set():
                        return
            except Exception:
                # The next poll retries pending jobs; errors cannot grant authority.
                logger.exception("librarian queue cycle failed")
            stopped.wait(self.config.memory.evaluator.poll_interval_seconds)
