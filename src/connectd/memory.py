"""Human-promoted persistent claims; session memory stays outside this ledger."""

import uuid

from connectd.governance import utcnow
from connectd.store import Store


class MemoryLedger:
    def __init__(self, store: Store):
        self.store = store

    def capture(self, scope: str, claim_text: str, origin: str) -> str:
        claim_id = str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute("INSERT INTO memory_claims VALUES (?,?,?,?,?,?,?,?)",
                       (claim_id, scope, claim_text, "pending", False, origin, None, utcnow().isoformat()))
        return claim_id

    def promote(self, claim_id: str, human_operator_id: str) -> None:
        if not human_operator_id:
            raise ValueError("human_operator_id is required")
        with self.store.connect() as db:
            result = db.execute("""UPDATE memory_claims SET status='promoted', is_trusted=TRUE, promoted_by=?
                WHERE claim_id=? AND status='pending'""", (human_operator_id, claim_id))
            if result.rowcount != 1:
                raise ValueError("claim missing or no longer pending")

    def recall(self, scope: str) -> list[str]:
        with self.store.connect() as db:
            return [row[0] for row in db.execute(
                """SELECT claim_text FROM memory_claims AS c WHERE scope=? AND status='promoted' AND is_trusted=TRUE
                AND NOT EXISTS (SELECT 1 FROM claim_contradictions AS x WHERE x.status='open'
                    AND (x.existing_claim_id=c.claim_id OR x.new_claim_id=c.claim_id))
                ORDER BY created_at""",
                (scope,))]
