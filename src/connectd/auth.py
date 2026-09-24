"""Separate operator identity and task-bound worker sessions."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

from connectd.governance import utcnow
from connectd.store import Store


class AuthenticationError(Exception):
    pass


@dataclass(frozen=True)
class WorkerIdentity:
    task_id: str
    worker_id: str


class AuthService:
    def __init__(self, store: Store, operator_token: str):
        if len(operator_token) < 32:
            raise ValueError("operator token must have at least 32 characters")
        self.store = store
        self._operator_token_hash = hashlib.sha256(operator_token.encode()).digest()

    def require_operator(self, token: str) -> None:
        actual = hashlib.sha256(token.encode()).digest()
        if not hmac.compare_digest(actual, self._operator_token_hash):
            raise AuthenticationError("operator authentication failed")

    def issue_worker(self, task_id: str, worker_id: str, ttl_seconds: int = 3600) -> str:
        if not 1 <= ttl_seconds <= 86400:
            raise ValueError("ttl_seconds must be between 1 and 86400")
        token = "act_" + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.store.connect() as db:
            db.execute("INSERT INTO worker_sessions VALUES (?,?,?,?,FALSE)",
                       (token_hash, task_id, worker_id, (utcnow() + timedelta(seconds=ttl_seconds)).isoformat()))
        return token

    def require_worker(self, token: str, task_id: str | None = None) -> WorkerIdentity:
        if not token.startswith("act_"):
            raise AuthenticationError("worker token required")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.store.connect() as db:
            row = db.execute("SELECT task_id,worker_id,expires_at,revoked FROM worker_sessions WHERE token_hash=?",
                             (token_hash,)).fetchone()
        if row is None or row["revoked"] or row["expires_at"] <= utcnow().isoformat():
            raise AuthenticationError("worker session missing or expired")
        if task_id is not None and row["task_id"] != task_id:
            raise AuthenticationError("worker session has the wrong task scope")
        return WorkerIdentity(row["task_id"], row["worker_id"])

    def revoke_worker(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.store.connect() as db:
            db.execute("UPDATE worker_sessions SET revoked=TRUE WHERE token_hash=?", (token_hash,))
