"""Separate operator identity and task-bound worker sessions."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from connectd.governance import utcnow
from connectd.store import Store


class AuthenticationError(Exception):
    pass


@dataclass(frozen=True)
class OperatorIdentity:
    user_id: str
    org_id: str | None
    role: str
    bootstrap: bool = False


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

    def require_operator(self, token: str, minimum_role: str = "operator") -> OperatorIdentity:
        ranks = {"viewer": 0, "operator": 1, "admin": 2, "daemon_admin": 3}
        if minimum_role not in ranks:
            raise ValueError("unknown minimum role")
        actual = hashlib.sha256(token.encode()).digest()
        bootstrap_match = hmac.compare_digest(actual, self._operator_token_hash)
        token_hash = actual.hex()
        with self.store.connect() as db:
            genesis_done = db.execute("SELECT 1 FROM daemon_admins LIMIT 1").fetchone()
            if bootstrap_match:
                if genesis_done is None:
                    return OperatorIdentity("bootstrap", None, "admin", True)
                raise AuthenticationError("bootstrap token expired after genesis")
            system_admin = db.execute("""SELECT admin_id,active FROM daemon_admins
                WHERE token_hash=?""", (token_hash,)).fetchone()
            if system_admin is not None:
                if system_admin["active"] and ranks["daemon_admin"] >= ranks[minimum_role]:
                    return OperatorIdentity(system_admin["admin_id"], None,
                                            "daemon_admin")
                raise AuthenticationError("daemon administrator is inactive")
            row = db.execute("""SELECT user_id,org_id,role,active FROM operator_users
                WHERE token_hash=?""", (token_hash,)).fetchone()
        if row is None or not row["active"] or ranks.get(row["role"], -1) < ranks[minimum_role]:
            raise AuthenticationError("operator authentication failed")
        return OperatorIdentity(row["user_id"], row["org_id"], row["role"])

    def genesis(self, display_name: str) -> tuple[str, str]:
        if not display_name.strip():
            raise ValueError("daemon administrator name is required")
        token = "sys_" + secrets.token_urlsafe(32)
        admin_id = str(uuid4())
        with self.store.connect() as db:
            if db.execute("SELECT 1 FROM daemon_admins LIMIT 1").fetchone():
                raise ValueError("genesis has already completed")
            db.execute("""INSERT INTO daemon_admins(admin_id,display_name,token_hash,
                created_at) VALUES (?,?,?,?)""",
                (admin_id, display_name.strip(), hashlib.sha256(token.encode()).hexdigest(),
                 utcnow().isoformat()))
        return admin_id, token

    def issue_operator(self, org_id: str, display_name: str, role: str) -> tuple[str, str]:
        if role not in {"admin", "operator", "viewer"}:
            raise ValueError("invalid operator role")
        token = "op_" + secrets.token_urlsafe(32)
        user_id = str(uuid4())
        with self.store.connect() as db:
            db.execute("""INSERT INTO operator_users(user_id,org_id,display_name,role,
                token_hash,created_at) VALUES (?,?,?,?,?,?)""",
                (user_id, org_id, display_name, role,
                 hashlib.sha256(token.encode()).hexdigest(), utcnow().isoformat()))
        return user_id, token

    def revoke_operator(self, org_id: str, user_id: str) -> bool:
        with self.store.connect() as db:
            changed = db.execute("""UPDATE operator_users SET active=FALSE
                WHERE org_id=? AND user_id=? AND active=TRUE""", (org_id, user_id))
        return changed.rowcount == 1

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
