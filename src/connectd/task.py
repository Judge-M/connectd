"""Durable task steps with single-claimer leases and compact result summaries."""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from connectd.compute import PrivacyClass
from connectd.governance import utcnow
from connectd.store import Store


class LeaseError(Exception):
    pass


@dataclass(frozen=True)
class Lease:
    step_id: str
    task_id: str
    instruction: str
    worker_id: str
    token: str
    expires_at: str


class TaskManager:
    def __init__(self, store: Store):
        self.store = store

    def create_task(self, title: str, privacy: PrivacyClass, memory_scope: str,
                    execution_profile: str = "balanced", goal: str = "", priority: str = "normal",
                    created_by: str = "operator", metadata_json: str = "{}") -> str:
        task_id = str(uuid.uuid4())
        now = utcnow().isoformat()
        with self.store.connect() as db:
            db.execute("""INSERT INTO tasks(task_id,title,goal,priority,created_by,metadata_json,
                privacy_class,memory_scope,execution_profile,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (task_id, title, goal, priority, created_by,
                metadata_json, privacy.value, memory_scope, execution_profile, now, now))
        return task_id

    def add_step(self, task_id: str, instruction: str) -> str:
        step_id = str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute("SELECT is_terminal FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if task is None or task["is_terminal"]:
                raise LeaseError("task is missing or terminal")
            next_number = db.execute("SELECT COALESCE(MAX(step_number),0)+1 FROM task_steps WHERE task_id=?", (task_id,)).fetchone()[0]
            db.execute("INSERT INTO task_steps(step_id,task_id,step_number,instruction) VALUES (?,?,?,?)",
                       (step_id, task_id, next_number, instruction))
            db.commit()
        return step_id

    def claim(self, step_id: str, worker_id: str, lease_seconds: int = 120) -> Lease:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        now = utcnow()
        expires = (now + timedelta(seconds=lease_seconds)).isoformat()
        token = str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            step = db.execute("""SELECT s.task_id,s.instruction,s.status,s.lease_expires_at,t.is_terminal
                FROM task_steps s JOIN tasks t ON t.task_id=s.task_id WHERE s.step_id=?""", (step_id,)).fetchone()
            if step is None or not (step["status"] == "pending" or
                                    (step["status"] == "claimed" and step["lease_expires_at"] < now.isoformat())) or step["is_terminal"]:
                raise LeaseError("step unavailable")
            updated = db.execute("""UPDATE task_steps SET status='claimed', assigned_worker_id=?, lease_token=?, lease_expires_at=?
                WHERE step_id=? AND (status='pending' OR (status='claimed' AND lease_expires_at<?))""",
                (worker_id, token, expires, step_id, now.isoformat()))
            if updated.rowcount != 1:
                raise LeaseError("step unavailable")
            db.commit()
            return Lease(step_id, step["task_id"], step["instruction"], worker_id, token, expires)

    def complete(self, lease: Lease, summary: str) -> None:
        self.finish(lease, summary, "done")

    def finish(self, lease: Lease, summary: str, status: str) -> None:
        if status not in ("done", "failed"):
            raise ValueError("invalid terminal step status")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute("""UPDATE task_steps SET status=?, result_summary=?, lease_token=NULL,
                lease_expires_at=NULL WHERE step_id=? AND status='claimed' AND assigned_worker_id=?
                AND lease_token=? AND lease_expires_at>?""",
                (status, summary, lease.step_id, lease.worker_id, lease.token, utcnow().isoformat()))
            if result.rowcount != 1:
                raise LeaseError("lease missing, stale, or expired")
            db.commit()

    def record_artifact(self, task_id: str, kind: str, path: str, content: bytes) -> str:
        artifact_id = str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?)",
                       (artifact_id, task_id, kind, path, hashlib.sha256(content).hexdigest(), utcnow().isoformat()))
        return artifact_id
