"""Deterministic admission and single-use, argument-bound Ed25519 grants."""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.exc import SQLAlchemyError

from connectd.config import ExecutionProfile, GrantMode
from connectd.store import Store
from connectd.spend import SpendError, assess_spend


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def args_hash(args: object) -> str:
    return hashlib.sha256(canonical_json(args)).hexdigest()


def signed_payload(grant: dict) -> bytes:
    return canonical_json({key: grant[key] for key in (
        "grant_id", "decision_id", "task_id", "principal_id", "tool_id",
        "frozen_args_hash", "issued_at", "expires_at"
    )})


class AuthorizationError(Exception):
    pass


class Governance:
    def __init__(self, store: Store, signing_key: Ed25519PrivateKey, profile: ExecutionProfile,
                 high_risk_policy: Callable[[str, str, str, dict], bool] | None = None,
                 profiles: dict[str, ExecutionProfile] | None = None,
                 approval_policy: Callable[[str, str, str, dict], bool] | None = None,
                 policy_evaluator=None, spend_reset_timezone: str = "UTC"):
        self.store = store
        self.signing_key = signing_key
        self.public_key: Ed25519PublicKey = signing_key.public_key()
        self.profile = profile
        self.profiles = profiles
        # The default is deny. A trusted host must supply the high-risk policy.
        self.high_risk_policy = high_risk_policy or (lambda _task, _principal, _tool, _args: False)
        self.approval_policy = approval_policy or (lambda _task, _principal, _tool, _args: False)
        self.policy_evaluator = policy_evaluator
        self.spend_reset_timezone = spend_reset_timezone

    def approve(self, task_id: str, principal_id: str, tool_id: str, args: dict,
                approved_by: str, ttl_seconds: int = 300) -> str:
        """Record a single-use operator approval for exact Tier 2 arguments."""
        if not approved_by or not 1 <= ttl_seconds <= 3600:
            raise ValueError("valid operator and TTL are required")
        approval_id = str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute("INSERT INTO governance_approvals VALUES (?,?,?,?,?,?,FALSE,?)",
                       (approval_id, task_id, principal_id, tool_id, args_hash(args),
                        (utcnow() + timedelta(seconds=ttl_seconds)).isoformat(), approved_by))
        return approval_id

    def issue(self, task_id: str, principal_id: str, tool_id: str, args: dict,
              ttl_seconds: int = 60) -> dict:
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("ttl_seconds must be between 1 and 300")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if self.store.engine.dialect.name == "postgresql":
                db.execute("SELECT task_id FROM tasks WHERE task_id=? FOR UPDATE", (task_id,)).fetchone()
            task = db.execute("SELECT privacy_class,execution_profile,is_terminal FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            tool = db.execute("SELECT * FROM tool_registry WHERE tool_id=?", (tool_id,)).fetchone()
            if task is None or task["is_terminal"] or tool is None or not tool["active"]:
                raise AuthorizationError("unknown task or inactive tool")
            profile = self.profile
            if self.profiles is not None:
                profile = self.profiles.get(task["execution_profile"])
                if profile is None:
                    raise AuthorizationError("task execution profile is unavailable")
            tier = tool["effect_tier"]
            try:
                spend = assess_spend(db, task_id, tool, utcnow(), self.spend_reset_timezone)
            except SpendError as exc:
                raise AuthorizationError(str(exc)) from exc
            if spend.financial and tier != 2:
                raise AuthorizationError("financial tools must be Tier 2")
            # dev_fast is explicitly permissive, including destructive and
            # external Tier 2 operations. The active profile must be chosen by
            # a trusted operator, never by an untrusted worker.
            allowed = tier == 0 or (tier == 1 and profile.worktree_sandbox)
            annotation_approval = False
            if tier == 2:
                if profile.grant_mode == GrantMode.AUTO_GRANT:
                    allowed = True
                elif self.policy_evaluator is not None:
                    evaluation = self.policy_evaluator(task_id, principal_id, tool_id, args)
                    allowed = evaluation.permit
                    annotation_approval = evaluation.require_human_approval
                else:
                    allowed = self.high_risk_policy(task_id, principal_id, tool_id, args)
            approval_required = (tier == 2 and (
                profile.grant_mode == GrantMode.STRICT_ED25519 or spend.approval_required or
                annotation_approval or self.approval_policy(task_id, principal_id, tool_id, args)))
            approved = None
            if approval_required:
                approved = db.execute("""SELECT approval_id FROM governance_approvals WHERE
                    task_id=? AND principal_id=? AND tool_id=? AND frozen_args_hash=?
                    AND consumed=FALSE AND expires_at>? ORDER BY expires_at LIMIT 1""",
                    (task_id, principal_id, tool_id, args_hash(args), utcnow().isoformat())).fetchone()
                allowed = allowed and approved is not None
            if profile.grant_mode == GrantMode.STRICT_ED25519 and tier > 0:
                allowed = allowed and profile.worktree_sandbox
            decision_id = str(uuid.uuid4())
            now = utcnow()
            db.execute("INSERT INTO governance_decisions VALUES (?,?,?,?,?,?,?)",
                       (decision_id, task_id, principal_id, tool_id, "permit" if allowed else "deny",
                        "policy_permit" if allowed else "policy_denied", now.isoformat()))
            if not allowed:
                db.commit()
                raise AuthorizationError("policy denied")
            grant = {
                "grant_id": str(uuid.uuid4()), "decision_id": decision_id, "task_id": task_id,
                "principal_id": principal_id, "tool_id": tool_id, "frozen_args_hash": args_hash(args),
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            }
            grant["signature"] = self.signing_key.sign(signed_payload(grant)).hex()
            db.execute("INSERT INTO governance_grants VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (grant["grant_id"], decision_id, task_id, principal_id, tool_id,
                        grant["frozen_args_hash"], grant["signature"], "issued",
                        grant["issued_at"], grant["expires_at"]))
            if approval_required:
                consumed = db.execute("UPDATE governance_approvals SET consumed=TRUE WHERE approval_id=? AND consumed=FALSE",
                                      (approved["approval_id"],))
                if consumed.rowcount != 1:
                    raise AuthorizationError("operator approval was already used")
            if spend.financial:
                db.execute("""INSERT INTO quota_records(record_id,task_id,tool_id,grant_id,source_type,
                    amount_cents,reserved_cents,status,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""", (str(uuid.uuid4()), task_id, tool_id, grant["grant_id"],
                    "tool", spend.cost_cents, spend.cost_cents, "reserved", now.isoformat()))
            db.commit()
            return grant

    def redeem(self, grant: dict, task_id: str, principal_id: str, tool_id: str, args: dict) -> str:
        """Call at the point of effect. Successful redemption authorizes one attempt."""
        try:
            self.public_key.verify(bytes.fromhex(grant["signature"]), signed_payload(grant))
        except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
            raise AuthorizationError("invalid grant signature") from exc
        if (grant["task_id"], grant["principal_id"], grant["tool_id"]) != (task_id, principal_id, tool_id):
            raise AuthorizationError("grant binding mismatch")
        if grant["frozen_args_hash"] != args_hash(args):
            raise AuthorizationError("arguments changed")
        if datetime.fromisoformat(grant["expires_at"]) <= utcnow():
            raise AuthorizationError("grant expired")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                result = db.execute("""UPDATE governance_grants SET status='redeemed'
                    WHERE grant_id=? AND decision_id=? AND signature=? AND status='issued' AND expires_at>?""",
                    (grant["grant_id"], grant["decision_id"], grant["signature"], utcnow().isoformat()))
                if result.rowcount != 1:
                    raise AuthorizationError("grant missing, expired, or already used")
                invocation_id = str(uuid.uuid4())
                db.execute("INSERT INTO tool_invocation_logs VALUES (?,?,?,?,?,?)",
                           (invocation_id, grant["grant_id"], task_id, tool_id, "authorized", utcnow().isoformat()))
                db.commit()
                return invocation_id
            except SQLAlchemyError as exc:
                raise AuthorizationError("grant redemption failed") from exc
