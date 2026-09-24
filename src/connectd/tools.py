"""Point-of-effect schema validation, grant redemption, and tool dispatch."""

import json
from collections.abc import Callable
from dataclasses import dataclass

from jsonschema import ValidationError, validate

from connectd.governance import AuthorizationError, Governance
from connectd.store import Store
from connectd.spend import SpendError, metered_quote, settle_record


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class TrustedToolResult:
    """Usage is supplied by an operator-bound handler, never by worker arguments."""

    value: object
    actual_units: int


class ToolGateway:
    def __init__(self, store: Store, governance: Governance):
        self.store = store
        self.governance = governance
        self.handlers: dict[str, Callable[[dict], object]] = {}

    def register_handler(self, tool_id: str, handler: Callable[[dict], object]) -> None:
        self.handlers[tool_id] = handler

    def invoke(self, task_id: str, principal_id: str, tool_id: str, args: dict,
               grant: dict | None = None) -> object:
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM tool_registry WHERE tool_id=?", (tool_id,)).fetchone()
        if row is None or not row["active"] or tool_id not in self.handlers:
            raise ToolError("tool is not registered for execution")
        try:
            validate(args, json.loads(row["schema_json"]))
        except (ValidationError, ValueError) as exc:
            raise ToolError("tool arguments fail schema validation") from exc
        # Authorization and redemption occur before dispatch. A signed grant
        # can authorize one attempt only; tool retries need a new decision.
        try:
            grant = grant or self.governance.issue(task_id, principal_id, tool_id, args)
            invocation_id = self.governance.redeem(grant, task_id, principal_id, tool_id, args)
        except AuthorizationError as exc:
            raise ToolError(str(exc)) from exc
        try:
            result = self.handlers[tool_id](args)
        except Exception as exc:
            with self.store.connect() as db:
                db.execute("UPDATE tool_invocation_logs SET outcome='error' WHERE invocation_id=?", (invocation_id,))
            raise ToolError("tool execution failed") from exc
        if isinstance(result, TrustedToolResult):
            actual_units = result.actual_units
            result = result.value
        else:
            actual_units = None
        with self.store.connect() as db:
            quota = db.execute("SELECT record_id FROM quota_records WHERE grant_id=?", (grant["grant_id"],)).fetchone()
            if quota:
                try:
                    _, rate, maximum = metered_quote(row["pricing_model"])
                    if rate == 0 or actual_units is not None:
                        settle_record(db, quota["record_id"], actual_units or 0,
                                      rate_per_unit_microusd=rate, max_units=maximum,
                                      fixed_cents=row["cost_per_invocation_cents"])
                except SpendError as exc:
                    db.execute("UPDATE tool_invocation_logs SET outcome='usage_error' WHERE invocation_id=?",
                               (invocation_id,))
                    raise ToolError("trusted tool usage exceeded registry bounds") from exc
            db.execute("UPDATE tool_invocation_logs SET outcome='success' WHERE invocation_id=?", (invocation_id,))
        return result
