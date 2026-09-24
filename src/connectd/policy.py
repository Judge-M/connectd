"""In-process Cedar policy decision for Tier 2 tool calls."""

from pathlib import Path
from dataclasses import dataclass

import cedarpy


@dataclass(frozen=True)
class PolicyEvaluation:
    permit: bool
    require_human_approval: bool


class CedarPolicy:
    def __init__(self, source: str):
        try:
            self._policies = cedarpy.PolicySet.from_str(source)
            pst = self._policies.to_pst()
            self._approval_policy_ids = {
                policy_id for policy_id, policy in pst.static_policies.items()
                if policy.annotations.get("require_human_approval") == "true"
            }
        except Exception as exc:
            raise ValueError(f"invalid Cedar policy set: {exc}") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> "CedarPolicy":
        return cls(Path(path).read_text(encoding="utf-8"))

    def evaluate(self, task_id: str, principal_id: str, tool_id: str, args: dict) -> PolicyEvaluation:
        # The grant engine freezes exact arguments separately. Cedar sees the
        # same hash so policies may constrain specific approved payloads.
        from connectd.governance import args_hash

        request = {
            "principal": {"type": "Agent", "id": principal_id},
            "action": {"type": "Action", "id": "invoke"},
            "resource": {"type": "Tool", "id": tool_id},
            "context": {"task_id": task_id, "args_hash": args_hash(args)},
        }
        entities = [
            {"uid": {"type": "Agent", "id": principal_id}, "attrs": {}, "parents": []},
            {"uid": {"type": "Tool", "id": tool_id}, "attrs": {}, "parents": []},
        ]
        try:
            decision = cedarpy.is_authorized(request, self._policies, entities)
            permitted = decision.decision is cedarpy.Decision.Allow
            approval = permitted and bool(self._approval_policy_ids.intersection(
                decision.diagnostics.reasons))
            return PolicyEvaluation(permitted, approval)
        except Exception:
            return PolicyEvaluation(False, False)

    def permit(self, task_id: str, principal_id: str, tool_id: str, args: dict) -> bool:
        return self.evaluate(task_id, principal_id, tool_id, args).permit

    def requires_human_approval(self, task_id: str, principal_id: str,
                                tool_id: str, args: dict) -> bool:
        return self.evaluate(task_id, principal_id, tool_id, args).require_human_approval
