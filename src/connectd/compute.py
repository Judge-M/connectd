"""Privacy gates precede any capacity or model routing."""

import json
from datetime import datetime, timedelta
from enum import Enum

from connectd.governance import utcnow
from connectd.store import Store
from connectd.registry_access import visible_to


class PrivacyClass(str, Enum):
    PUBLIC = "public"
    LOW_SENSITIVE = "low_sensitive"
    REPO_SENSITIVE = "repo_sensitive"
    SECRET_SENSITIVE = "secret_sensitive"


class PlacementDenied(Exception):
    pass


def eligible_tiers(privacy: PrivacyClass) -> tuple[str, ...]:
    if privacy == PrivacyClass.SECRET_SENSITIVE:
        return ("local_only", "private_rented", "external")
    if privacy == PrivacyClass.REPO_SENSITIVE:
        return ("local_only", "private_rented")
    return ("local_only", "private_rented", "external")


def place(store: Store, privacy: PrivacyClass,
          secret_sensitive_allowed_node_ids: frozenset[str] = frozenset(),
          model_id: str | None = None,
          max_health_age_seconds: int = 90,
          org_id: str = "default") -> str:
    if max_health_age_seconds < 1:
        raise ValueError("health age must be positive")
    tiers = eligible_tiers(privacy)
    cutoff = utcnow() - timedelta(seconds=max_health_age_seconds)
    with store.connect() as db:
        nodes = db.execute("""SELECT node_id, privacy_tier, airgapped, allowed_privacy_json,
                endpoint_url, model_id, health_url, manager_id, last_health_at, owner_org_id
            FROM compute_nodes WHERE healthy=TRUE ORDER BY node_id""").fetchall()
        visible_nodes = [node for node in nodes if visible_to(
            db, node["owner_org_id"], org_id, "node", node["node_id"])]
    for tier in tiers:
        for node in visible_nodes:
            if node["privacy_tier"] != tier:
                continue
            if not node["endpoint_url"] or not node["model_id"]:
                continue
            if model_id is not None and node["model_id"] != model_id:
                continue
            if node["health_url"] or node["manager_id"]:
                try:
                    checked_at = datetime.fromisoformat(node["last_health_at"])
                    if checked_at.tzinfo is None or checked_at < cutoff:
                        continue
                except (ValueError, TypeError):
                    continue
            if node["allowed_privacy_json"] and privacy.value not in json.loads(node["allowed_privacy_json"]):
                continue
            if privacy == PrivacyClass.SECRET_SENSITIVE and not (
                node["node_id"] in secret_sensitive_allowed_node_ids or
                (node["privacy_tier"] == "local_only" and node["airgapped"])
            ):
                continue
            if node["privacy_tier"] == tier:
                return node["node_id"]
    raise PlacementDenied("no healthy node satisfies the privacy class")
