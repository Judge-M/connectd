"""Privacy gates precede any capacity or model routing."""

import json
from enum import Enum

from connectd.store import Store


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


def place(store: Store, privacy: PrivacyClass, secret_sensitive_allowed_node_ids: frozenset[str] = frozenset()) -> str:
    tiers = eligible_tiers(privacy)
    with store.connect() as db:
        nodes = db.execute("""SELECT node_id, privacy_tier, airgapped, allowed_privacy_json
            FROM compute_nodes WHERE healthy=TRUE ORDER BY node_id""").fetchall()
    for tier in tiers:
        for node in nodes:
            if node["privacy_tier"] != tier:
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
