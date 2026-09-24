"""Authenticated health and capacity probes for registered model nodes."""

import json
import ssl
from threading import Event
from urllib.parse import urlsplit

import httpx

from connectd.config import NodeManagerSettings
from connectd.governance import utcnow
from connectd.store import Store


class NodeMonitor:
    def __init__(self, store: Store, client_factory=None,
                 managers: list[NodeManagerSettings] | None = None):
        self.store = store
        self.client_factory = client_factory
        self.managers = managers or []

    def probe(self, node_id: str) -> bool:
        with self.store.connect() as db:
            node = db.execute("SELECT * FROM compute_nodes WHERE node_id=?", (node_id,)).fetchone()
        if node is None or not node["health_url"] or not node["endpoint_url"]:
            return False
        healthy = False
        capacity = None
        try:
            endpoint, check = urlsplit(node["endpoint_url"]), urlsplit(node["health_url"])
            if ((endpoint.scheme, endpoint.hostname, endpoint.port) !=
                    (check.scheme, check.hostname, check.port) or
                    not check.path or check.query or check.fragment or check.username or check.password):
                raise ValueError("health endpoint origin changed")
            if node["privacy_tier"] != "local_only":
                if endpoint.scheme != "https" or not all(node[key] for key in (
                        "ca_cert_path", "client_cert_path", "client_key_path")):
                    raise ValueError("remote node lacks mTLS")
                context = ssl.create_default_context(cafile=node["ca_cert_path"])
                context.load_cert_chain(node["client_cert_path"], node["client_key_path"])
                context.check_hostname = True
            else:
                context = True
            client = (self.client_factory(context) if self.client_factory
                      else httpx.Client(verify=context, timeout=5))
            with client:
                response = client.get(node["health_url"])
                response.raise_for_status()
                report = response.json()
            slots = report.get("available_slots") if isinstance(report, dict) else None
            models = report.get("loaded_models") if isinstance(report, dict) else None
            if (not isinstance(report, dict) or report.get("status") != "healthy" or
                    type(slots) is not int or slots < 0 or
                    not isinstance(models, list) or not all(isinstance(model, str) for model in models) or
                    node["model_id"] not in models):
                raise ValueError("invalid node capacity report")
            capacity = json.dumps({"available_slots": slots, "loaded_models": models}, sort_keys=True)
            healthy = slots > 0
        except (httpx.HTTPError, ValueError, OSError, ssl.SSLError, TypeError):
            pass
        with self.store.connect() as db:
            db.execute("""UPDATE compute_nodes SET healthy=?,last_health_at=?,capacity_json=?
                WHERE node_id=?""", (healthy, utcnow().isoformat(), capacity, node_id))
        return healthy

    def probe_manager(self, manager: NodeManagerSettings) -> dict[str, bool]:
        """Only operator-registered nodes may be admitted by a manager report."""
        with self.store.connect() as db:
            nodes = db.execute("SELECT node_id,model_id FROM compute_nodes WHERE manager_id=?",
                               (manager.manager_id,)).fetchall()
        approved = {node["node_id"]: node["model_id"] for node in nodes
                    if node["node_id"] in manager.allowed_node_ids}
        status = {node_id: False for node_id in approved}
        capacity = {}
        try:
            context = ssl.create_default_context(cafile=str(manager.ca_cert_path))
            context.load_cert_chain(str(manager.client_cert_path), str(manager.client_key_path))
            context.check_hostname = True
            client = (self.client_factory(context) if self.client_factory
                      else httpx.Client(verify=context, timeout=5))
            with client:
                response = client.get(manager.endpoint_url)
                response.raise_for_status()
                report = response.json()
            entries = report.get("nodes") if isinstance(report, dict) else None
            if not isinstance(entries, list):
                raise ValueError("invalid manager inventory")
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("node_id"), str):
                    raise ValueError("invalid manager node")
                node_id = entry["node_id"]
                if node_id in seen:
                    raise ValueError("duplicate manager node")
                seen.add(node_id)
                if node_id not in approved:
                    continue
                slots = entry.get("available_slots")
                models = entry.get("loaded_models")
                if (entry.get("status") != "healthy" or type(slots) is not int or slots < 0 or
                        not isinstance(models, list) or
                        not all(isinstance(model, str) for model in models)):
                    raise ValueError("invalid approved node capacity")
                capacity[node_id] = json.dumps(
                    {"available_slots": slots, "loaded_models": models}, sort_keys=True)
                status[node_id] = slots > 0 and approved[node_id] in models
        except (httpx.HTTPError, ValueError, OSError, ssl.SSLError, TypeError):
            status = {node_id: False for node_id in approved}
            capacity = {}
        with self.store.connect() as db:
            for node_id, healthy in status.items():
                db.execute("""UPDATE compute_nodes SET healthy=?,last_health_at=?,capacity_json=?
                    WHERE node_id=? AND manager_id=?""",
                    (healthy, utcnow().isoformat(), capacity.get(node_id), node_id,
                     manager.manager_id))
        return status

    def poll_once(self) -> dict[str, bool]:
        with self.store.connect() as db:
            node_ids = [row["node_id"] for row in db.execute(
                "SELECT node_id FROM compute_nodes WHERE health_url IS NOT NULL ORDER BY node_id")]
        results = {node_id: self.probe(node_id) for node_id in node_ids}
        for manager in self.managers:
            results.update(self.probe_manager(manager))
        return results

    def run_until(self, stopped: Event, interval_seconds: int = 30) -> None:
        if interval_seconds < 1:
            raise ValueError("health interval must be positive")
        while not stopped.is_set():
            self.poll_once()
            stopped.wait(interval_seconds)
