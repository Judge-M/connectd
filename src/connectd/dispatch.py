"""Host-side step dispatch. The control-plane container never receives a Docker socket."""

from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

import httpx

from connectd.config import ConnectdConfig, GrantMode
from connectd.launcher import WorkerInput, WorkerLauncher
from connectd.worker import Ticket, WorkerReport
from connectd.workbench import WORKBENCH_TOOL


class DispatchError(Exception):
    pass


def stable_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError:
        return uuid5(NAMESPACE_URL, "connectd:" + value)


class StepDispatcher:
    def __init__(self, config: ConnectdConfig, control_plane_url: str, operator_token: str,
                 client: httpx.Client | None = None, launcher: WorkerLauncher | None = None):
        self.config = config
        self.control_plane_url = control_plane_url.rstrip("/")
        self.operator_token = operator_token
        self.client = client or httpx.Client(timeout=30)
        self.launcher = launcher or WorkerLauncher(docker_network="connectd-isolated")

    def _request(self, method: str, path: str, token: str, **kwargs) -> dict:
        response = self.client.request(method, self.control_plane_url + path,
                                       headers={"Authorization": f"Bearer {token}"}, **kwargs)
        response.raise_for_status()
        return response.json()

    def run_step(self, task_id: str, step_id: str, worktree: Path,
                 tool_id: str = "auto", timeout_seconds: int = 300) -> WorkerReport:
        if not worktree.is_dir():
            raise DispatchError("worktree directory is missing")
        task = self._request("GET", f"/api/v1/tasks/{task_id}", self.operator_token)
        if task["is_terminal"]:
            raise DispatchError("terminal tasks cannot be dispatched")
        profile = self.config.profile(task["execution_profile"])
        worker_id = uuid4()
        worker_token = self._request("POST", f"/api/v1/tasks/{task_id}/worker-sessions",
                                     self.operator_token, json={"worker_id": str(worker_id),
                                                                "ttl_seconds": timeout_seconds + 120})["token"]
        placement = self._request("GET", f"/api/v1/tasks/{task_id}/placement", worker_token)
        node = self._request("GET", f"/api/v1/compute/nodes/{placement['node_id']}",
                             self.operator_token)
        model_url = self.config.worker_model.base_url
        model_id = node["model_id"] or self.config.worker_model.model_id
        if not model_url or not model_id:
            raise DispatchError("a capable worker model endpoint and model ID must be configured")
        if placement["privacy_tier"] != "local_only" and not self.config.worker_model.uses_proxy:
            raise DispatchError("remote inference requires the authenticated model proxy")
        if profile.grant_mode == GrantMode.STRICT_ED25519:
            model_url = f"http://model-api:{self.config.model_api.port}"
        if task["privacy_class"] == "secret_sensitive":
            if (placement["privacy_tier"] != "local_only" and
                    placement["node_id"] not in self.config.secret_sensitive_allowed_node_ids):
                raise DispatchError("remote secret-sensitive node is not allowlisted")
            if placement["privacy_tier"] == "local_only" and not placement["airgapped"]:
                raise DispatchError("local secret-sensitive inference node is not air-gapped")
            if not self.config.worker_model.uses_proxy and urlsplit(model_url).hostname not in {
                    "127.0.0.1", "localhost"}:
                raise DispatchError("secret-sensitive model endpoint is not local")
        context = self._request("GET", f"/api/v1/tasks/{task_id}/context-pack", worker_token)
        if tool_id == "auto":
            step = self._request("GET", f"/api/v1/steps/{step_id}", self.operator_token)
            if step["task_id"] != task_id:
                raise DispatchError("step is not in the requested task")
            routed = self._request("POST", "/api/v1/router/route", worker_token,
                                   json={"task_id": task_id, "objective": step["instruction"]})
            tool_id = routed["tool_id"]
            tool = routed["tool"]
            effect_tier = routed["effect_tier"]
            capabilities = set() if tool_id == "workbench" else {tool_id}
        elif tool_id == "workbench":
            tool = WORKBENCH_TOOL
            effect_tier = 1
            capabilities: set[str] = set()
        else:
            registered = self._request("GET", f"/api/v1/tools/{tool_id}", worker_token)
            tool = {"type": "function", "function": {"name": tool_id,
                    "description": registered["name"], "parameters": registered["schema"]}}
            effect_tier = registered["effect_tier"]
            capabilities = {tool_id}
        lease = self._request("POST", f"/api/v1/steps/{step_id}/claim", worker_token,
                              json={"lease_seconds": min(3600, timeout_seconds + 60)})
        ticket = Ticket(id=stable_uuid(step_id), conversation_id=stable_uuid(task_id),
                        objective=lease["instruction"],
                        context=[{"label": "promoted_memory", "value": item} for item in context["memory"]],
                        constraints=["Stay within this ticket and its granted authority."],
                        deliverable="A concise summary and any workspace changes",
                        authority={"local": {"read_workspace": True, "write_workspace": True,
                                             "execute_local": True},
                                   "external_capabilities": capabilities})
        worker_control_url = ("http://connectd-gateway:8790"
                              if profile.grant_mode == GrantMode.STRICT_ED25519
                              else self.control_plane_url)
        payload = WorkerInput(ticket=ticket, worker_id=worker_id, task_id=task_id, tool=tool,
                              model_base_url=model_url, model_id=model_id,
                              control_plane_url=worker_control_url, worker_token=worker_token,
                              model_api_auth=self.config.worker_model.uses_proxy)
        try:
            report = self.launcher.run(payload, worktree, profile, effect_tier, timeout_seconds)
        except Exception as exc:
            self._request("POST", f"/api/v1/steps/{step_id}/complete", self.operator_token,
                          json={"lease": lease, "summary": str(exc)[:500], "status": "failed"})
            raise
        self._request("POST", f"/api/v1/steps/{step_id}/complete", self.operator_token,
                      json={"lease": lease, "summary": report.summary,
                            "status": "done" if report.status == "completed" else "failed"})
        return report
