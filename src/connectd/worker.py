"""Stateless, bounded OpenAI-compatible worker turn loop."""

import json
from collections.abc import Callable
from typing import Any, Literal
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field


class ContextItem(BaseModel):
    label: str
    value: str


class LocalAuthority(BaseModel):
    read_workspace: bool = True
    write_workspace: bool = False
    execute_local: bool = False


class AuthorityEnvelope(BaseModel):
    local: LocalAuthority = Field(default_factory=LocalAuthority)
    external_capabilities: set[str] = Field(default_factory=set)


class Ticket(BaseModel):
    """JSON-compatible with Seam's protocol crate Ticket fields."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    conversation_id: UUID
    objective: str
    context: list[ContextItem] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    deliverable: str
    authority: AuthorityEnvelope


class WorkerReport(BaseModel):
    worker_id: UUID
    ticket_id: UUID
    conversation_id: UUID
    status: Literal["completed", "blocked", "failed"]
    summary: str
    artifacts: list[dict] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WorkerError(Exception):
    pass


class DirectWorker:
    def __init__(self, model_base_url: str, model_id: str,
                 invoke_capability: Callable[[str, dict], Any],
                 client: httpx.Client | None = None,
                 model_auth_token: str | None = None,
                 max_output_tokens: int | None = None):
        self.model_base_url = model_base_url.rstrip("/")
        self.model_id = model_id
        self.invoke_capability = invoke_capability
        self.client = client or httpx.Client(timeout=60)
        self.model_auth_token = model_auth_token
        self.max_output_tokens = max_output_tokens

    def run(self, ticket: Ticket, worker_id: UUID, tool: dict, max_turns: int = 5) -> WorkerReport:
        if not 1 <= max_turns <= 5:
            raise ValueError("max_turns must be between 1 and 5")
        if not isinstance(tool, dict) or set(tool) != {"type", "function"}:
            raise WorkerError("exactly one OpenAI tool definition is required")
        tool_name = tool["function"]["name"]
        if tool_name != "workbench" and tool_name not in ticket.authority.external_capabilities:
            raise WorkerError("ticket does not authorize this capability")
        messages = [
            {"role": "system", "content": "Perform the bounded ticket. Use only the supplied tool. Return a concise final summary."},
            {"role": "user", "content": json.dumps({
                "objective": ticket.objective,
                "context": [item.model_dump() for item in ticket.context],
                "constraints": ticket.constraints,
                "deliverable": ticket.deliverable,
            })},
        ]
        for _turn in range(max_turns):
            headers = ({"Authorization": f"Bearer {self.model_auth_token}"}
                       if self.model_auth_token else {})
            request = {
                "model": self.model_id, "messages": messages, "tools": [tool], "tool_choice": "auto",
            }
            if self.max_output_tokens is not None:
                request["max_tokens"] = self.max_output_tokens
            response = self.client.post(f"{self.model_base_url}/v1/chat/completions", headers=headers,
                                        json=request)
            response.raise_for_status()
            try:
                message = response.json()["choices"][0]["message"]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise WorkerError("invalid model response") from exc
            tool_calls = message.get("tool_calls") or []
            if len(tool_calls) > 1:
                raise WorkerError("model attempted multiple tool calls in one turn")
            if not tool_calls:
                content = message.get("content")
                if not isinstance(content, str) or not content.strip():
                    raise WorkerError("model returned no final summary")
                return WorkerReport(worker_id=worker_id, ticket_id=ticket.id,
                                    conversation_id=ticket.conversation_id,
                                    status="completed", summary=content.strip())
            call = tool_calls[0]
            try:
                if call["function"]["name"] != tool_name:
                    raise WorkerError("model selected an unprovided tool")
                args = json.loads(call["function"]["arguments"])
                if not isinstance(args, dict):
                    raise WorkerError("tool arguments must be an object")
                result = self.invoke_capability(tool_name, args)
            except (KeyError, TypeError, ValueError) as exc:
                raise WorkerError("invalid tool call") from exc
            messages.append({"role": "assistant", "content": message.get("content"), "tool_calls": tool_calls})
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": json.dumps(result, ensure_ascii=False)})
        return WorkerReport(worker_id=worker_id, ticket_id=ticket.id,
                            conversation_id=ticket.conversation_id, status="blocked",
                            summary="worker turn limit reached")


class HttpCapabilityClient:
    def __init__(self, control_plane_url: str, token: str, task_id: str,
                 client: httpx.Client | None = None):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.token = token
        self.task_id = task_id
        self.client = client or httpx.Client(timeout=30)

    def __call__(self, tool_id: str, args: dict) -> Any:
        response = self.client.post(f"{self.control_plane_url}/api/v1/tools/invoke",
                                    headers={"Authorization": f"Bearer {self.token}"},
                                    json={"task_id": self.task_id, "tool_id": tool_id, "args": args})
        response.raise_for_status()
        return response.json()["result"]
