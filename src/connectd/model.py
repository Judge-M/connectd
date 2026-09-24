"""One-pass typed System-1 routing through Laya or Jev."""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from connectd.router import Route, RouteError, traverse


class ChoiceAnswer(BaseModel):
    choice: str
    confidence: float = Field(ge=0, le=1)


@dataclass(frozen=True)
class RoutingDecision:
    route: Route
    latency_ms: float
    provider: str
    confidences: Mapping[str, float]


class TypedDecisionRouter:
    def __init__(self, provider: Literal["laya", "jev"], base_url: str,
                 min_confidence: float, api_key: str | None = None,
                 client: httpx.Client | None = None):
        if not 0 <= min_confidence <= 1:
            raise ValueError("minimum routing confidence must be between 0 and 1")
        if provider == "jev" and not api_key:
            raise ValueError("Jev requires an API key")
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.min_confidence = min_confidence
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=2)

    def route(self, tree: Mapping[str, Any], objective: str) -> RoutingDecision:
        nodes = tree["nodes"]
        questions = {}
        for node_id, node in nodes.items():
            options = node["options"]
            if not 1 <= len(options) <= 4:
                raise RouteError("each routing node must have one to four options")
            questions[node_id] = {
                "type": "choice",
                "instructions": f"For the task, choose the best option at routing node {node_id}.",
                "criteria": {str(option["id"]): str(option.get("label", option["id"]))
                             for option in options},
            }
        request = {"state": {"objective": objective}, "questions": questions}
        headers = {}
        if self.provider == "jev":
            request["model"] = "jev-latest"
            headers["Authorization"] = f"Bearer {self.api_key}"
        start = time.perf_counter()
        try:
            response = self.client.post(f"{self.base_url}/v1/systemone", json=request,
                                        headers=headers)
            response.raise_for_status()
            raw_answers = response.json()["answers"]
            answers = {node_id: ChoiceAnswer.model_validate(raw_answers[node_id])
                       for node_id in nodes}
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise RouteError("decision classifier failed or returned invalid choices") from exc
        elapsed = (time.perf_counter() - start) * 1000

        def choose(node_id: str, _options: tuple[Mapping[str, Any], ...]) -> str:
            answer = answers[node_id]
            if answer.confidence < self.min_confidence:
                raise RouteError("decision confidence is below the routing threshold")
            return answer.choice

        route = traverse(tree, choose)
        return RoutingDecision(route, elapsed, self.provider,
                               {hop.node_id: answers[hop.node_id].confidence for hop in route.hops})
