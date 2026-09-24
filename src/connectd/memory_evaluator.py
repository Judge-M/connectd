"""Independent, configurable evidence assessment for cross-task memory."""

import os
from typing import Protocol

import httpx
from pydantic import BaseModel, Field

from connectd.config import LibrarianSettings


class EvaluationResult(BaseModel):
    confidence_score: float = Field(ge=0, le=1)
    is_corroborated: bool
    contradiction_detected: bool = False
    reasoning_summary: str = Field(min_length=1, max_length=2000)


class LibrarianEvaluator(Protocol):
    async def evaluate_claim(self, claim_text: str, provenance_context: str,
                             existing_org_claims: list[str]) -> EvaluationResult: ...


class FailClosedEvaluator:
    async def evaluate_claim(self, claim_text: str, provenance_context: str,
                             existing_org_claims: list[str]) -> EvaluationResult:
        return EvaluationResult(confidence_score=0, is_corroborated=False,
            reasoning_summary="No independent librarian is configured")


class HttpJsonEvaluator:
    """POST an explicit contract to an operator-configured trusted service."""

    def __init__(self, settings: LibrarianSettings):
        if settings.type != "http_json" or settings.endpoint_url is None:
            raise ValueError("HTTP librarian endpoint is not configured")
        self.settings = settings

    async def evaluate_claim(self, claim_text: str, provenance_context: str,
                             existing_org_claims: list[str]) -> EvaluationResult:
        headers = {}
        if self.settings.token_env:
            token = os.environ.get(self.settings.token_env)
            if not token:
                raise RuntimeError("librarian credential is unavailable")
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=self.settings.timeout_seconds) as client:
            response = await client.post(self.settings.endpoint_url, headers=headers,
                json={"claim_text": claim_text,
                      "provenance_context": provenance_context,
                      "existing_org_claims": existing_org_claims})
            response.raise_for_status()
            return EvaluationResult.model_validate(response.json())


def make_evaluator(settings: LibrarianSettings) -> LibrarianEvaluator:
    return HttpJsonEvaluator(settings) if settings.type == "http_json" else FailClosedEvaluator()
