"""
Mock LLM Provider Adapter for Hermetic, Deterministic Automated Testing.
"""
import time
import json
import asyncio
from typing import Optional, Dict, Any, List
from app.agents.core.llm_client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    LLMTimeoutException,
    LLMValidationException,
    LLMException
)


class MockLLMClient(LLMClient):
    """
    Simulated LLM client for tests. Runs locally with zero external network dependencies.
    Allows injecting custom responses, simulated latency, timeouts, and malformed outputs.
    """

    provider_name: str = "mock"
    model_name: str = "mock-v1"

    def __init__(
        self,
        default_response: Optional[Dict[str, Any]] = None,
        simulated_latency_ms: int = 10,
        inject_timeout: bool = False,
        inject_invalid_json: bool = False,
        inject_exception: Optional[Exception] = None,
        **kwargs
    ):
        self.default_response = default_response or {"status": "success", "assessment": "benign"}
        self.simulated_latency_ms = simulated_latency_ms
        self.inject_timeout = inject_timeout
        self.inject_invalid_json = inject_invalid_json
        self.inject_exception = inject_exception
        self.extra_kwargs = kwargs
        self.recorded_requests: List[LLMRequest] = []

    def validate_configuration(self) -> bool:
        return True

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.recorded_requests.append(request)

        if self.simulated_latency_ms > 0:
            await asyncio.sleep(self.simulated_latency_ms / 1000.0)

        if self.inject_timeout:
            raise LLMTimeoutException("Mock LLM client simulated request timeout after deadline exceeded.")

        if self.inject_exception:
            raise self.inject_exception

        if self.inject_invalid_json:
            return LLMResponse(
                content="INVALID_NON_JSON_OUTPUT {{{malformed",
                parsed_json=None,
                prompt_tokens=25,
                completion_tokens=10,
                latency_ms=self.simulated_latency_ms,
                provider="mock",
                model="mock-v1"
            )

        content_str = json.dumps(self.default_response)
        return LLMResponse(
            content=content_str,
            parsed_json=self.default_response,
            prompt_tokens=len(request.prompt.split()),
            completion_tokens=len(content_str.split()),
            latency_ms=self.simulated_latency_ms,
            provider="mock",
            model="mock-v1"
        )
