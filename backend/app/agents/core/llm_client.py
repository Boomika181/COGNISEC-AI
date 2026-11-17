"""
LLM Client Interface and Protocol Definition.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class LLMException(Exception):
    """Base exception for all LLM errors."""
    pass


class LLMTimeoutException(LLMException):
    """Raised when an LLM provider call exceeds the configured timeout."""
    pass


class LLMAuthenticationException(LLMException):
    """Raised when API credentials are missing, revoked, or invalid."""
    pass


class LLMRateLimitException(LLMException):
    """Raised when provider rate limits / quotas are exceeded."""
    pass


class LLMValidationException(LLMException):
    """Raised when LLM response is malformed or violates output schema."""
    pass


class LLMRequest(BaseModel):
    """Encapsulates a sanitized request sent to an LLM provider."""
    prompt: str
    system_instruction: Optional[str] = None
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    max_tokens: int = Field(default=1024, ge=1, le=8192)
    response_schema: Optional[Dict[str, Any]] = None
    timeout_seconds: Optional[float] = None


class LLMResponse(BaseModel):
    """Encapsulates the structured response returned by an LLM provider."""
    content: str
    parsed_json: Optional[Dict[str, Any]] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    provider: str
    model: str


class LLMClient(ABC):
    """Abstract Base Class for all LLM Provider Adapters."""

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Asynchronously generates a response from the LLM provider.
        Must handle timeouts, rate limits, and network errors.
        """
        pass

    @abstractmethod
    def validate_configuration(self) -> bool:
        """
        Validates that required provider configuration (e.g. API keys, models) is present.
        """
        pass

