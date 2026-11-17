"""
Google Gemini Provider Adapter using asynchronous HTTP client.
Communicates with the Google Generative Language REST API.
"""
import asyncio
import time
import json
import logging
import re
import threading
import weakref
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import httpx

from app.core.config import settings
from app.agents.core.llm_client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    LLMException,
    LLMTimeoutException,
    LLMAuthenticationException,
    LLMRateLimitException,
    LLMValidationException,
)

logger = logging.getLogger("cognisec.agents.gemini")

SUPPORTED_GEMINI_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.8-flash",
    "gemini-flash-lite-latest",
    "gemini-flash-latest",
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
]

# Thread-safe runtime provider health telemetry (never stores credentials)
_health_lock = threading.RLock()
_provider_health_state: Dict[str, Any] = {
    "connectivity_verified": False,
    "agent_request_succeeded": False,
    "test_generation_status": "Not tested",
    "last_successful_check": None,
    "last_failure_category": None,
    "last_failure_reason": None,
    "last_verified_model": None,
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "timeout_errors": 0,
    "rate_limit_errors": 0,
    "last_latency_ms": None,
    "avg_latency_ms": None,
    "_latency_sum_ms": 0.0,
    "_latency_count": 0,
}

# Per-event-loop semaphore cache to bound concurrent Gemini API calls safely across tests & runtime
_loop_semaphores: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = weakref.WeakKeyDictionary()
_sem_lock = threading.Lock()


def _get_concurrency_semaphore() -> asyncio.Semaphore:
    limit = max(1, int(getattr(settings, "LLM_MAX_CONCURRENT_REQUESTS", 5) or 5))
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Semaphore(limit)
    with _sem_lock:
        sem = _loop_semaphores.get(loop)
        if sem is None:
            sem = asyncio.Semaphore(limit)
            _loop_semaphores[loop] = sem
        return sem


def record_provider_success(model: str, is_agent_request: bool = False, latency_ms: Optional[float] = None) -> None:
    """Records a verified Gemini API interaction without storing any sensitive payload."""
    with _health_lock:
        _provider_health_state["connectivity_verified"] = True
        _provider_health_state["total_requests"] += 1
        _provider_health_state["successful_requests"] += 1
        if is_agent_request:
            _provider_health_state["agent_request_succeeded"] = True
            _provider_health_state["test_generation_status"] = "Successful"
        if latency_ms is not None:
            val = round(float(latency_ms), 2)
            _provider_health_state["last_latency_ms"] = val
            _provider_health_state["_latency_sum_ms"] += val
            _provider_health_state["_latency_count"] += 1
            _provider_health_state["avg_latency_ms"] = round(
                _provider_health_state["_latency_sum_ms"] / _provider_health_state["_latency_count"], 2
            )
        _provider_health_state["last_successful_check"] = datetime.now(timezone.utc).isoformat()
        _provider_health_state["last_failure_category"] = None
        _provider_health_state["last_failure_reason"] = None
        _provider_health_state["last_verified_model"] = model


def record_provider_failure(category: str, reason: Optional[str] = None) -> None:
    """Records a sanitized failure category without storing raw response bodies or keys."""
    with _health_lock:
        _provider_health_state["total_requests"] += 1
        _provider_health_state["failed_requests"] += 1
        if category == "TIMEOUT":
            _provider_health_state["timeout_errors"] += 1
        elif category == "RATE_LIMIT":
            _provider_health_state["rate_limit_errors"] += 1
        if category in ("MISSING_API_KEY", "AUTHENTICATION_ERROR", "MODEL_UNAVAILABLE"):
            _provider_health_state["connectivity_verified"] = False
        if category in ("TIMEOUT", "RATE_LIMIT", "VALIDATION_ERROR", "PROVIDER_ERROR", "NETWORK_ERROR", "AUTHENTICATION_ERROR", "MODEL_UNAVAILABLE"):
            _provider_health_state["test_generation_status"] = "Failed"
        _provider_health_state["last_failure_category"] = category
        _provider_health_state["last_failure_reason"] = (str(reason)[:180] if reason else category)


def reset_provider_health_state() -> None:
    """Resets runtime provider health telemetry (primarily for isolated testing)."""
    with _health_lock:
        _provider_health_state["connectivity_verified"] = False
        _provider_health_state["agent_request_succeeded"] = False
        _provider_health_state["test_generation_status"] = "Not tested"
        _provider_health_state["last_successful_check"] = None
        _provider_health_state["last_failure_category"] = None
        _provider_health_state["last_failure_reason"] = None
        _provider_health_state["last_verified_model"] = None
        _provider_health_state["total_requests"] = 0
        _provider_health_state["successful_requests"] = 0
        _provider_health_state["failed_requests"] = 0
        _provider_health_state["timeout_errors"] = 0
        _provider_health_state["rate_limit_errors"] = 0
        _provider_health_state["last_latency_ms"] = None
        _provider_health_state["avg_latency_ms"] = None
        _provider_health_state["_latency_sum_ms"] = 0.0
        _provider_health_state["_latency_count"] = 0


def get_gemini_runtime_state() -> Dict[str, Any]:
    """Returns a snapshot of safe Gemini runtime health state."""
    with _health_lock:
        return {k: v for k, v in _provider_health_state.items() if not k.startswith("_")}


def _strip_markdown_fences(text: str) -> str:
    """Removes optional ```json ... ``` fences around JSON output."""
    cleaned = text.strip()
    fence_match = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```$", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence_match:
        return fence_match.group(1).strip()
    return cleaned


class GeminiLLMClient(LLMClient):
    """
    Lightweight, robust Gemini API adapter using httpx.
    Requires GEMINI_API_KEY environment variable. Never hardcodes credentials.
    Passes API key via x-goog-api-key header rather than query parameters.
    """

    provider_name: str = "gemini"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        # Allow explicit empty string override in tests; otherwise fall back to settings
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = settings.GEMINI_API_KEY

        self.model = (
            model
            or getattr(settings, "GEMINI_MODEL", None)
            or settings.LLM_MODEL
            or "gemini-3.5-flash-lite"
        )
        self.timeout_seconds = float(timeout_seconds or settings.LLM_TIMEOUT_SECONDS or 2.0)
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

    @property
    def model_name(self) -> str:
        return self.model

    def validate_configuration(self) -> bool:
        """Validates that a non-empty API key is set and model identifier is non-empty."""
        if not self.api_key or not str(self.api_key).strip():
            logger.warning("GeminiLLMClient configuration invalid: GEMINI_API_KEY is not configured.")
            return False
        if not self.model or not str(self.model).strip():
            logger.warning("GeminiLLMClient configuration invalid: GEMINI_MODEL is empty.")
            return False
        if self.model not in SUPPORTED_GEMINI_MODELS:
            logger.warning(
                f"Configured model '{self.model}' is not in verified list: {SUPPORTED_GEMINI_MODELS}. "
                "Attempting execution with user-specified model."
            )
        return True

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-goog-api-key": str(self.api_key).strip(),
        }

    def _handle_error_response(self, response: httpx.Response) -> None:
        status = response.status_code
        body_lower = (response.text or "")[:500].lower()

        if status in (401, 403):
            record_provider_failure("AUTHENTICATION_ERROR")
            logger.error(f"Gemini authentication failed (HTTP {status}).")
            raise LLMAuthenticationException("Gemini API key is invalid or lacks necessary permissions.")

        if status == 400 and ("api_key_invalid" in body_lower or "api key not valid" in body_lower):
            record_provider_failure("AUTHENTICATION_ERROR")
            logger.error("Gemini rejected API key (HTTP 400 API_KEY_INVALID).")
            raise LLMAuthenticationException("Gemini API key is invalid.")

        if status == 404:
            record_provider_failure("MODEL_UNAVAILABLE")
            logger.error(f"Gemini model '{self.model}' unavailable or unsupported (HTTP 404).")
            raise LLMException(f"Gemini model '{self.model}' is not available or unsupported (HTTP 404).")

        if status == 429:
            record_provider_failure("RATE_LIMIT")
            logger.warning("Gemini API rate limit or quota exceeded (HTTP 429).")
            raise LLMRateLimitException("Gemini API rate limit or quota exceeded.")

        if status >= 500:
            record_provider_failure("PROVIDER_ERROR")
            logger.error(f"Gemini provider server error (HTTP {status}).")
            raise LLMException(f"Gemini provider server error: HTTP {status}")

        record_provider_failure("PROVIDER_ERROR")
        logger.error(f"Gemini unexpected HTTP status {status}.")
        raise LLMException(f"Gemini API error (HTTP {status}).")

    async def verify_model_availability(self) -> Dict[str, Any]:
        """
        Queries the Gemini Models API to verify that the configured model
        is available and supports generateContent.
        """
        if not self.validate_configuration():
            record_provider_failure("MISSING_API_KEY")
            raise LLMAuthenticationException("GEMINI_API_KEY is missing or unconfigured.")

        endpoint = f"{self.base_url}/models/{self.model}"
        try:
            async with _get_concurrency_semaphore():
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(endpoint, headers=self._auth_headers())
        except httpx.TimeoutException as e:
            record_provider_failure("TIMEOUT")
            raise LLMTimeoutException(f"Gemini model check timed out after {self.timeout_seconds}s.") from e
        except httpx.RequestError as e:
            record_provider_failure("NETWORK_ERROR")
            raise LLMException(f"Network error checking Gemini model availability: {type(e).__name__}") from e

        if response.status_code != 200:
            self._handle_error_response(response)

        data = response.json()
        supported_methods = data.get("supportedGenerationMethods", [])
        if supported_methods and "generateContent" not in supported_methods:
            record_provider_failure("MODEL_UNAVAILABLE")
            raise LLMException(
                f"Gemini model '{self.model}' does not support generateContent (methods={supported_methods})."
            )

        record_provider_success(self.model, is_agent_request=False)
        return {
            "model": self.model,
            "available": True,
            "supported_generation_methods": supported_methods,
        }

    async def verify_connectivity(self, test_generation: bool = False) -> Dict[str, Any]:
        """
        Verifies live Gemini API connectivity (and optionally runs a harmless test prompt).
        Never exposes the API key.
        """
        model_info = await self.verify_model_availability()
        if not test_generation:
            return {**model_info, "connectivity_verified": True}

        req = LLMRequest(
            prompt='Respond with a JSON object containing {"status": "ok"}',
            system_instruction="Return only valid JSON.",
            temperature=0.0,
            max_tokens=64,
            response_schema={"type": "object"},
            timeout_seconds=max(self.timeout_seconds, 5.0),
        )
        resp = await self.generate(req)
        return {
            **model_info,
            "connectivity_verified": True,
            "test_generation_ok": bool(resp.parsed_json),
            "latency_ms": resp.latency_ms,
        }

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Submits request to Gemini generateContent endpoint.
        Translates HTTP status codes into structured LLMException types.
        """
        if not self.validate_configuration():
            record_provider_failure("MISSING_API_KEY")
            raise LLMAuthenticationException("GEMINI_API_KEY is missing or unconfigured.")

        endpoint = f"{self.base_url}/models/{self.model}:generateContent"
        effective_timeout = float(request.timeout_seconds or self.timeout_seconds)

        # Build payload according to Gemini REST API format
        contents = [
            {
                "role": "user",
                "parts": [{"text": request.prompt}],
            }
        ]

        generation_config: Dict[str, Any] = {
            "temperature": request.temperature,
            "maxOutputTokens": request.max_tokens,
        }
        expect_json = bool(request.response_schema or "json" in request.prompt.lower())
        if expect_json:
            generation_config["responseMimeType"] = "application/json"

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": generation_config,
        }
        if request.system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": request.system_instruction}]
            }

        start_time = time.monotonic()
        try:
            async with _get_concurrency_semaphore():
                async with httpx.AsyncClient(timeout=effective_timeout) as client:
                    response = await client.post(
                        endpoint,
                        headers=self._auth_headers(),
                        json=payload,
                    )
        except httpx.TimeoutException as e:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            record_provider_failure("TIMEOUT")
            logger.error(f"Gemini API request timed out after {elapsed_ms}ms.")
            raise LLMTimeoutException(f"Gemini API call timed out after {effective_timeout}s.") from e
        except httpx.RequestError as e:
            record_provider_failure("NETWORK_ERROR")
            logger.error(f"Gemini API network request error: {type(e).__name__}")
            raise LLMException(f"Network error communicating with Gemini API: {type(e).__name__}") from e

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        if response.status_code != 200:
            self._handle_error_response(response)

        # Parse response body
        try:
            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                record_provider_failure("VALIDATION_ERROR")
                raise LLMValidationException("Gemini returned empty candidates list (content filtered or blocked).")

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                record_provider_failure("VALIDATION_ERROR")
                raise LLMValidationException("Gemini candidate content contains no parts.")

            text_content = parts[0].get("text", "")
            if not text_content or not str(text_content).strip():
                record_provider_failure("VALIDATION_ERROR")
                raise LLMValidationException("Gemini returned empty text content.")

            usage = data.get("usageMetadata", {})
            prompt_tokens = int(usage.get("promptTokenCount", 0) or 0)
            completion_tokens = int(usage.get("candidatesTokenCount", 0) or 0)

            parsed_json = None
            if expect_json:
                cleaned_text = _strip_markdown_fences(str(text_content))
                try:
                    parsed_candidate = json.loads(cleaned_text)
                    if not isinstance(parsed_candidate, dict):
                        raise LLMValidationException("Gemini JSON output must be a JSON object.")
                    parsed_json = parsed_candidate
                except LLMValidationException:
                    record_provider_failure("VALIDATION_ERROR")
                    raise
                except Exception as json_err:
                    record_provider_failure("VALIDATION_ERROR")
                    logger.warning(f"Failed to parse expected JSON output from Gemini: {json_err}")
                    raise LLMValidationException(f"Gemini returned malformed JSON output: {json_err}") from json_err

            record_provider_success(self.model, is_agent_request=True, latency_ms=elapsed_ms)
            return LLMResponse(
                content=str(text_content),
                parsed_json=parsed_json,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency_ms=elapsed_ms,
                provider="gemini",
                model=self.model,
            )
        except Exception as e:
            if isinstance(e, LLMException):
                raise
            record_provider_failure("VALIDATION_ERROR")
            logger.error(f"Malformed Gemini API response parsing error: {e}")
            raise LLMValidationException(f"Failed to parse Gemini response: {e}") from e
