"""
LLM Client Factory for Instantiating Configured Provider Adapters
and Reporting Safe Provider Health Telemetry.
"""
import logging
from typing import Optional, Dict, Any

from app.core.config import settings
from app.agents.core.llm_client import LLMClient
from app.agents.core.gemini_client import (
    GeminiLLMClient,
    get_gemini_runtime_state,
    record_provider_failure,
)
from app.agents.core.mock_client import MockLLMClient

logger = logging.getLogger("cognisec.agents.factory")


def get_llm_client(provider: Optional[str] = None, **kwargs) -> LLMClient:
    """
    Returns the configured LLM client adapter based on settings.LLM_PROVIDER
    or explicit caller override.

    Never silently switches from 'gemini' to 'mock' when Gemini credentials
    are missing or invalid; instead logs the configuration error clearly and
    returns GeminiLLMClient so callers fail closed to deterministic fallbacks.
    """
    chosen_provider = (provider or settings.LLM_PROVIDER or "mock").strip().lower()

    if chosen_provider == "gemini":
        client = GeminiLLMClient(**kwargs)
        if not client.validate_configuration():
            logger.error(
                "LLM_PROVIDER='gemini' selected, but GEMINI_API_KEY is missing or invalid. "
                "Refusing silent fallback to MockLLMClient; deterministic agent fallbacks will be used."
            )
            record_provider_failure("MISSING_API_KEY")
        return client
    elif chosen_provider == "mock":
        return MockLLMClient(**kwargs)
    else:
        logger.warning(f"Unrecognized LLM provider '{chosen_provider}'. Defaulting to MockLLMClient.")
        return MockLLMClient(**kwargs)


def get_provider_health_status() -> Dict[str, Any]:
    """
    Returns safe, credential-free provider health metadata distinguishing:
    - Provider configured
    - Provider credentials present
    - Provider connectivity verified
    - Actual agent request successfully completed
    """
    chosen_provider = (settings.LLM_PROVIDER or "mock").strip().lower()

    if chosen_provider == "mock":
        return {
            "configured_provider": "mock",
            "configured_model": "mock-v1",
            "provider_configured": True,
            "credentials_present": True,
            "connectivity_verified": True,
            "agent_request_succeeded": True,
            "connectivity_status": "MOCK_MODE",
            "last_successful_check": None,
            "last_failure_category": None,
        }

    if chosen_provider == "gemini":
        effective_model = (
            getattr(settings, "GEMINI_MODEL", None)
            or settings.LLM_MODEL
            or "gemini-3.5-flash-lite"
        )
        credentials_present = bool(settings.GEMINI_API_KEY and str(settings.GEMINI_API_KEY).strip())
        runtime_state = get_gemini_runtime_state()
        connectivity_verified = bool(runtime_state.get("connectivity_verified", False)) and credentials_present
        agent_succeeded = bool(runtime_state.get("agent_request_succeeded", False)) and credentials_present
        last_failure = runtime_state.get("last_failure_category")

        if not credentials_present:
            status = "MISCONFIGURED"
            last_failure = last_failure or "MISSING_API_KEY"
            api_conn = "Failed"
        elif connectivity_verified:
            status = "VERIFIED"
            api_conn = "Connected"
        elif last_failure in ("AUTHENTICATION_ERROR", "MODEL_UNAVAILABLE", "PROVIDER_ERROR", "NETWORK_ERROR", "TIMEOUT", "RATE_LIMIT"):
            status = "UNAVAILABLE"
            api_conn = "Failed"
        else:
            status = "UNVERIFIED"
            api_conn = "Not checked"

        return {
            "configured_provider": "gemini",
            "configured_model": effective_model,
            "provider_configured": True,
            "credentials_present": credentials_present,
            "connectivity_verified": connectivity_verified,
            "agent_request_succeeded": agent_succeeded,
            "connectivity_status": status,
            "api_connectivity": api_conn,
            "test_generation": runtime_state.get("test_generation_status", "Not tested") if credentials_present else "Failed",
            "test_generation_status": runtime_state.get("test_generation_status", "Not tested") if credentials_present else "Failed",
            "last_successful_check": runtime_state.get("last_successful_check") if credentials_present else None,
            "last_failure_category": last_failure,
            "last_failure_reason": runtime_state.get("last_failure_reason") or (last_failure if last_failure else None),
            "total_requests": int(runtime_state.get("total_requests") or 0),
            "successful_requests": int(runtime_state.get("successful_requests") or 0),
            "failed_requests": int(runtime_state.get("failed_requests") or 0),
            "timeout_errors": int(runtime_state.get("timeout_errors") or 0),
            "rate_limit_errors": int(runtime_state.get("rate_limit_errors") or 0),
            "last_latency_ms": runtime_state.get("last_latency_ms"),
            "avg_latency_ms": runtime_state.get("avg_latency_ms"),
        }

    return {
        "configured_provider": chosen_provider,
        "configured_model": "unknown",
        "provider_configured": False,
        "credentials_present": False,
        "connectivity_verified": False,
        "agent_request_succeeded": False,
        "connectivity_status": "MISCONFIGURED",
        "last_successful_check": None,
        "last_failure_category": "UNRECOGNIZED_PROVIDER",
    }
