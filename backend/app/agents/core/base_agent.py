"""
Base Agent Abstract Class with Sandboxed Tooling, Schema Enforcement,
Bounded Retries, and Fail-Secure Deterministic Fallback.
"""
import time
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Type, Dict, Any, Set, Optional
from pydantic import BaseModel, ValidationError

from app.core.config import settings
from app.agents.core.llm_client import (
    LLMClient,
    LLMException,
    LLMTimeoutException,
    LLMAuthenticationException,
)
from app.agents.core.factory import get_llm_client
from app.agents.core.tool import AgentTool, UnauthorizedToolError

logger = logging.getLogger("cognisec.agents.base")


class BaseAgent(ABC):
    """
    Abstract Base Class for all specialized agents in Cognisec AI.
    Guarantees:
    - Inputs & outputs conform strictly to configured Pydantic schemas.
    - Sandboxed tool execution with explicit capability whitelist.
    - Hard timeouts and bounded retry policies.
    - Seamless fail-secure deterministic fallback on any failure.
    """

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Type[BaseModel],
        output_schema: Type[BaseModel],
        permitted_tools: Optional[Set[str]] = None,
        llm_client: Optional[LLMClient] = None,
        timeout_seconds: Optional[float] = None,
        max_retries: Optional[int] = None
    ):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.permitted_tool_names: Set[str] = permitted_tools or set()
        self.tools: Dict[str, AgentTool] = {}
        self.llm_client: LLMClient = llm_client or get_llm_client()
        default_agent_timeout = max(
            float(getattr(settings, "LLM_TIMEOUT_SECONDS", 2.0) or 2.0) + 1.0,
            float(getattr(settings, "AGENT_EXECUTION_TIMEOUT_SECONDS", 0.8) or 0.8),
        )
        self.timeout_seconds: float = float(timeout_seconds) if timeout_seconds is not None else default_agent_timeout
        self.max_retries: int = max_retries or settings.LLM_MAX_RETRIES or 2
        self.last_execution_meta: Dict[str, Any] = {}
        self.logger = logging.getLogger(f"cognisec.agent.{self.name}")

    def register_tool(self, tool_instance: AgentTool) -> None:
        """Registers a sandboxed tool with the agent."""
        self.tools[tool_instance.name] = tool_instance

    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Executes a registered tool after verifying whitelist permissions.
        Fails closed with UnauthorizedToolError if the tool is not whitelisted.
        """
        if tool_name not in self.permitted_tool_names:
            msg = f"Agent '{self.name}' is prohibited from executing tool '{tool_name}' (least-privilege violation)."
            self.logger.error(msg)
            raise UnauthorizedToolError(msg)

        if tool_name not in self.tools:
            msg = f"Tool '{tool_name}' is permitted for agent '{self.name}' but has not been registered in runtime."
            self.logger.error(msg)
            raise KeyError(msg)

        self.logger.info(f"Agent '{self.name}' executing permitted tool '{tool_name}'.")
        return self.tools[tool_name].execute(**kwargs)

    async def execute(self, input_data: Any) -> BaseModel:
        """
        Public execution entrypoint.
        Validates input, executes reasoning with bounded retry and timeout,
        and falls back to deterministic behavior on any failure.
        """
        start_time = time.monotonic()

        # 1. Validate Input Schema
        try:
            if isinstance(input_data, dict):
                validated_input = self.input_schema(**input_data)
            elif isinstance(input_data, self.input_schema):
                validated_input = input_data
            else:
                validated_input = self.input_schema.model_validate(input_data)
        except ValidationError as val_err:
            self.logger.error(f"Input validation error for agent '{self.name}': {val_err}")
            self.last_execution_meta = {
                "status": "FALLBACK",
                "attempts": 0,
                "error": f"Input validation error: {str(val_err)[:160]}",
                "duration_ms": 0,
            }
            # Fails closed to deterministic fallback immediately
            return self.get_deterministic_fallback(input_data)

        # 2. Bounded Retry Execution Loop
        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Wrap reasoning call in strict per-agent timeout
                result = await asyncio.wait_for(
                    self._run_reasoning(validated_input),
                    timeout=self.timeout_seconds
                )

                # Validate Output Schema
                if isinstance(result, self.output_schema):
                    validated_output = result
                elif isinstance(result, dict):
                    validated_output = self.output_schema(**result)
                else:
                    validated_output = self.output_schema.model_validate(result)

                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                self.last_execution_meta = {
                    "status": "SUCCESS",
                    "attempts": attempt,
                    "error": None,
                    "duration_ms": elapsed_ms,
                }
                self.logger.info(
                    f"Agent '{self.name}' successfully executed on attempt {attempt} in {elapsed_ms}ms."
                )
                return validated_output

            except LLMAuthenticationException as ae:
                last_error = ae
                self.logger.error(
                    f"Agent '{self.name}' authentication/configuration error: {ae}. "
                    "Engaging fail-secure deterministic fallback immediately."
                )
                break
            except asyncio.TimeoutError as te:
                last_error = te
                self.logger.warning(
                    f"Agent '{self.name}' timeout on attempt {attempt}/{self.max_retries} (> {self.timeout_seconds}s)."
                )
            except LLMException as le:
                last_error = le
                self.logger.warning(
                    f"Agent '{self.name}' LLM provider error on attempt {attempt}/{self.max_retries}: {le}"
                )
            except ValidationError as ve:
                last_error = ve
                self.logger.warning(
                    f"Agent '{self.name}' generated invalid output schema on attempt {attempt}/{self.max_retries}: {ve}"
                )
            except Exception as e:
                last_error = e
                self.logger.error(
                    f"Agent '{self.name}' unexpected error on attempt {attempt}/{self.max_retries}: {e}"
                )

            if attempt < self.max_retries:
                await asyncio.sleep(min(0.05 * attempt, 0.2))

        # 3. Fallback Triggered upon Exhaustion of Retries
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        fb_status = "TIMEOUT" if isinstance(last_error, asyncio.TimeoutError) else "FALLBACK"
        self.last_execution_meta = {
            "status": fb_status,
            "attempts": self.max_retries,
            "error": (str(last_error)[:200] if last_error else "Fallback engaged"),
            "duration_ms": elapsed_ms,
        }
        self.logger.warning(
            f"Agent '{self.name}' failed after {self.max_retries} attempts ({elapsed_ms}ms). "
            f"Engaging fail-secure deterministic fallback. Cause: {last_error}"
        )
        return self.get_deterministic_fallback(validated_input)

    @abstractmethod
    async def _run_reasoning(self, validated_input: BaseModel) -> Any:
        """
        Internal reasoning method implemented by concrete agent modules.
        Must return an instance or dict conforming to self.output_schema.
        """
        pass

    @abstractmethod
    def get_deterministic_fallback(self, input_data: Any) -> BaseModel:
        """
        Authoritative fail-secure deterministic response.
        Guaranteed to produce a valid self.output_schema instance without relying on LLMs.
        """
        pass

