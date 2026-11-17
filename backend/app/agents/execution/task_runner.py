"""
Asynchronous Non-Blocking Execution Runner for Agent Workflows.
Implements in-process concurrency without requiring external infrastructure (Redis/Celery).
"""
import logging
import asyncio
from typing import Coroutine, Any, Optional

logger = logging.getLogger("cognisec.agents.executor")


async def run_with_timeout(
    coro: Coroutine[Any, Any, Any],
    timeout_seconds: float,
    fallback_value: Any = None
) -> Any:
    """
    Executes a coroutine with a strict time budget.
    Returns fallback_value on timeout or error without raising.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"Asynchronous task exceeded timeout budget of {timeout_seconds}s. Falling back.")
        return fallback_value
    except Exception as e:
        logger.error(f"Error executing asynchronous task: {e}. Falling back.")
        return fallback_value


def dispatch_background_task(coro: Coroutine[Any, Any, Any]) -> asyncio.Task:
    """
    Schedules an asynchronous coroutine as an independent background task in the event loop.
    Enforces a strict safety wrapper to prevent unhandled exceptions from terminating the server.
    """
    async def _safe_wrapper():
        try:
            await coro
        except Exception as e:
            logger.error(f"Unhandled background agent task failure: {e}", exc_info=True)

    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(_safe_wrapper())
    except RuntimeError:
        # If called outside a running event loop (e.g. sync thread), run with asyncio.run
        logger.warning("No running asyncio event loop detected. Spawning one-shot loop.")
        return asyncio.run(_safe_wrapper())

