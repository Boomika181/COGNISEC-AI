"""
Agent Tool Abstraction and Permission Sandboxing.
"""
from typing import Callable, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class UnauthorizedToolError(Exception):
    """Raised when an agent attempts to execute a tool not in its permitted list."""
    pass


class ToolExecutionError(Exception):
    """Raised when tool execution encounters an unhandled runtime error."""
    pass


class AgentTool(BaseModel):
    """Encapsulates a sandboxed tool exposed to agents."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str
    func: Callable[..., Any] = Field(exclude=True)
    is_read_only: bool = True

    def execute(self, **kwargs) -> Any:
        try:
            return self.func(**kwargs)
        except Exception as e:
            raise ToolExecutionError(f"Error executing tool '{self.name}': {e}") from e


def tool(name: str, description: str, is_read_only: bool = True):
    """Decorator to define a sandboxed AgentTool."""
    def decorator(fn: Callable[..., Any]) -> AgentTool:
        return AgentTool(
            name=name,
            description=description,
            func=fn,
            is_read_only=is_read_only
        )
    return decorator
