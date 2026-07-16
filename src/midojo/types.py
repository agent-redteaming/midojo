from typing import Literal

from pydantic import BaseModel, ConfigDict, SerializeAsAny


class Environment(BaseModel):
    """Base class for suite environments."""

    ...


class ToolModification(BaseModel):
    """Describes how to modify a tool definition for tool poisoning attacks."""

    tool_name: str
    append_to_description: str | None = None
    replace_description: str | None = None


class MemoryEntry(BaseModel):
    """A poisoned memory entry to pre-populate in the agent's memory store."""

    content: str
    source: str = "system"
    relevance: float = 1.0


class OutputHook(BaseModel):
    """Describes how to modify a tool's return value at runtime."""

    tool_name: str
    inject_in_response: str
    inject_mode: Literal["append", "prepend"] = "append"


class PromptModification(BaseModel):
    """Describes how to modify the user task prompt for direct injection."""

    mode: Literal["prepend", "append"] = "append"
    content: str


class FunctionCallRecord(BaseModel):
    """A recorded function call execution (function + args + result + env snapshots)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    function: str
    args: dict
    result: str
    error: str | None = None
    timestamp: str
    pre_environment: SerializeAsAny[Environment]
    post_environment: SerializeAsAny[Environment]
