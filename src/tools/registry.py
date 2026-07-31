"""
Phase 6a: tool dispatch.

circuit_breakers is passed in and a new dict is returned -- never mutated
in place -- so this composes as a LangGraph node (state in, state out)
rather than depending on hidden mutable global state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal

ToolStatus = Literal["success", "failure"]


@dataclass
class ToolResult:
    tool_name: str
    status: ToolStatus
    evidence: str | None  # always a string (possibly "") on success, always None on failure
    timestamp: datetime


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _closed_breaker() -> dict:
    return {"status": "closed", "failure_count": 0, "last_attempt": None}


class ToolRegistry:
    def __init__(self, tools: dict[str, Callable[..., str]]):
        # each tool: callable(**kwargs) -> str evidence; raises on failure
        self._tools = tools

    def dispatch(self, tool_name: str, circuit_breakers: dict, **kwargs) -> tuple[ToolResult, dict]:
        breaker = circuit_breakers.get(tool_name, _closed_breaker())

        if breaker["status"] == "open":
            return ToolResult(tool_name, "failure", None, _now()), circuit_breakers

        result = self._attempt_with_retry(tool_name, **kwargs)

        if result.status == "failure":
            updated_breaker = {
                "status": "open",
                "failure_count": breaker["failure_count"] + 1,
                "last_attempt": result.timestamp,
            }
        else:
            updated_breaker = {
                "status": "closed",
                "failure_count": 0,
                "last_attempt": result.timestamp,
            }

        return result, {**circuit_breakers, tool_name: updated_breaker}

    def _attempt_with_retry(self, tool_name: str, **kwargs) -> ToolResult:
        tool = self._tools[tool_name]
        for _ in range(2):  # one attempt, one retry
            try:
                evidence = tool(**kwargs)
                return ToolResult(tool_name, "success", evidence, _now())
            except Exception:
                continue
        return ToolResult(tool_name, "failure", None, _now())
