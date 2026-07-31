"""
Phase 6c: conditional routing after the `reflect` node.

Cap checks live here, not inside `planner` or `reflect` -- same separation
as 6a's tool registry (it doesn't know about tool_call_count; the
orchestrating layer does). Whatever `reflect` decided, a cap breach always
wins: the loop is not allowed to continue past the hard bounds regardless
of how confident the model is that it needs one more cycle.

Locked requirement on the `planner`/`reflect` prompts (whenever they're
written): they must never be told planning_count, tool_call_count, or
either cap. A model that knows it's on "cycle 6 of 6" has a reason to say
"done" that has nothing to do with the evidence being sufficient -- it may
be avoiding a forced escalation it didn't choose rather than genuinely
concluding the investigation is complete. That turns "done" into an
ambiguous signal no post-hoc trace review can untangle, which corrupts
the exact thing confidence_score is supposed to honestly represent. A
model that stops at the cap with no knowledge the cap existed is a real
coincidence (evidence-driven reasoning happened to land there); a model
told the cap in advance is a confound.
"""
from __future__ import annotations

from typing import Literal

PLANNING_COUNT_CAP = 6
TOOL_CALL_COUNT_CAP = 12

PlannerRoute = Literal["tool_execution", "reflect"]
RouteName = Literal["planner", "verdict", "verdict_escalate"]


def route_after_planner(state: dict) -> PlannerRoute:
    """
    Routes out of `planner`. If planner declined to name a tool (no
    tool_use block in its response -- see tool_binding.py / the API's
    stop_reason contract), there is nothing for tool_execution to run, so
    this skips it entirely rather than having tool_execution also handle
    "there was nothing to run." One node, one job.
    """
    if state["planner_decision"]["action"] == "no_tool_needed":
        return "reflect"
    return "tool_execution"


def route_after_reflect(state: dict) -> RouteName:
    """
    Routes out of `reflect`. Reads state only -- never mutates it: edge
    functions in LangGraph must stay pure, so forcing escalation_flag=True
    on cap breach is not done here. "verdict_escalate" is wired in the
    graph to a small node whose only job is that state write, before
    rejoining the shared `verdict` node.

    A cap breach only overrides `reflect` when `reflect` actually wanted
    to keep going. If `reflect` already decided it's done, that's a
    voluntary stop, not a denied continuation -- it routes to plain
    `verdict` even if a count happens to be at its cap, since nothing was
    actually blocked.

    no_tools_left gets the identical treatment as a cap breach: reflect is
    never told planner declined (same reasoning as never telling it the
    caps -- knowing continuation is impossible would let it rationalize
    "done" to dodge a forced escalation it didn't choose). So if reflect
    genuinely wants more evidence but planner had nothing left to offer,
    that desire-that-couldn't-be-met is a real signal on its own merits,
    caught here purely from state reflect never saw.
    """
    wants_to_continue = state["reflection_decision"] == "continue"
    cap_breached = (
        state["planning_count"] >= PLANNING_COUNT_CAP
        or state["tool_call_count"] >= TOOL_CALL_COUNT_CAP
    )
    no_tools_left = state.get("planner_decision", {}).get("action") == "no_tool_needed"

    if wants_to_continue and (cap_breached or no_tools_left):
        return "verdict_escalate"
    if wants_to_continue:
        return "planner"
    return "verdict"
