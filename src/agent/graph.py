"""Phase 6c: assembles the investigation StateGraph."""
from __future__ import annotations

from functools import partial

from langgraph.graph import END, StateGraph

from src.agent.llm_client import LLMClient
from src.agent.nodes import (
    auto_resolve_node,
    escalate_node,
    feedback_memory_node,
    planner_node,
    reflect_node,
    route_after_verdict,
    tool_execution_node,
    verdict_escalate_node,
    verdict_node,
)
from src.agent.routing import route_after_planner, route_after_reflect
from src.agent.state import InvestigationState
from src.tools.registry import ToolRegistry


def build_graph(
    llm_client: LLMClient,
    registry: ToolRegistry,
    data_sources: dict,
    conn,
    true_label_lookup: dict[str, str] | None = None,
):
    graph = StateGraph(InvestigationState)

    graph.add_node("planner", partial(planner_node, llm_client=llm_client))
    graph.add_node("tool_execution", partial(tool_execution_node, registry=registry, data_sources=data_sources))
    graph.add_node("reflect", partial(reflect_node, llm_client=llm_client))
    graph.add_node("verdict_escalate", verdict_escalate_node)
    graph.add_node("verdict", verdict_node)
    graph.add_node("escalate", escalate_node)
    graph.add_node("auto_resolve", auto_resolve_node)
    graph.add_node("feedback_memory", partial(
        feedback_memory_node, conn=conn, llm_client=llm_client, true_label_lookup=true_label_lookup
    ))

    graph.set_entry_point("planner")

    graph.add_conditional_edges(
        "planner", route_after_planner,
        {"tool_execution": "tool_execution", "reflect": "reflect"},
    )
    graph.add_edge("tool_execution", "reflect")

    graph.add_conditional_edges(
        "reflect", route_after_reflect,
        {"planner": "planner", "verdict": "verdict", "verdict_escalate": "verdict_escalate"},
    )
    graph.add_edge("verdict_escalate", "verdict")

    graph.add_conditional_edges(
        "verdict", route_after_verdict,
        {"escalate": "escalate", "auto_resolve": "auto_resolve"},
    )
    graph.add_edge("escalate", "feedback_memory")
    graph.add_edge("auto_resolve", "feedback_memory")
    graph.add_edge("feedback_memory", END)

    return graph.compile()
