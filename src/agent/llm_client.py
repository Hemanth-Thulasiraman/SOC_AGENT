"""
Phase 6c: the LLM client boundary. `planner`/`reflect` nodes call this
interface, not the Anthropic SDK directly, so the real client and the
demo stub are interchangeable without touching node code.
"""
from __future__ import annotations

from typing import Protocol

from dotenv import load_dotenv

load_dotenv()

from src.agent.prompts import (
    PLANNER_SYSTEM_PROMPT,
    REFLECT_SYSTEM_PROMPT,
    REFLECTION_DECISION_TOOL,
    format_alert_and_evidence,
)


class LLMClient(Protocol):
    def call_planner(self, alert_type: str, raw_evidence: dict, evidence: list[dict], tool_schemas: list[dict]) -> dict: ...
    def call_reflect(self, alert_type: str, raw_evidence: dict, evidence: list[dict]) -> dict: ...
    def summarize(self, prompt: str) -> str: ...


class AnthropicLLMClient:
    """Real client. Requires ANTHROPIC_API_KEY -- not exercised in this
    environment (no key present), but structurally what a real run uses."""

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic
        self._client = anthropic.Anthropic()
        self._model = model

    def call_planner(self, alert_type, raw_evidence, evidence, tool_schemas) -> dict:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=PLANNER_SYSTEM_PROMPT,
            tools=tool_schemas,
            messages=[{"role": "user", "content": format_alert_and_evidence(alert_type, raw_evidence, evidence)}],
        )
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            return {"action": "no_tool_needed"}
        return {"action": "call_tool", "tool_name": tool_use_blocks[0].name}

    def call_reflect(self, alert_type, raw_evidence, evidence) -> dict:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=REFLECT_SYSTEM_PROMPT,
            tools=[REFLECTION_DECISION_TOOL],
            tool_choice={"type": "tool", "name": "submit_reflection_decision"},
            messages=[{"role": "user", "content": format_alert_and_evidence(alert_type, raw_evidence, evidence)}],
        )
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        decision_input = tool_use_blocks[0].input
        return {"decision": decision_input["decision"], "reasoning": decision_input["reasoning"]}

    def summarize(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=128,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()


def _to_openai_tool(schema: dict) -> dict:
    """Anthropic-format {name, description, input_schema} -> OpenAI's {type, function}."""
    return {
        "type": "function",
        "function": {
            "name": schema["name"],
            "description": schema["description"],
            "parameters": schema["input_schema"],
        },
    }


class OpenAILLMClient:
    """
    Real client, OpenAI backend. Requires OPENAI_API_KEY. Implements the
    same LLMClient interface as AnthropicLLMClient -- node code never
    touches this class directly, so swapping providers is a one-line
    change at graph-construction time, not a rewrite.

    Tracks real cumulative token usage (self.usage) across every call made
    through this instance -- one client per eval run gives an honest
    measured cost-per-investigation, not a guess extrapolated from
    published per-call estimates.
    """

    # Public per-1M-token pricing at time of writing -- not billing-API-
    # verified, just enough to turn tracked usage into an approximate
    # dollar figure for the eval report.
    INPUT_COST_PER_1M = 2.50
    OUTPUT_COST_PER_1M = 10.00

    def __init__(self, model: str = "gpt-4o"):
        import openai
        self._client = openai.OpenAI()
        self._model = model
        self.usage = {"input_tokens": 0, "output_tokens": 0}

    def _track(self, response) -> None:
        if response.usage:
            self.usage["input_tokens"] += response.usage.prompt_tokens
            self.usage["output_tokens"] += response.usage.completion_tokens

    def estimated_cost_usd(self) -> float:
        return (
            self.usage["input_tokens"] / 1_000_000 * self.INPUT_COST_PER_1M
            + self.usage["output_tokens"] / 1_000_000 * self.OUTPUT_COST_PER_1M
        )

    def call_planner(self, alert_type, raw_evidence, evidence, tool_schemas) -> dict:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=512,
            tools=[_to_openai_tool(s) for s in tool_schemas],
            tool_choice="auto",
            messages=[
                {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                {"role": "user", "content": format_alert_and_evidence(alert_type, raw_evidence, evidence)},
            ],
        )
        self._track(response)
        tool_calls = response.choices[0].message.tool_calls
        if not tool_calls:
            return {"action": "no_tool_needed"}
        return {"action": "call_tool", "tool_name": tool_calls[0].function.name}

    def call_reflect(self, alert_type, raw_evidence, evidence) -> dict:
        import json

        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=512,
            tools=[_to_openai_tool(REFLECTION_DECISION_TOOL)],
            tool_choice={"type": "function", "function": {"name": "submit_reflection_decision"}},
            messages=[
                {"role": "system", "content": REFLECT_SYSTEM_PROMPT},
                {"role": "user", "content": format_alert_and_evidence(alert_type, raw_evidence, evidence)},
            ],
        )
        self._track(response)
        tool_call = response.choices[0].message.tool_calls[0]
        args = json.loads(tool_call.function.arguments)
        return {"decision": args["decision"], "reasoning": args["reasoning"]}

    def summarize(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=128,
            messages=[{"role": "user", "content": prompt}],
        )
        self._track(response)
        return response.choices[0].message.content.strip()

    def call_classifier(self, system: str, user: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=16,  # just one of three words
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content.strip()


class StubLLMClient:
    """
    Deterministic stand-in for demo/testing without an API key. Planner
    calls each tool relevant to the alert type once, in a fixed order,
    then declines. Reflect is blind to tool availability (matches the
    real prompt's contract) -- it judges purely on evidence: continue if
    the weighted confidence magnitude so far is still ambiguous, verdict
    once it's not. This is what lets it demonstrate route_after_reflect's
    no_tools_left forced-escalate path organically, exactly like a real
    model reasoning itself into a corner would.
    """

    CONFIDENCE_SUFFICIENT_THRESHOLD = 0.4

    def call_planner(self, alert_type, raw_evidence, evidence, tool_schemas) -> dict:
        already_called = {e["tool_name"] for e in evidence}
        available = [s["name"] for s in tool_schemas if s["name"] not in already_called]
        if not available:
            return {"action": "no_tool_needed"}
        return {"action": "call_tool", "tool_name": available[0]}

    def call_reflect(self, alert_type, raw_evidence, evidence) -> dict:
        from src.agent.confidence import compute_confidence

        magnitude, _leaning = compute_confidence(alert_type, evidence)
        if magnitude < self.CONFIDENCE_SUFFICIENT_THRESHOLD:
            return {"decision": "continue", "reasoning": "evidence so far is still ambiguous"}
        return {"decision": "verdict", "reasoning": "evidence is sufficient to conclude"}

    def summarize(self, prompt: str) -> str:
        return "Stub summary (no LLM call made)."

    def call_classifier(self, system: str, user: str) -> str:
        if "alert type if known: phishing" in user.lower():
            return "phishing"
        if "alert type if known: lateral_movement" in user.lower():
            return "lateral_movement"
        if "alert type if known: insider_threat" in user.lower():
            return "insider_threat"
        # fallback: infer from field names
        if "sender_domain" in user or "click" in user:
            return "phishing"
        if "source_ip" in user or "dest_ip" in user:
            return "lateral_movement"
        return "insider_threat"