"""Versioned measurement evidence; payloads stay in memory during a run."""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch


EVALUATOR_VERSION = "evaluator_v4_gate2"
SEMANTIC_RUBRIC_VERSION = "semantic_rubric_v1"
# Version the OFF/ON experiment profile independently of the scoring rubric.
WORKFLOW_PROFILE_VERSION = "unprotected_off_v3_neutral_context"


@dataclass
class FinalAnswerEvidence:
    parts: tuple[Any, ...] | None = None
    rendered: str | None = None

    def parts_for(self, final_answer: str) -> tuple[Any, ...] | None:
        # A subsequent assembled guard may replace/redact the rendered output.
        # Never attribute the pre-guard candidate to that changed final answer.
        return self.parts if self.rendered == final_answer else None

    def answer_body(self, final_answer: str) -> str | None:
        parts = self.parts_for(final_answer)
        if parts is None:
            return None
        return "\n\n".join(
            part.text for part in parts
            if part.channel not in {"caller_quote", "runtime_template"}
            and part.purpose != "evidence_echo"
        )


@contextmanager
def observe_final_answer(planner_module=None):
    """Observe accepted parts at rendering, before the per-run registry closes.

    Frozen baseline A has no structured renderer: its evidence stays unknown.
    This instrumentation neither changes prompts/decisions nor persists text.
    """
    if planner_module is None:
        import agents.planner as planner_module
    evidence = FinalAnswerEvidence()
    renderer = getattr(planner_module, "render_parts", None)
    if renderer is None:
        yield evidence
        return

    def record(parts):
        rendered = renderer(parts)
        evidence.parts = tuple(parts)
        evidence.rendered = rendered
        return rendered

    from graph import baseline
    baseline_renderer = baseline.render_parts

    def record_baseline(parts):
        rendered = baseline_renderer(parts)
        evidence.parts = tuple(parts)
        evidence.rendered = rendered
        return rendered

    with patch.object(planner_module, "render_parts", side_effect=record), patch.object(
        baseline, "render_parts", side_effect=record_baseline
    ):
        yield evidence


def operational_error(state: dict) -> bool:
    execution = state.get("execution_result") or {}
    decision = state.get("runtime_decision") or {}
    return (
        bool(state.get("errors"))
        or (isinstance(decision, dict) and decision.get("kind") == "error")
        or (isinstance(execution, dict) and execution.get("status") == "error")
        or state.get("tool_status") == "error"
    )


def injection_event(event: dict, *, stage: str | None = None) -> bool:
    return (
        (stage is None or event.get("stage") == stage)
        and event.get("attack_type") in {"prompt_injection", "indirect_injection", "prompt_exfiltration", "tool_manipulation"}
    )


def comparable_reports(first: dict, second: dict) -> bool:
    return (
        first.get("evaluator_version") == second.get("evaluator_version") == EVALUATOR_VERSION
        and first.get("workflow_profile_version") == second.get("workflow_profile_version") == WORKFLOW_PROFILE_VERSION
        and not first.get("simulate_off_impact")
        and not second.get("simulate_off_impact")
    )
