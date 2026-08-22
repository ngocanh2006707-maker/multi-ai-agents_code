"""Nguồn định nghĩa route duy nhất cho Planner và shared state."""

from typing import Literal, get_args


ClassifierRoute = Literal[
    "DIRECT_RESPONSE",
    "RESEARCH",
    "ANALYSIS",
    "RESEARCH_AND_ANALYSIS",
    "EXECUTE",
    "RESEARCH_ANALYSIS_EXECUTE",
    "OUT_OF_SCOPE",
]

# SECURITY_BLOCKED là trạng thái do Input Guard tạo ra, không phải nhãn để LLM chọn.
Route = ClassifierRoute | Literal["SECURITY_BLOCKED"]

CLASSIFIER_ROUTES: tuple[str, ...] = get_args(ClassifierRoute)

ROUTE_TO_PLAN: dict[str, list[str]] = {
    "DIRECT_RESPONSE": [],
    "RESEARCH": ["research"],
    "ANALYSIS": ["analyst"],
    "RESEARCH_AND_ANALYSIS": ["research", "analyst"],
    "EXECUTE": ["executor"],
    "RESEARCH_ANALYSIS_EXECUTE": ["research", "analyst", "executor"],
    "OUT_OF_SCOPE": [],
    "SECURITY_BLOCKED": [],
}
