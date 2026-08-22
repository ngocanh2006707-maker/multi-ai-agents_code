import pytest

from graph.router import route_planner


@pytest.mark.parametrize("agent", ["research", "analyst", "executor", "final"])
def test_route_planner_accepts_known_next_agent(agent):
    assert route_planner({"next_agent": agent}) == agent


def test_route_planner_rejects_unknown_next_agent():
    with pytest.raises(ValueError):
        route_planner({"next_agent": "shell"})


def test_route_planner_rejects_missing_next_agent():
    with pytest.raises(ValueError):
        route_planner({})
