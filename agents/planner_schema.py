"""Schema quyết định route của Planner Agent."""

from pydantic import BaseModel, Field

from graph.routes import ClassifierRoute

# Alias giữ tương thích với các import cũ của project.
PlannerRoute = ClassifierRoute


class RouteDecision(BaseModel):
    """Kết quả phân loại route có giới hạn giá trị rõ ràng."""

    route: PlannerRoute = Field(description="Route phù hợp với yêu cầu người dùng.")
