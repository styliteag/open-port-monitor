"""Executive overview endpoint (UI v3, ADR 0005)."""

from fastapi import APIRouter

from app.core.deps import CurrentUser, DbSession
from app.schemas.overview import ExecutiveOverviewResponse
from app.services import overview as overview_service

router = APIRouter(prefix="/api/overview", tags=["overview"])


@router.get("/executive", response_model=ExecutiveOverviewResponse)
async def get_executive_overview(
    user: CurrentUser,
    db: DbSession,
) -> ExecutiveOverviewResponse:
    """Read-only management overview: traffic lights, top risks, totals."""
    data = await overview_service.get_executive_overview(db)
    return ExecutiveOverviewResponse.model_validate(data)
