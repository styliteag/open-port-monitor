"""Executive overview schemas (UI v3, ADR 0005)."""

from pydantic import BaseModel


class NetworkStatusEntry(BaseModel):
    """Traffic-light status for one network."""

    network_id: int
    name: str
    status: str  # "red" (open critical) | "amber" (open high) | "green"
    open_critical: int
    open_high: int
    open_total: int


class TopRiskEntry(BaseModel):
    """One of the currently highest-priority open alerts."""

    alert_id: int
    message: str
    severity: str
    ip: str
    port: int | None
    network_name: str | None


class ExecutiveOverviewResponse(BaseModel):
    """Read-only management overview."""

    networks: list[NetworkStatusEntry]
    top_risks: list[TopRiskEntry]
    open_alerts: int
    handled_alerts_30d: int
