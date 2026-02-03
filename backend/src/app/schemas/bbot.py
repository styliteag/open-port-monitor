"""Bbot scan schemas for API requests and responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class BbotScanTriggerRequest(BaseModel):
    """Request schema for triggering a new bbot scan."""

    network_id: int
    target: str
    modules: str | None = None  # Comma-separated list of bbot modules


class BbotScanTriggerResponse(BaseModel):
    """Response when triggering a bbot scan."""

    scan_id: int
    message: str


class BbotFindingResponse(BaseModel):
    """Bbot finding response schema."""

    id: int
    bbot_scan_id: int
    timestamp: datetime
    event_type: str
    data: str
    host: str | None
    port: int | None
    protocol: str | None
    module: str | None
    severity: str | None
    tags: list[str] | None
    raw_event: dict[str, Any] | None

    model_config = {"from_attributes": True}


class BbotScanResponse(BaseModel):
    """Bbot scan response schema."""

    id: int
    network_id: int
    scanner_id: int | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    cancelled_by: int | None
    cancelled_by_email: str | None
    error_message: str | None
    target: str
    modules: str | None
    findings_count: int | None = None

    model_config = {"from_attributes": True}


class BbotScanDetailResponse(BaseModel):
    """Detailed bbot scan response with findings."""

    id: int
    network_id: int
    scanner_id: int | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    cancelled_by: int | None
    cancelled_by_email: str | None
    error_message: str | None
    target: str
    modules: str | None
    findings: list[BbotFindingResponse]

    model_config = {"from_attributes": True}


class BbotScanListResponse(BaseModel):
    """List of bbot scans."""

    scans: list[BbotScanResponse]
    total: int


class BbotFindingListResponse(BaseModel):
    """List of bbot findings."""

    findings: list[BbotFindingResponse]
    total: int


class BbotScanResultSubmission(BaseModel):
    """Schema for scanner to submit bbot scan results."""

    findings: list[dict[str, Any]]  # List of raw bbot events
