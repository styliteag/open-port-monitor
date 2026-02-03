"""Service scan result schemas for API responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ServiceScanResultResponse(BaseModel):
    """Service scan result for a single host/port."""

    id: int
    scan_id: int
    host_ip: str
    port: int
    protocol: str
    service_name: str | None
    timestamp: datetime

    # HTTP-specific fields
    http_title: str | None = None
    http_status: int | None = None
    http_server: str | None = None
    http_methods: list[str] | None = None
    http_headers: dict[str, Any] | None = None

    # Generic NSE script output
    nse_scripts: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class ServiceScanResultListResponse(BaseModel):
    """List of service scan results."""

    service_results: list[ServiceScanResultResponse]


class ServiceHostSummary(BaseModel):
    """Summary of service scan for a host."""

    host_ip: str
    port: int
    protocol: str
    service_name: str | None
    http_title: str | None = None
    http_status: int | None = None
    http_server: str | None = None
    last_scan_id: int
    last_scanned: datetime
    network_id: int | None = None
    network_name: str | None = None


class ServiceHostListResponse(BaseModel):
    """Paginated list of service scan hosts."""

    services: list[ServiceHostSummary]
    total: int


class ServiceHistoryEntry(BaseModel):
    """Service scan result entry for host history."""

    scan_id: int
    timestamp: datetime
    service_name: str | None
    http_title: str | None = None
    http_status: int | None = None
    http_server: str | None = None
    http_methods: list[str] | None = None
    nse_scripts: dict[str, Any] | None = None
    network_id: int | None = None
    network_name: str | None = None

    model_config = {"from_attributes": True}


class ServiceHistoryResponse(BaseModel):
    """Service scan history for a single host/port."""

    host_ip: str
    port: int
    protocol: str
    history: list[ServiceHistoryEntry]
    total: int
