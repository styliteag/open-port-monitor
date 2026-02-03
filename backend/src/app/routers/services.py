"""Service scan result endpoints for HTTP and NSE script results."""

from fastapi import APIRouter, HTTPException, Query, status

from app.core.deps import CurrentUser, DbSession
from app.schemas.service import (
    ServiceHistoryEntry,
    ServiceHistoryResponse,
    ServiceHostListResponse,
    ServiceHostSummary,
    ServiceScanResultListResponse,
    ServiceScanResultResponse,
)
from app.services import scans as scans_service
from app.services import service_results as service_service

router = APIRouter(prefix="/api", tags=["services"])


@router.get("/scans/{scan_id}/services", response_model=ServiceScanResultListResponse)
async def get_scan_service_results(
    user: CurrentUser,
    db: DbSession,
    scan_id: int,
) -> ServiceScanResultListResponse:
    """Get service scan results (HTTP/NSE) for a specific scan."""
    # Verify scan exists
    scan = await scans_service.get_scan_by_id(db, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    service_results = await service_service.get_service_results_for_scan(db, scan_id)
    return ServiceScanResultListResponse(
        service_results=[ServiceScanResultResponse.model_validate(r) for r in service_results]
    )


@router.get("/services/hosts", response_model=ServiceHostListResponse)
async def list_service_hosts(
    user: CurrentUser,
    db: DbSession,
    network_id: int | None = Query(None, ge=1, description="Filter by network ID"),
    service_name: str | None = Query(None, description="Filter by service name"),
    http_server: str | None = Query(None, description="Filter by HTTP server"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Number of results (max 200)"),
) -> ServiceHostListResponse:
    """
    List all hosts with service scan data, showing the latest result for each host/port.

    Supports filtering by network, service name, and HTTP server.
    Returns paginated results.
    """
    services, total = await service_service.get_service_hosts(
        db,
        network_id=network_id,
        service_name=service_name,
        http_server=http_server,
        offset=offset,
        limit=limit,
    )

    service_summaries: list[ServiceHostSummary] = []
    for service in services:
        service_summaries.append(
            ServiceHostSummary(
                host_ip=service.host_ip,
                port=service.port,
                protocol=service.protocol,
                service_name=service.service_name,
                http_title=service.http_title,
                http_status=service.http_status,
                http_server=service.http_server,
                last_scan_id=service.scan_id,
                last_scanned=service.timestamp,
                network_id=service.network_id if hasattr(service, "network_id") else None,
                network_name=service.network_name if hasattr(service, "network_name") else None,
            )
        )

    return ServiceHostListResponse(services=service_summaries, total=total)


@router.get("/services/hosts/{host_ip}/{port}", response_model=ServiceHistoryResponse)
async def get_service_host_history(
    user: CurrentUser,
    db: DbSession,
    host_ip: str,
    port: int,
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Number of results (max 200)"),
) -> ServiceHistoryResponse:
    """Get service scan history for a specific host and port."""
    history, total = await service_service.get_service_history(
        db, host_ip, port, offset=offset, limit=limit
    )

    history_entries: list[ServiceHistoryEntry] = []
    for entry in history:
        history_entries.append(
            ServiceHistoryEntry(
                scan_id=entry.scan_id,
                timestamp=entry.timestamp,
                service_name=entry.service_name,
                http_title=entry.http_title,
                http_status=entry.http_status,
                http_server=entry.http_server,
                http_methods=entry.http_methods,
                nse_scripts=entry.nse_scripts,
                network_id=entry.network_id if hasattr(entry, "network_id") else None,
                network_name=entry.network_name if hasattr(entry, "network_name") else None,
            )
        )

    return ServiceHistoryResponse(
        host_ip=host_ip,
        port=port,
        protocol="tcp",  # Default to tcp
        history=history_entries,
        total=total,
    )
