"""Bbot scan endpoints."""

from fastapi import APIRouter, HTTPException, Query, status

from app.core.deps import AdminUser, CurrentUser, DbSession
from app.models.bbot_scan import BbotScanStatus
from app.schemas.bbot import (
    BbotFindingListResponse,
    BbotFindingResponse,
    BbotScanDetailResponse,
    BbotScanListResponse,
    BbotScanResponse,
    BbotScanTriggerRequest,
    BbotScanTriggerResponse,
)
from app.services import bbot_scans as bbot_service
from app.services.networks import get_network_by_id

router = APIRouter(prefix="/api/bbot", tags=["bbot"])


@router.post("/scans", response_model=BbotScanTriggerResponse, status_code=status.HTTP_201_CREATED)
async def trigger_bbot_scan(
    user: AdminUser,
    db: DbSession,
    request: BbotScanTriggerRequest,
) -> BbotScanTriggerResponse:
    """Trigger a new bbot security scan for a network."""
    # Verify network exists
    network = await get_network_by_id(db, request.network_id)
    if not network:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network not found",
        )

    # Create the scan
    bbot_scan = await bbot_service.create_bbot_scan(
        db, network, request.target, request.modules
    )
    await db.commit()

    return BbotScanTriggerResponse(
        scan_id=bbot_scan.id,
        message=f"Bbot scan created for target '{request.target}'",
    )


@router.get("/scans", response_model=BbotScanListResponse)
async def get_bbot_scans(
    user: CurrentUser,
    db: DbSession,
    network_id: int | None = Query(None, ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> BbotScanListResponse:
    """Get all bbot scans with optional network filter."""
    if network_id:
        scan_results = await bbot_service.get_bbot_scans_by_network_id(
            db, network_id, offset, limit
        )
    else:
        scan_results = await bbot_service.get_all_bbot_scans(db, offset, limit)

    scans = [
        BbotScanResponse(
            id=scan.id,
            network_id=scan.network_id,
            scanner_id=scan.scanner_id,
            status=scan.status.value,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            cancelled_at=scan.cancelled_at,
            cancelled_by=scan.cancelled_by,
            cancelled_by_email=scan.cancelled_by_email,
            error_message=scan.error_message,
            target=scan.target,
            modules=scan.modules,
            findings_count=finding_count,
        )
        for scan, finding_count in scan_results
    ]

    return BbotScanListResponse(scans=scans, total=len(scans))


@router.get("/scans/{scan_id}", response_model=BbotScanDetailResponse)
async def get_bbot_scan_detail(
    user: CurrentUser,
    db: DbSession,
    scan_id: int,
) -> BbotScanDetailResponse:
    """Get detailed information about a specific bbot scan including findings."""
    bbot_scan = await bbot_service.get_bbot_scan_with_findings(db, scan_id)
    if not bbot_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bbot scan not found",
        )

    findings = [
        BbotFindingResponse(
            id=f.id,
            bbot_scan_id=f.bbot_scan_id,
            timestamp=f.timestamp,
            event_type=f.event_type,
            data=f.data,
            host=f.host,
            port=f.port,
            protocol=f.protocol,
            module=f.module,
            severity=f.severity,
            tags=f.tags,
            raw_event=f.raw_event,
        )
        for f in bbot_scan.findings
    ]

    return BbotScanDetailResponse(
        id=bbot_scan.id,
        network_id=bbot_scan.network_id,
        scanner_id=bbot_scan.scanner_id,
        status=bbot_scan.status.value,
        started_at=bbot_scan.started_at,
        completed_at=bbot_scan.completed_at,
        cancelled_at=bbot_scan.cancelled_at,
        cancelled_by=bbot_scan.cancelled_by,
        cancelled_by_email=bbot_scan.cancelled_by_email,
        error_message=bbot_scan.error_message,
        target=bbot_scan.target,
        modules=bbot_scan.modules,
        findings=findings,
    )


@router.delete("/scans/{scan_id}/cancel")
async def cancel_bbot_scan(
    user: AdminUser,
    db: DbSession,
    scan_id: int,
) -> dict[str, str]:
    """Cancel a running bbot scan."""
    bbot_scan = await bbot_service.get_bbot_scan_by_id(db, scan_id)
    if not bbot_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bbot scan not found",
        )

    if bbot_scan.status not in [BbotScanStatus.PLANNED, BbotScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in {bbot_scan.status.value} status",
        )

    await bbot_service.cancel_bbot_scan(db, bbot_scan, user.id)
    await db.commit()

    return {"message": "Bbot scan cancelled successfully"}


@router.get("/scans/{scan_id}/findings", response_model=BbotFindingListResponse)
async def get_bbot_scan_findings(
    user: CurrentUser,
    db: DbSession,
    scan_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> BbotFindingListResponse:
    """Get findings for a specific bbot scan with pagination."""
    # Verify scan exists
    bbot_scan = await bbot_service.get_bbot_scan_by_id(db, scan_id)
    if not bbot_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bbot scan not found",
        )

    findings = await bbot_service.get_findings_by_scan_id(db, scan_id, offset, limit)
    total = await bbot_service.get_findings_count_by_scan_id(db, scan_id)

    return BbotFindingListResponse(
        findings=[
            BbotFindingResponse(
                id=f.id,
                bbot_scan_id=f.bbot_scan_id,
                timestamp=f.timestamp,
                event_type=f.event_type,
                data=f.data,
                host=f.host,
                port=f.port,
                protocol=f.protocol,
                module=f.module,
                severity=f.severity,
                tags=f.tags,
                raw_event=f.raw_event,
            )
            for f in findings
        ],
        total=total,
    )
