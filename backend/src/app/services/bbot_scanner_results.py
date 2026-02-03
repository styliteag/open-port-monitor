"""Service for submitting bbot scanner results."""

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bbot_scan import BbotScan, BbotScanStatus
from app.models.scanner import Scanner
from app.schemas.scanner import BbotResultRequest, BbotResultResponse
from app.services.bbot_scanner_jobs import get_bbot_scan_for_scanner
from app.services.bbot_scans import create_bbot_findings


async def submit_bbot_results(
    db: AsyncSession,
    scanner: Scanner,
    request: BbotResultRequest,
) -> BbotResultResponse | None:
    """
    Submit bbot scan results from a scanner.

    Updates the bbot scan status and creates finding records.
    Returns None if scan not found or not assigned to scanner.
    """
    # Get the scan and verify it belongs to this scanner
    bbot_scan = await get_bbot_scan_for_scanner(db, scanner, request.scan_id)
    if not bbot_scan:
        return None

    # Accept results for RUNNING or CANCELLED scans
    if bbot_scan.status not in [BbotScanStatus.RUNNING, BbotScanStatus.CANCELLED]:
        return None

    # Update scan status based on request
    if request.status == "success":
        # Only mark as completed if not already cancelled
        if bbot_scan.status != BbotScanStatus.CANCELLED:
            bbot_scan.status = BbotScanStatus.COMPLETED
        bbot_scan.completed_at = datetime.now(timezone.utc)
    elif request.status == "failed":
        bbot_scan.status = BbotScanStatus.FAILED
        bbot_scan.completed_at = datetime.now(timezone.utc)
        bbot_scan.error_message = request.error_message

    # Create findings from the results
    findings = await create_bbot_findings(db, request.scan_id, request.findings)
    
    await db.flush()

    return BbotResultResponse(
        scan_id=bbot_scan.id,
        status=bbot_scan.status.value,
        findings_recorded=len(findings),
    )
