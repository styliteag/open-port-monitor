"""Service for bbot scanner job management."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.bbot_scan import BbotScan, BbotScanStatus
from app.models.network import Network
from app.models.scanner import Scanner
from app.schemas.scanner import BbotJobClaimResponse, BbotJobResponse


async def get_pending_bbot_jobs_for_scanner(
    db: AsyncSession, scanner: Scanner
) -> list[BbotJobResponse]:
    """
    Get pending bbot scan jobs for a scanner.

    Returns planned bbot scans for networks assigned to this scanner.
    """
    result = await db.execute(
        select(BbotScan, Network)
        .join(Network, Network.id == BbotScan.network_id)
        .where(Network.scanner_id == scanner.id)
        .where(BbotScan.status == BbotScanStatus.PLANNED)
        .order_by(BbotScan.id.asc())
    )
    
    jobs = []
    for bbot_scan, network in result.all():
        jobs.append(
            BbotJobResponse(
                scan_id=bbot_scan.id,
                network_id=network.id,
                target=bbot_scan.target,
                modules=bbot_scan.modules,
            )
        )
    
    return jobs


async def is_bbot_job_running(db: AsyncSession, network_id: int) -> bool:
    """Check if there's already a running bbot scan for a network."""
    result = await db.execute(
        select(BbotScan)
        .where(BbotScan.network_id == network_id)
        .where(BbotScan.status == BbotScanStatus.RUNNING)
    )
    return result.scalar_one_or_none() is not None


async def claim_bbot_job(
    db: AsyncSession, scanner: Scanner, network_id: int
) -> BbotJobClaimResponse | None:
    """
    Claim a bbot scan job for a network.

    Marks the first PLANNED bbot scan for the network as RUNNING.
    Returns None if no planned scan exists or network not assigned to scanner.
    """
    # Get the network and verify it's assigned to this scanner
    result = await db.execute(
        select(Network).where(Network.id == network_id).where(Network.scanner_id == scanner.id)
    )
    network = result.scalar_one_or_none()
    if not network:
        return None

    # Get the first planned bbot scan for this network
    result = await db.execute(
        select(BbotScan)
        .where(BbotScan.network_id == network_id)
        .where(BbotScan.status == BbotScanStatus.PLANNED)
        .order_by(BbotScan.id.asc())
    )
    bbot_scan = result.scalar_one_or_none()
    if not bbot_scan:
        return None

    # Mark scan as running
    bbot_scan.status = BbotScanStatus.RUNNING
    bbot_scan.started_at = datetime.now(timezone.utc)
    bbot_scan.scanner_id = scanner.id

    await db.flush()

    return BbotJobClaimResponse(
        scan_id=bbot_scan.id,
        network_id=network.id,
        target=bbot_scan.target,
        modules=bbot_scan.modules,
    )


async def get_bbot_scan_for_scanner(
    db: AsyncSession, scanner: Scanner, scan_id: int
) -> BbotScan | None:
    """Get a bbot scan by ID if it belongs to this scanner's networks."""
    result = await db.execute(
        select(BbotScan)
        .options(selectinload(BbotScan.network))
        .where(BbotScan.id == scan_id)
    )
    bbot_scan = result.scalar_one_or_none()
    
    if not bbot_scan:
        return None
    
    # Verify the scan's network belongs to this scanner
    if bbot_scan.network.scanner_id != scanner.id:
        return None
    
    return bbot_scan
