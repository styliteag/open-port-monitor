"""Bbot scan management service."""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.bbot_finding import BbotFinding
from app.models.bbot_scan import BbotScan, BbotScanStatus
from app.models.network import Network


async def create_bbot_scan(
    db: AsyncSession, network: Network, target: str, modules: str | None = None
) -> BbotScan:
    """
    Create a new bbot scan for a network.

    Creates a scan record with status 'planned'.
    """
    bbot_scan = BbotScan(
        network_id=network.id,
        scanner_id=network.scanner_id,
        status=BbotScanStatus.PLANNED,
        target=target,
        modules=modules,
    )
    db.add(bbot_scan)
    await db.flush()
    return bbot_scan


async def cancel_bbot_scan(
    db: AsyncSession,
    bbot_scan: BbotScan,
    cancelled_by: int,
) -> BbotScan:
    """Cancel a running bbot scan and set cancellation metadata."""
    bbot_scan.status = BbotScanStatus.CANCELLED
    bbot_scan.cancelled_at = datetime.now(timezone.utc)
    bbot_scan.cancelled_by = cancelled_by
    await db.flush()
    return bbot_scan


async def get_bbot_scans_by_network_id(
    db: AsyncSession,
    network_id: int,
    offset: int = 0,
    limit: int = 50,
) -> list[tuple[BbotScan, int]]:
    """
    Get bbot scan history for a specific network with finding counts.

    Returns scans ordered by most recent first.
    """
    result = await db.execute(
        select(BbotScan, func.count(BbotFinding.id).label("finding_count"))
        .outerjoin(BbotFinding, BbotFinding.bbot_scan_id == BbotScan.id)
        .options(selectinload(BbotScan.cancelled_by_user))
        .where(BbotScan.network_id == network_id)
        .group_by(BbotScan.id)
        .order_by(BbotScan.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return [(row[0], int(row[1])) for row in result.all()]


async def get_all_bbot_scans(
    db: AsyncSession,
    offset: int = 0,
    limit: int = 50,
) -> list[tuple[BbotScan, int]]:
    """
    Get all bbot scans with finding counts.

    Returns scans ordered by most recent first.
    """
    result = await db.execute(
        select(BbotScan, func.count(BbotFinding.id).label("finding_count"))
        .outerjoin(BbotFinding, BbotFinding.bbot_scan_id == BbotScan.id)
        .options(selectinload(BbotScan.cancelled_by_user))
        .group_by(BbotScan.id)
        .order_by(BbotScan.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return [(row[0], int(row[1])) for row in result.all()]


async def get_bbot_scan_with_findings(
    db: AsyncSession, scan_id: int
) -> BbotScan | None:
    """Get a bbot scan by ID with findings loaded."""
    result = await db.execute(
        select(BbotScan)
        .options(
            selectinload(BbotScan.findings),
            selectinload(BbotScan.cancelled_by_user),
        )
        .where(BbotScan.id == scan_id)
    )
    return result.scalar_one_or_none()


async def get_bbot_scan_by_id(db: AsyncSession, scan_id: int) -> BbotScan | None:
    """Get a bbot scan by ID."""
    result = await db.execute(select(BbotScan).where(BbotScan.id == scan_id))
    return result.scalar_one_or_none()


async def get_findings_by_scan_id(
    db: AsyncSession,
    scan_id: int,
    offset: int = 0,
    limit: int = 100,
) -> list[BbotFinding]:
    """Get findings for a specific bbot scan."""
    result = await db.execute(
        select(BbotFinding)
        .where(BbotFinding.bbot_scan_id == scan_id)
        .order_by(BbotFinding.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_findings_count_by_scan_id(db: AsyncSession, scan_id: int) -> int:
    """Get count of findings for a specific bbot scan."""
    result = await db.execute(
        select(func.count(BbotFinding.id)).where(BbotFinding.bbot_scan_id == scan_id)
    )
    count = result.scalar_one()
    return int(count) if count is not None else 0


async def create_bbot_findings(
    db: AsyncSession, scan_id: int, findings_data: list[dict]
) -> list[BbotFinding]:
    """Create bbot findings from scanner results."""
    findings = []
    for finding_data in findings_data:
        # Extract relevant fields from bbot event
        finding = BbotFinding(
            bbot_scan_id=scan_id,
            event_type=finding_data.get("type", "UNKNOWN"),
            data=str(finding_data.get("data", "")),
            host=finding_data.get("host"),
            port=finding_data.get("port"),
            protocol=finding_data.get("protocol"),
            module=finding_data.get("module"),
            severity=finding_data.get("severity"),
            tags=finding_data.get("tags"),
            raw_event=finding_data,
        )
        db.add(finding)
        findings.append(finding)
    
    await db.flush()
    return findings
