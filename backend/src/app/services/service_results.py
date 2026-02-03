"""Service scan result service for querying HTTP/NSE script data."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network import Network
from app.models.scan import Scan
from app.models.service_scan_result import ServiceScanResult


async def get_service_results_for_scan(
    db: AsyncSession, scan_id: int
) -> list[ServiceScanResult]:
    """Get all service scan results for a specific scan."""
    result = await db.execute(
        select(ServiceScanResult)
        .where(ServiceScanResult.scan_id == scan_id)
        .order_by(ServiceScanResult.host_ip, ServiceScanResult.port)
    )
    return list(result.scalars().all())


async def get_service_hosts(
    db: AsyncSession,
    network_id: int | None = None,
    service_name: str | None = None,
    http_server: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list, int]:
    """
    Get latest service scan results for each unique host/port combination.

    Returns tuple of (results, total_count).
    """
    # Build subquery to get the latest scan_id for each host/port
    latest_scans = (
        select(
            ServiceScanResult.host_ip,
            ServiceScanResult.port,
            func.max(ServiceScanResult.id).label("max_id"),
        )
        .group_by(ServiceScanResult.host_ip, ServiceScanResult.port)
        .subquery()
    )

    # Main query with filters
    query = (
        select(
            ServiceScanResult,
            Network.id.label("network_id"),
            Network.name.label("network_name"),
        )
        .join(Scan, ServiceScanResult.scan_id == Scan.id)
        .join(Network, Scan.network_id == Network.id)
        .join(
            latest_scans,
            ServiceScanResult.id == latest_scans.c.max_id,
        )
    )

    # Apply filters
    if network_id is not None:
        query = query.where(Network.id == network_id)
    if service_name is not None:
        query = query.where(ServiceScanResult.service_name.ilike(f"%{service_name}%"))
    if http_server is not None:
        query = query.where(ServiceScanResult.http_server.ilike(f"%{http_server}%"))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination and ordering
    query = (
        query.order_by(ServiceScanResult.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(query)
    rows = result.all()

    # Enrich results with network info
    enriched_results = []
    for row in rows:
        service_result = row[0]
        # Add network_id and network_name as attributes
        service_result.network_id = row[1]
        service_result.network_name = row[2]
        enriched_results.append(service_result)

    return enriched_results, total


async def get_service_history(
    db: AsyncSession,
    host_ip: str,
    port: int,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[ServiceScanResult], int]:
    """Get service scan history for a specific host and port."""
    # Count total
    count_query = select(func.count()).where(
        (ServiceScanResult.host_ip == host_ip) & (ServiceScanResult.port == port)
    )
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get results with network info
    query = (
        select(
            ServiceScanResult,
            Network.id.label("network_id"),
            Network.name.label("network_name"),
        )
        .join(Scan, ServiceScanResult.scan_id == Scan.id)
        .join(Network, Scan.network_id == Network.id)
        .where(
            (ServiceScanResult.host_ip == host_ip) & (ServiceScanResult.port == port)
        )
        .order_by(ServiceScanResult.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(query)
    rows = result.all()

    # Enrich results
    enriched_results = []
    for row in rows:
        service_result = row[0]
        service_result.network_id = row[1]
        service_result.network_name = row[2]
        enriched_results.append(service_result)

    return enriched_results, total
