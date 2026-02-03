"""Router for vulnerability-related endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AdminUser
from app.core.database import get_db
from app.models import Scan, Vulnerability
from app.schemas.vulnerability import VulnerabilityListResponse, VulnerabilityResponse, VulnerabilitySummary

router = APIRouter(prefix="/api/scans", tags=["vulnerabilities"])


@router.get("/{scan_id}/vulnerabilities", response_model=VulnerabilityListResponse)
async def get_scan_vulnerabilities(
    scan_id: int,
    _user: AdminUser,
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityListResponse:
    """Get all vulnerabilities for a specific scan."""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get all vulnerabilities for this scan
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc())
    )
    vulnerabilities = result.scalars().all()

    # Calculate summary
    total = len(vulnerabilities)
    critical = sum(1 for v in vulnerabilities if v.severity >= 9.0)
    high = sum(1 for v in vulnerabilities if 7.0 <= v.severity < 9.0)
    medium = sum(1 for v in vulnerabilities if 4.0 <= v.severity < 7.0)
    low = sum(1 for v in vulnerabilities if v.severity < 4.0)

    summary = VulnerabilitySummary(
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
    )

    vuln_responses = [VulnerabilityResponse.model_validate(v) for v in vulnerabilities]

    return VulnerabilityListResponse(vulnerabilities=vuln_responses, summary=summary)
