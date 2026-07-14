"""Executive overview aggregation (UI v3, ADR 0005).

Read-only management view: traffic-light status per network, the
highest-priority open alerts, and open/handled totals. Severity uses the
lightweight type-based mapping — the same one the alert list uses for its
aggregate counts.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.network import Network
from app.services.alert_severity import SEVERITY_RANK, lightweight_severity

TOP_RISK_LIMIT = 5


def _status_for(open_critical: int, open_high: int) -> str:
    if open_critical > 0:
        return "red"
    if open_high > 0:
        return "amber"
    return "green"


async def get_executive_overview(db: AsyncSession) -> dict[str, object]:
    networks_result = await db.execute(select(Network.id, Network.name))
    network_names: dict[int, str] = {row[0]: row[1] for row in networks_result.all()}

    open_result = await db.execute(
        select(Alert).where(Alert.dismissed.is_(False))
    )
    open_alerts = list(open_result.scalars().all())

    severities = {
        alert.id: lightweight_severity(alert.alert_type.value, alert.severity_override)
        for alert in open_alerts
    }

    per_network: dict[int, dict[str, int]] = {
        nid: {"critical": 0, "high": 0, "total": 0} for nid in network_names
    }
    for alert in open_alerts:
        if alert.network_id is None or alert.network_id not in per_network:
            continue
        bucket = per_network[alert.network_id]
        bucket["total"] += 1
        severity = severities[alert.id]
        if severity in ("critical", "high"):
            bucket[severity] += 1

    networks = [
        {
            "network_id": nid,
            "name": name,
            "status": _status_for(counts["critical"], counts["high"]),
            "open_critical": counts["critical"],
            "open_high": counts["high"],
            "open_total": counts["total"],
        }
        for nid, name in sorted(network_names.items(), key=lambda item: item[1].lower())
        for counts in (per_network[nid],)
    ]

    # Highest severity first; within the same severity, newest first.
    top = sorted(
        open_alerts,
        key=lambda a: (
            SEVERITY_RANK.get(severities[a.id], 9),
            -(a.created_at.timestamp() if a.created_at else 0),
        ),
    )[:TOP_RISK_LIMIT]

    top_risks = [
        {
            "alert_id": alert.id,
            "message": alert.message,
            "severity": severities[alert.id],
            "ip": alert.ip,
            "port": alert.port,
            "network_name": network_names.get(alert.network_id)
            if alert.network_id is not None
            else None,
        }
        for alert in top
    ]

    # No dismissed_at column exists, so "handled in the last 30 days"
    # approximates via created_at of dismissed alerts.
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    handled_result = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.dismissed.is_(True), Alert.created_at >= cutoff)
    )
    handled_30d = int(handled_result.scalar_one())

    return {
        "networks": networks,
        "top_risks": top_risks,
        "open_alerts": len(open_alerts),
        "handled_alerts_30d": handled_30d,
    }
