"""Tests for the executive overview endpoint (UI v3, ADR 0005)."""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertType
from app.models.network import Network
from app.models.scan import Scan


async def _create_alert(
    db_session: AsyncSession,
    network: Network,
    scan: Scan,
    *,
    alert_type: AlertType = AlertType.NEW_PORT,
    severity_override: str | None = None,
    ip: str = "192.168.1.10",
    dismissed: bool = False,
) -> Alert:
    alert = Alert(
        scan_id=scan.id,
        network_id=network.id,
        alert_type=alert_type,
        source="port",
        ip=ip,
        port=22,
        message=f"Overview test alert {ip}",
        dismissed=dismissed,
        severity_override=severity_override,
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)
    return alert


class TestExecutiveOverview:
    async def test_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/overview/executive")
        assert resp.status_code == 401

    async def test_viewer_can_read(
        self,
        client: AsyncClient,
        viewer_headers: dict[str, str],
    ):
        resp = await client.get("/api/overview/executive", headers=viewer_headers)
        assert resp.status_code == 200

    async def test_green_without_open_alerts(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        network_with_scan: tuple[Network, Scan],
    ):
        network, _ = network_with_scan
        resp = await client.get("/api/overview/executive", headers=admin_headers)
        data = resp.json()
        entry = next(n for n in data["networks"] if n["network_id"] == network.id)
        assert entry["status"] == "green"
        assert data["open_alerts"] == 0
        assert data["top_risks"] == []

    async def test_amber_on_open_high(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan)  # NEW_PORT → high

        resp = await client.get("/api/overview/executive", headers=admin_headers)
        entry = next(
            n for n in resp.json()["networks"] if n["network_id"] == network.id
        )
        assert entry["status"] == "amber"
        assert entry["open_high"] == 1

    async def test_red_on_open_critical_and_top_risk_order(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.0.0.1")  # high
        critical = await _create_alert(
            db_session,
            network,
            scan,
            ip="10.0.0.2",
            severity_override="critical",
        )

        resp = await client.get("/api/overview/executive", headers=admin_headers)
        data = resp.json()
        entry = next(n for n in data["networks"] if n["network_id"] == network.id)
        assert entry["status"] == "red"
        assert entry["open_critical"] == 1
        assert entry["open_total"] == 2
        # Critical alert ranks first in top risks
        assert data["top_risks"][0]["alert_id"] == critical.id
        assert data["top_risks"][0]["severity"] == "critical"
        assert data["top_risks"][0]["network_name"] == network.name

    async def test_dismissed_alerts_do_not_color_networks(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(
            db_session, network, scan, dismissed=True, severity_override="critical"
        )

        resp = await client.get("/api/overview/executive", headers=admin_headers)
        data = resp.json()
        entry = next(n for n in data["networks"] if n["network_id"] == network.id)
        assert entry["status"] == "green"
        assert data["handled_alerts_30d"] == 1
