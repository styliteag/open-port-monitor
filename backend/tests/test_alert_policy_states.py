"""Tests for the UI v3 queue/policy state dimensions on the alert list API."""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertType
from app.models.alert_rule import AlertRule, RuleType
from app.models.network import Network
from app.models.scan import Scan


async def _create_alert(
    db_session: AsyncSession,
    network: Network,
    scan: Scan,
    *,
    ip: str = "192.168.1.10",
    port: int = 22,
    dismissed: bool = False,
) -> Alert:
    alert = Alert(
        scan_id=scan.id,
        network_id=network.id,
        alert_type=AlertType.NEW_PORT,
        source="port",
        ip=ip,
        port=port,
        message=f"Test alert: {ip}:{port}",
        dismissed=dismissed,
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)
    return alert


async def _create_rule(
    db_session: AsyncSession,
    *,
    network_id: int | None = None,
    ip: str | None = None,
    port: str = "22",
    rule_type: RuleType = RuleType.ACCEPTED,
    enabled: bool = True,
) -> AlertRule:
    criteria: dict[str, str | None] = {"port": port}
    if ip is not None:
        criteria["ip"] = ip
    rule = AlertRule(
        network_id=network_id,
        source="port",
        rule_type=rule_type,
        match_criteria=criteria,
        enabled=enabled,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


class TestQueuePolicyResponseFields:
    async def test_open_alert_without_rule(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan)

        resp = await client.get("/api/alerts/", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()["alerts"][0]
        assert data["queue_state"] == "inbox"
        assert data["policy_state"] == "none"
        assert data["allow_rule_id"] is None
        assert data["allow_scope"] is None

    async def test_dismissed_alert_is_out_of_inbox(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, dismissed=True)

        resp = await client.get("/api/alerts/", headers=admin_headers)
        data = resp.json()["alerts"][0]
        assert data["queue_state"] == "out_of_inbox"

    async def test_global_rule_marks_allowed_global(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.0.0.5", port=80)
        rule = await _create_rule(db_session, ip="10.0.0.5", port="80")

        resp = await client.get("/api/alerts/", headers=admin_headers)
        data = resp.json()["alerts"][0]
        assert data["policy_state"] == "allowed_global"
        assert data["allow_rule_id"] == rule.id
        assert data["allow_scope"] == "global"

    async def test_network_rule_wins_over_global(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.0.0.6", port=443)
        await _create_rule(db_session, ip="10.0.0.6", port="443")  # global
        network_rule = await _create_rule(
            db_session, network_id=network.id, ip="10.0.0.6", port="443"
        )

        resp = await client.get("/api/alerts/", headers=admin_headers)
        data = resp.json()["alerts"][0]
        assert data["policy_state"] == "allowed_network"
        assert data["allow_rule_id"] == network_rule.id
        assert data["allow_scope"] == "network"

    async def test_disabled_and_non_accepted_rules_ignored(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.0.0.7", port=8080)
        await _create_rule(db_session, ip="10.0.0.7", port="8080", enabled=False)
        await _create_rule(
            db_session, ip="10.0.0.7", port="8080", rule_type=RuleType.CRITICAL
        )

        resp = await client.get("/api/alerts/", headers=admin_headers)
        data = resp.json()["alerts"][0]
        assert data["policy_state"] == "none"


class TestQueuePolicyFilters:
    async def test_queue_state_filter(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.1.0.1", dismissed=False)
        await _create_alert(db_session, network, scan, ip="10.1.0.2", dismissed=True)

        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"queue_state": "inbox"}
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["ip"] == "10.1.0.1"

        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"queue_state": "out_of_inbox"},
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["ip"] == "10.1.0.2"

    async def test_queue_state_conflicts_with_dismissed(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
    ):
        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"queue_state": "inbox", "dismissed": "true"},
        )
        assert resp.status_code == 400

    async def test_invalid_state_values_rejected(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
    ):
        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"queue_state": "bogus"}
        )
        assert resp.status_code == 422
        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"policy_state": "bogus"}
        )
        assert resp.status_code == 422

    async def test_policy_state_filter_allowed_and_none(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.2.0.1", port=80)
        await _create_alert(db_session, network, scan, ip="10.2.0.2", port=81)
        await _create_rule(db_session, ip="10.2.0.1", port="80")

        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"policy_state": "allowed"}
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["ip"] == "10.2.0.1"
        assert data["alerts"][0]["policy_state"] == "allowed_global"

        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"policy_state": "none"}
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["ip"] == "10.2.0.2"

    async def test_policy_state_scope_filters(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        await _create_alert(db_session, network, scan, ip="10.3.0.1", port=80)
        await _create_alert(db_session, network, scan, ip="10.3.0.2", port=81)
        await _create_rule(db_session, ip="10.3.0.1", port="80")  # global
        await _create_rule(
            db_session, network_id=network.id, ip="10.3.0.2", port="81"
        )

        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"policy_state": "allowed_global"},
        )
        assert [a["ip"] for a in resp.json()["alerts"]] == ["10.3.0.1"]

        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"policy_state": "allowed_network"},
        )
        assert [a["ip"] for a in resp.json()["alerts"]] == ["10.3.0.2"]

    async def test_policy_filter_pagination_totals(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        network, scan = network_with_scan
        # 3 allowed alerts (port 80), 1 not allowed (port 9999)
        for i in range(3):
            await _create_alert(db_session, network, scan, ip=f"10.4.0.{i}", port=80)
        await _create_alert(db_session, network, scan, ip="10.4.0.99", port=9999)
        await _create_rule(db_session, port="80")

        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"policy_state": "allowed", "limit": 2, "offset": 0},
        )
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 2
        assert data["severity_counts"] == {"high": 3}

        resp = await client.get(
            "/api/alerts/",
            headers=admin_headers,
            params={"policy_state": "allowed", "limit": 2, "offset": 2},
        )
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 1


class TestSeverityCountsRegression:
    async def test_severity_counts_ignore_page_ips(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        db_session: AsyncSession,
        network_with_scan: tuple[Network, Scan],
    ):
        """severity_counts must cover ALL filtered alerts, not the page.

        Regression: the host-cache loop in list_alerts shadowed the `ip`
        query param, so _count_by_severity silently filtered on the last
        IP of the current page — counts changed with the page size.
        """
        network, scan = network_with_scan
        for i in range(3):
            await _create_alert(db_session, network, scan, ip=f"10.5.0.{i}", port=22)

        resp = await client.get(
            "/api/alerts/", headers=admin_headers, params={"limit": 1}
        )
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 1
        # All three NEW_PORT alerts are "high" — regardless of page size.
        assert data["severity_counts"] == {"high": 3}
