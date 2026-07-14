"""Lightweight alert severity mapping (no async rule checks).

Shared by the alert list severity counts and the executive overview.
The full resolution including severity rules lives in
routers/alerts/detail.compute_alert_severity; this module is the cheap
type-based fallback used for aggregate counting.
"""

from app.schemas.alert import Severity

TYPE_SEVERITY: dict[str, str] = {
    "blocked": "critical",
    "new_port": "high",
    "not_allowed": "medium",
    "ssh_insecure_auth": "high",
    "ssh_weak_cipher": "medium",
    "ssh_weak_kex": "medium",
    "ssh_outdated_version": "medium",
    "ssh_config_regression": "high",
    "nse_vulnerability": "medium",
    "nse_cve_detected": "medium",
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "info": 3,
}


def lightweight_severity(alert_type_value: str, override: str | None) -> str:
    if override:
        try:
            return Severity(override).value
        except ValueError:
            pass
    return TYPE_SEVERITY.get(alert_type_value, "medium")
