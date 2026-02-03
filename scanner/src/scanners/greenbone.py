"""Greenbone (OpenVAS) scanner implementation for vulnerability scanning.

This module integrates with Greenbone Vulnerability Management (GVM) to perform
vulnerability scans on discovered hosts and ports.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING

from src.models import OpenPortResult

if TYPE_CHECKING:
    from src.client import ScannerClient
    from src.threading_utils import ProgressReporter


# Vulnerability data structure returned by Greenbone scanner
class GreenboneVulnerability:
    """A vulnerability discovered by Greenbone scanner."""

    def __init__(
        self,
        host_ip: str,
        port: int | None,
        protocol: str | None,
        nvt_oid: str,
        name: str,
        severity: float,
        threat: str,
        cve: str | None = None,
        description: str | None = None,
        solution: str | None = None,
        solution_type: str | None = None,
        references: str | None = None,
    ):
        self.host_ip = host_ip
        self.port = port
        self.protocol = protocol
        self.nvt_oid = nvt_oid
        self.name = name
        self.severity = severity
        self.threat = threat
        self.cve = cve
        self.description = description
        self.solution = solution
        self.solution_type = solution_type
        self.references = references

    def to_payload(self) -> dict[str, str | int | float | None]:
        """Convert to JSON-serializable payload for API submission."""
        return {
            "host_ip": self.host_ip,
            "port": self.port,
            "protocol": self.protocol,
            "nvt_oid": self.nvt_oid,
            "name": self.name,
            "severity": self.severity,
            "threat": self.threat,
            "cve": self.cve,
            "description": self.description,
            "solution": self.solution,
            "solution_type": self.solution_type,
            "references": self.references,
        }


# Sample vulnerability database for demonstration
SAMPLE_VULNERABILITIES = [
    {
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.103692",
        "name": "SSL/TLS: Certificate Signed Using Weak Hashing Algorithm",
        "severity": 5.3,
        "threat": "Medium",
        "cve": "CVE-2004-2761",
        "description": "The SSL/TLS certificate is signed using a cryptographically weak hashing algorithm (MD5 or SHA1).",
        "solution": "Replace the certificate with a stronger signature algorithm (SHA256 or higher).",
        "solution_type": "Mitigation",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2004-2761",
    },
    {
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.105058",
        "name": "SSH Weak Encryption Algorithms Supported",
        "severity": 4.3,
        "threat": "Medium",
        "cve": None,
        "description": "The remote SSH server is configured to allow weak encryption algorithms.",
        "solution": "Disable weak encryption algorithms in the SSH server configuration.",
        "solution_type": "Mitigation",
        "references": "https://www.ssh.com/ssh/sshd_config/",
    },
    {
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.117317",
        "name": "HTTP Server Detection",
        "severity": 0.0,
        "threat": "Log",
        "cve": None,
        "description": "An HTTP server is running on this port.",
        "solution": "N/A",
        "solution_type": None,
        "references": None,
    },
    {
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.900242",
        "name": "Apache HTTP Server Multiple Vulnerabilities",
        "severity": 7.5,
        "threat": "High",
        "cve": "CVE-2021-44790",
        "description": "The remote Apache HTTP Server is affected by multiple vulnerabilities.",
        "solution": "Update to the latest version of Apache HTTP Server.",
        "solution_type": "VendorFix",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-44790",
    },
    {
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.108797",
        "name": "TCP timestamps",
        "severity": 0.0,
        "threat": "Log",
        "cve": None,
        "description": "The remote host implements TCP timestamps.",
        "solution": "N/A",
        "solution_type": None,
        "references": None,
    },
]


def run_greenbone_scan(
    client: ScannerClient,
    scan_id: int,
    open_ports: list[OpenPortResult],
    logger: logging.Logger,
    progress_reporter: ProgressReporter | None = None,
) -> list[GreenboneVulnerability]:
    """
    Run Greenbone vulnerability scan on discovered open ports.

    This is a simplified implementation that demonstrates the integration.
    In a real implementation, this would:
    1. Connect to GVM (Greenbone Vulnerability Management) via gvm-tools
    2. Create a target with the discovered hosts/ports
    3. Start a vulnerability scan task
    4. Wait for completion and retrieve results
    5. Parse the XML/JSON report

    For now, this generates sample vulnerability data based on the ports.

    Args:
        client: Scanner client for API communication
        scan_id: Scan ID
        open_ports: List of discovered open ports to scan
        logger: Logger instance
        progress_reporter: Optional progress reporter

    Returns:
        List of discovered vulnerabilities
    """
    if not open_ports:
        logger.info("No open ports to scan for vulnerabilities")
        return []

    logger.info("Starting Greenbone vulnerability scan on %d open ports", len(open_ports))

    if progress_reporter:
        progress_reporter.update(0, "Initializing Greenbone scan...")

    vulnerabilities: list[GreenboneVulnerability] = []

    # Group ports by host
    hosts_ports: dict[str, list[OpenPortResult]] = {}
    for port_result in open_ports:
        if port_result.ip not in hosts_ports:
            hosts_ports[port_result.ip] = []
        hosts_ports[port_result.ip].append(port_result)

    total_hosts = len(hosts_ports)
    logger.info("Scanning %d hosts for vulnerabilities", total_hosts)

    # Simulate vulnerability scanning for each host
    for idx, (host_ip, ports) in enumerate(hosts_ports.items()):
        if progress_reporter:
            progress = int((idx / total_hosts) * 100)
            progress_reporter.update(progress, f"Scanning host {idx + 1}/{total_hosts}: {host_ip}")

        logger.info("Scanning host %s with %d open ports", host_ip, len(ports))

        # For demonstration: randomly generate vulnerabilities for some ports
        for port_result in ports:
            # Generate 0-3 vulnerabilities per port
            num_vulns = random.randint(0, 3)

            for _ in range(num_vulns):
                # Randomly select a vulnerability template
                vuln_template = random.choice(SAMPLE_VULNERABILITIES)

                # Adapt based on port/service
                nvt_oid = vuln_template["nvt_oid"]
                name = vuln_template["name"]
                severity = vuln_template["severity"]

                # Adjust severity based on service
                if port_result.service_guess:
                    if "http" in port_result.service_guess.lower():
                        # Web services might have more severe vulnerabilities
                        severity = min(10.0, severity + random.uniform(0, 2.0))
                    elif "ssh" in port_result.service_guess.lower():
                        # SSH might have configuration issues
                        if "Weak" in name or "weak" in name:
                            severity = min(10.0, severity + random.uniform(0, 1.0))

                # Determine threat level from severity
                if severity >= 9.0:
                    threat = "Critical"
                elif severity >= 7.0:
                    threat = "High"
                elif severity >= 4.0:
                    threat = "Medium"
                elif severity >= 0.1:
                    threat = "Low"
                else:
                    threat = "Log"

                vulnerability = GreenboneVulnerability(
                    host_ip=host_ip,
                    port=port_result.port,
                    protocol=port_result.protocol,
                    nvt_oid=nvt_oid,
                    name=name,
                    severity=round(severity, 1),
                    threat=threat,
                    cve=vuln_template.get("cve"),
                    description=vuln_template.get("description"),
                    solution=vuln_template.get("solution"),
                    solution_type=vuln_template.get("solution_type"),
                    references=vuln_template.get("references"),
                )
                vulnerabilities.append(vulnerability)
                logger.debug(
                    "Found vulnerability: %s on %s:%d (severity: %.1f)",
                    name,
                    host_ip,
                    port_result.port,
                    severity,
                )

    if progress_reporter:
        progress_reporter.update(100, "Vulnerability scan complete")

    logger.info(
        "Greenbone scan completed: found %d vulnerabilities across %d hosts",
        len(vulnerabilities),
        total_hosts,
    )

    # Log summary by severity
    critical = sum(1 for v in vulnerabilities if v.severity >= 9.0)
    high = sum(1 for v in vulnerabilities if 7.0 <= v.severity < 9.0)
    medium = sum(1 for v in vulnerabilities if 4.0 <= v.severity < 7.0)
    low = sum(1 for v in vulnerabilities if v.severity < 4.0)

    logger.info(
        "Vulnerability summary: %d critical, %d high, %d medium, %d low",
        critical,
        high,
        medium,
        low,
    )

    return vulnerabilities
