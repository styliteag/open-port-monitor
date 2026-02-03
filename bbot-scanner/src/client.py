"""API client for communicating with the backend."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx


class BbotScannerClient:
    """Client for interacting with the Open Port Monitor backend API."""

    def __init__(self, backend_url: str, api_key: str, logger: logging.Logger):
        """Initialize the client."""
        self.backend_url = backend_url.rstrip("/")
        self.api_key = api_key
        self.logger = logger
        self.client = httpx.Client(timeout=30.0)
        self.jwt_token: str | None = None

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def wait_for_backend(self, max_retries: int = 60, delay: int = 5) -> None:
        """Wait for backend to be ready before starting."""
        for attempt in range(max_retries):
            try:
                response = self.client.get(f"{self.backend_url}/health")
                if response.status_code == 200:
                    self.logger.info("Backend is ready")
                    return
            except Exception as e:
                self.logger.debug("Backend not ready yet: %s", e)
            
            if attempt < max_retries - 1:
                self.logger.info("Waiting for backend... (attempt %d/%d)", attempt + 1, max_retries)
                time.sleep(delay)
        
        raise RuntimeError("Backend did not become ready in time")

    def authenticate(self) -> None:
        """Authenticate with the backend and get JWT token."""
        try:
            response = self.client.post(
                f"{self.backend_url}/api/scanner/auth",
                headers={"X-API-Key": self.api_key},
                json={"scanner_version": "bbot-scanner-0.1.0"},
            )
            response.raise_for_status()
            data = response.json()
            self.jwt_token = data["access_token"]
            self.logger.info("Successfully authenticated with backend")
        except Exception as e:
            self.logger.error("Failed to authenticate: %s", e)
            raise

    def _get_headers(self) -> dict[str, str]:
        """Get headers with JWT token."""
        if not self.jwt_token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.jwt_token}"}

    def get_bbot_jobs(self) -> list[dict[str, Any]]:
        """Get pending bbot jobs from the backend."""
        try:
            response = self.client.get(
                f"{self.backend_url}/api/scanner/bbot-jobs",
                headers=self._get_headers(),
            )
            response.raise_for_status()
            data = response.json()
            return data.get("jobs", [])
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired, re-authenticate
                self.logger.info("Token expired, re-authenticating...")
                self.jwt_token = None
                return self.get_bbot_jobs()
            raise

    def claim_bbot_job(self, network_id: int) -> dict[str, Any] | None:
        """Claim a bbot job for a network."""
        try:
            response = self.client.post(
                f"{self.backend_url}/api/scanner/bbot-jobs/{network_id}/claim",
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                self.logger.warning("Bbot job already claimed for network %d", network_id)
                return None
            raise

    def submit_bbot_results(
        self, scan_id: int, status: str, findings: list[dict[str, Any]], error_message: str | None = None
    ) -> None:
        """Submit bbot scan results to the backend."""
        payload = {
            "scan_id": scan_id,
            "status": status,
            "findings": findings,
            "error_message": error_message,
        }
        
        response = self.client.post(
            f"{self.backend_url}/api/scanner/bbot-results",
            headers=self._get_headers(),
            json=payload,
        )
        response.raise_for_status()
        self.logger.info("Submitted bbot results for scan %d", scan_id)
