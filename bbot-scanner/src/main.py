"""Open Port Monitor Bbot Scanner Agent - Main entry point."""

from __future__ import annotations

import logging
import time

from src.client import BbotScannerClient
from src.config import load_config
from src.executor import run_bbot_scan


def configure_logging(log_level: str) -> logging.Logger:
    """Configure logging for the scanner."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    return logging.getLogger(__name__)


def process_bbot_job(job: dict, client: BbotScannerClient, logger: logging.Logger) -> None:
    """Process a single bbot scan job."""
    network_id = job["network_id"]
    scan_id = job["scan_id"]
    target = job["target"]
    modules = job.get("modules")
    
    logger.info("Processing bbot job: scan_id=%d, target=%s", scan_id, target)
    
    try:
        # Run bbot scan
        findings = run_bbot_scan(target, modules, logger)
        
        # Submit results to backend
        client.submit_bbot_results(scan_id, "success", findings)
        logger.info("Completed bbot scan %d successfully with %d findings", scan_id, len(findings))
        
    except Exception as e:
        logger.exception("Failed to complete bbot scan %d", scan_id)
        # Submit failure to backend
        try:
            client.submit_bbot_results(scan_id, "failed", [], error_message=str(e))
        except Exception as submit_error:
            logger.error("Failed to submit error status: %s", submit_error)


def main() -> None:
    """Main entry point for the bbot scanner agent."""
    config = load_config()
    logger = configure_logging(config.log_level)

    logger.info("Open Port Monitor Bbot Scanner starting...")
    logger.info("Polling interval set to %s seconds", config.poll_interval)

    client = BbotScannerClient(config.backend_url, config.api_key, logger)

    # Wait for backend to be ready before starting
    logger.info("Waiting for backend to be ready...")
    client.wait_for_backend()

    # Authenticate with backend
    client.authenticate()

    try:
        while True:
            has_work = False

            # Check for bbot scan jobs
            try:
                jobs = client.get_bbot_jobs()
                if jobs:
                    has_work = True
                    logger.info("Found %s pending bbot scan job(s)", len(jobs))
                    for job in jobs:
                        # Claim the job first
                        claim_result = client.claim_bbot_job(job["network_id"])
                        if claim_result:
                            # Process the job
                            process_bbot_job(claim_result, client, logger)
                        else:
                            logger.warning("Could not claim bbot job for network %d", job["network_id"])
            except Exception:
                logger.exception("Failed to fetch/process bbot scan jobs")

            if not has_work:
                logger.debug("No pending bbot jobs; sleeping")

            time.sleep(config.poll_interval)
    except KeyboardInterrupt:
        logger.info("Bbot scanner agent shutting down...")
    finally:
        client.close()


if __name__ == "__main__":
    main()
