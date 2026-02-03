"""Bbot scan execution logic."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any


def run_bbot_scan(target: str, modules: str | None, logger: logging.Logger) -> list[dict[str, Any]]:
    """
    Execute a bbot scan and return findings.

    Args:
        target: Target domain or IP to scan
        modules: Comma-separated list of bbot modules, or None for default
        logger: Logger instance

    Returns:
        List of bbot event dictionaries
    """
    findings: list[dict[str, Any]] = []
    
    try:
        # Build bbot command
        cmd = ["bbot", "-t", target]
        
        # Add modules if specified
        if modules:
            module_list = [m.strip() for m in modules.split(",")]
            cmd.extend(["-m"] + module_list)
        
        # Output JSON format for easier parsing
        cmd.extend(["-om", "json", "--json"])
        
        logger.info("Running bbot command: %s", " ".join(cmd))
        
        # Run bbot and capture output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        
        # Read output line by line
        if process.stdout:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Parse JSON event
                    event = json.loads(line)
                    
                    # Extract relevant information from the event
                    finding = {
                        "type": event.get("type", "UNKNOWN"),
                        "data": str(event.get("data", "")),
                        "host": event.get("host"),
                        "module": event.get("module"),
                        "tags": event.get("tags", []),
                        "raw_event": event,
                    }
                    
                    # Add port and protocol if available
                    if ":" in str(finding.get("data", "")):
                        try:
                            parts = str(finding["data"]).split(":")
                            if len(parts) >= 2 and parts[-1].isdigit():
                                finding["port"] = int(parts[-1])
                                finding["protocol"] = "tcp"  # Default to TCP
                        except (ValueError, IndexError):
                            pass
                    
                    findings.append(finding)
                    logger.debug("Bbot event: %s", finding["type"])
                    
                except json.JSONDecodeError:
                    # Not a JSON line, might be a log message
                    logger.debug("Bbot output: %s", line)
        
        # Wait for process to complete
        return_code = process.wait()
        
        if return_code != 0:
            stderr_output = process.stderr.read() if process.stderr else ""
            error_msg = f"Bbot exited with code {return_code}: {stderr_output}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        logger.info("Bbot scan completed, found %d events", len(findings))
        return findings
        
    except FileNotFoundError:
        error_msg = "bbot command not found. Is bbot installed?"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        logger.error("Error running bbot scan: %s", e)
        raise
