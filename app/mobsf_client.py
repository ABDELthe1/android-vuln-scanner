"""
MobSF REST API Client
Wraps every MobSF endpoint needed by the scanner so the rest of the
application never has to deal with raw HTTP details.

All public functions raise MobSFError on non-200 responses or network
failures, keeping error handling consistent for callers.
"""

import os
import logging
from pathlib import Path

import requests
from flask import current_app

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Custom exception
# --------------------------------------------------------------------------- #

class MobSFError(Exception):
    """Raised when a MobSF API call fails."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _base_url() -> str:
    """Return the MobSF base URL from app config (no trailing slash)."""
    return current_app.config["MOBSF_URL"].rstrip("/")


def _headers() -> dict:
    """Return the authorization headers required by every MobSF endpoint."""
    api_key = current_app.config.get("MOBSF_API_KEY", "")
    if not api_key:
        raise MobSFError("MOBSF_API_KEY is not configured.")
    return {"Authorization": api_key}


def _post(endpoint: str, data: dict | None = None, files=None, timeout: int = 120):
    """
    Generic POST helper.

    Args:
        endpoint: Path relative to the MobSF base URL (e.g. '/api/v1/upload').
        data:     Form-encoded payload dict.
        files:    Multipart file payload (passed directly to requests).
        timeout:  Request timeout in seconds.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        MobSFError: On HTTP errors or JSON decode failures.
    """
    url = f"{_base_url()}{endpoint}"
    try:
        response = requests.post(
            url,
            headers=_headers(),
            data=data,
            files=files,
            timeout=timeout,
        )
    except requests.exceptions.ConnectionError as exc:
        raise MobSFError(
            f"Cannot reach MobSF at {_base_url()}. Is it running?"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise MobSFError(f"Request to {endpoint} timed out after {timeout}s.") from exc

    if not response.ok:
        raise MobSFError(
            f"MobSF returned HTTP {response.status_code} for {endpoint}: "
            f"{response.text[:300]}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise MobSFError(
            f"MobSF response from {endpoint} is not valid JSON."
        ) from exc


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def upload_apk(file_path: str) -> str:
    """
    Upload an APK file to MobSF.

    Args:
        file_path: Absolute or relative path to the APK on disk.

    Returns:
        scan_hash (str): The unique hash MobSF assigns to this upload.
                         All subsequent API calls reference this hash.

    Raises:
        MobSFError: If the file is missing or MobSF rejects the upload.
    """
    path = Path(file_path)
    if not path.exists():
        raise MobSFError(f"APK file not found: {file_path}")

    logger.info("Uploading APK: %s", path.name)

    with open(path, "rb") as apk_file:
        result = _post(
            "/api/v1/upload",
            files={"file": (path.name, apk_file, "application/octet-stream")},
        )

    scan_hash = result.get("hash")
    if not scan_hash:
        raise MobSFError(f"Upload succeeded but no hash in response: {result}")

    logger.info("APK uploaded successfully. Hash: %s", scan_hash)
    return scan_hash


def start_scan(scan_hash: str) -> dict:
    """
    Trigger static analysis for a previously uploaded APK.

    Args:
        scan_hash: The hash returned by upload_apk().

    Returns:
        The raw MobSF scan-start response dict.

    Raises:
        MobSFError: On API failure.
    """
    logger.info("Starting scan for hash: %s", scan_hash)

    result = _post(
        "/api/v1/scan",
        data={"hash": scan_hash, "scan_type": "apk", "re_scan": 0},
    )

    logger.info("Scan initiated: %s", result)
    return result


def get_report(scan_hash: str) -> dict:
    """
    Fetch the full JSON analysis report for a completed scan.

    Args:
        scan_hash: The hash returned by upload_apk().

    Returns:
        Full MobSF JSON report as a dict.  This is the primary data source
        for the parser — it contains code analysis, manifest findings,
        binary analysis, network security, etc.

    Raises:
        MobSFError: On API failure.
    """
    logger.info("Fetching report for hash: %s", scan_hash)

    result = _post(
        "/api/v1/report_json",
        data={"hash": scan_hash},
    )

    return result


def get_scorecard(scan_hash: str) -> dict:
    """
    Fetch the security scorecard for a completed scan.

    The scorecard provides a condensed security rating and top-level
    vulnerability summary, complementing the detailed report.

    Args:
        scan_hash: The hash returned by upload_apk().

    Returns:
        MobSF scorecard dict.

    Raises:
        MobSFError: On API failure.
    """
    logger.info("Fetching scorecard for hash: %s", scan_hash)

    result = _post(
        "/api/v1/scorecard",
        data={"hash": scan_hash},
    )

    return result
