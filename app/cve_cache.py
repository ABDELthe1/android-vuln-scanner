"""
CVE File-based Cache — Phase 5
Simple JSON cache with 24-hour TTL for NVD API responses.
"""

import json
import logging
import os
import time

logger = logging.getLogger(__name__)

_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "cve_cache.json")
_CACHE_FILE = os.path.normpath(_CACHE_FILE)
_TTL = 86400  # 24 hours in seconds


def _load() -> dict:
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError as exc:
        logger.warning("Could not write CVE cache: %s", exc)


def get_cached(keyword: str):
    """Return cached CVE results for *keyword* if still fresh, else None."""
    data = _load()
    entry = data.get(keyword)
    if entry is None:
        return None
    if time.time() - entry.get("timestamp", 0) > _TTL:
        return None
    return entry.get("results")


def set_cache(keyword: str, results: list) -> None:
    """Persist *results* for *keyword* with the current timestamp."""
    data = _load()
    data[keyword] = {"timestamp": time.time(), "results": results}
    _save(data)
