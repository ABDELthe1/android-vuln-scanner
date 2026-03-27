"""
CVE Enricher — Phase 5
Queries the NVD API v2 to attach CVE matches to Critical/High findings.

Public API:
    enrich_findings(findings) -> list[dict]
        Mutates each Critical/High finding in-place, adding a `cve_matches` key.
"""

import logging
import re
import time

import requests

from app.cve_cache import get_cached, set_cache

logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 0.6   # seconds between NVD requests (stay under 5 req/30s)
_TIMEOUT = 10          # seconds
_ENRICH_SEVERITIES = {"critical", "high"}

# In-memory cache for the current process (avoids repeated disk reads)
_mem_cache: dict = {}


def _clean_keyword(raw: str) -> str:
    """Strip noise so the NVD keyword search returns useful results."""
    keyword = raw.strip()
    # Remove leading severity words often prepended by MobSF
    keyword = re.sub(r"^(critical|high|medium|low|warning|info)\s*[:\-]?\s*", "", keyword, flags=re.IGNORECASE)
    # Keep only the first ~6 words to avoid over-specificity
    words = keyword.split()
    keyword = " ".join(words[:6])
    # Drop parenthetical suffixes
    keyword = re.sub(r"\s*\(.*?\)\s*$", "", keyword).strip()
    return keyword


def search_cve_by_keyword(keyword: str, max_results: int = 3) -> list[dict]:
    """
    Search the NVD API v2 for CVEs matching *keyword*.

    Returns a list of dicts, each with keys:
        id, description, cvss_score, cvss_severity, url
    Returns [] on any error.
    """
    clean = _clean_keyword(keyword)
    if not clean:
        return []

    # Check in-memory cache first, then disk cache
    if clean in _mem_cache:
        return _mem_cache[clean]

    disk_hit = get_cached(clean)
    if disk_hit is not None:
        _mem_cache[clean] = disk_hit
        return disk_hit

    # --- Live NVD request ---
    time.sleep(_REQUEST_DELAY)
    try:
        resp = requests.get(
            _NVD_URL,
            params={"keywordSearch": clean, "resultsPerPage": max_results},
            timeout=_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("NVD request failed for '%s': %s", clean, exc)
        _mem_cache[clean] = []
        return []

    results: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Description — prefer English
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        desc = desc[:150] + "…" if len(desc) > 150 else desc

        # CVSS score — prefer v3.1, fall back to v3.0, then v2
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
                break

        # Skip rejected/withdrawn CVEs
        raw_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        if raw_desc.startswith("Rejected reason:") or "DO NOT USE THIS CANDIDATE NUMBER" in raw_desc:
            continue

        results.append({
            "id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_severity": (cvss_severity or "").upper(),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    print(f"[CVE] '{clean}' → {len(results)} result(s)")
    _mem_cache[clean] = results
    set_cache(clean, results)
    return results


def enrich_findings(findings: list[dict]) -> list[dict]:
    """
    Attach CVE matches to each Critical/High finding.
    Mutates findings in-place and also returns them.
    """
    for finding in findings:
        severity = (finding.get("severity") or "").lower()
        if severity not in _ENRICH_SEVERITIES:
            finding.setdefault("cve_matches", [])
            continue

        title = finding.get("title") or finding.get("description") or ""
        matches = search_cve_by_keyword(title)
        finding["cve_matches"] = matches

    return findings
