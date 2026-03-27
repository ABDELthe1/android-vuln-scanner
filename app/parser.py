"""
MobSF Report Parser
Normalises the raw MobSF JSON report into a clean, frontend-ready dict.

Only Critical and High severity findings are returned to keep the output
actionable and noise-free.

MobSF severity vocabulary (lower-cased for comparison):
  critical | high | warning | info | secure
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Severities we surface to the user
TARGET_SEVERITIES = {"critical", "high"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _severity(raw: str) -> str:
    """Normalise a severity string to lower-case."""
    return str(raw).strip().lower()


def _extract_code_findings(code_analysis: dict) -> list[dict]:
    """
    Parse the code_analysis block from a MobSF report.

    MobSF structures this as::

        {
          "findings": {
            "<rule_id>": {
              "metadata": {
                "severity": "high",
                "title": "...",
                "description": "...",
                "cwe": "...",
                "owasp-mobile": "...",
                ...
              },
              "files": { ... }
            }
          }
        }

    Returns a list of normalised finding dicts.
    """
    findings = []
    raw_findings = code_analysis.get("findings", {})

    for rule_id, entry in raw_findings.items():
        metadata = entry.get("metadata", {})
        sev = _severity(metadata.get("severity", ""))

        if sev not in TARGET_SEVERITIES:
            continue

        findings.append({
            "title": metadata.get("title", rule_id),
            "severity": sev,
            "description": metadata.get("description", "No description available."),
            "category": "Code Analysis",
            "cwe": metadata.get("cwe", ""),
            "owasp": metadata.get("owasp-mobile", ""),
            "cvss": metadata.get("cvss", None),
        })

    return findings


def _extract_manifest_findings(manifest_analysis: dict) -> list[dict]:
    """
    Parse the manifest_analysis block.

    MobSF returns manifest issues as a list under the key ``manifest``
    (or ``manifest_findings`` in some versions).  Each item looks like::

        {
          "rule": "...",
          "title": "...",
          "severity": "high",
          "description": "...",
          "component": [...]
        }
    """
    findings = []

    # MobSF uses different keys across versions — try both
    raw_list = manifest_analysis.get("manifest", []) or \
               manifest_analysis.get("manifest_findings", [])

    for item in raw_list:
        sev = _severity(item.get("severity", ""))
        if sev not in TARGET_SEVERITIES:
            continue

        findings.append({
            "title": item.get("title", item.get("rule", "Manifest Issue")),
            "severity": sev,
            "description": item.get("description", "No description available."),
            "category": "Manifest Analysis",
            "cwe": item.get("cwe", ""),
            "owasp": item.get("owasp-mobile", ""),
            "cvss": item.get("cvss", None),
        })

    return findings


def _extract_binary_findings(binary_analysis: dict) -> list[dict]:
    """
    Parse the binary_analysis block.

    Structure (MobSF >= 3.x)::

        {
          "<check_name>": {
            "severity": "high",
            "description": "...",
            ...
          }
        }
    """
    findings = []

    for check_name, entry in binary_analysis.items():
        if not isinstance(entry, dict):
            continue

        sev = _severity(entry.get("severity", ""))
        if sev not in TARGET_SEVERITIES:
            continue

        findings.append({
            "title": check_name.replace("_", " ").title(),
            "severity": sev,
            "description": entry.get("description", "No description available."),
            "category": "Binary Analysis",
            "cwe": entry.get("cwe", ""),
            "owasp": entry.get("owasp-mobile", ""),
            "cvss": entry.get("cvss", None),
        })

    return findings


def _extract_permissions(raw_perms: dict) -> tuple[list, list, list]:
    """
    Split a MobSF permissions dict into dangerous, normal, and signature lists.

    Each entry in raw_perms looks like::

        "android.permission.INTERNET": {
            "status": "normal",
            "description": "Allows the app to create network sockets..."
        }
    """
    dangerous, normal, signature = [], [], []

    for name, info in raw_perms.items():
        if isinstance(info, dict):
            status = str(info.get("status", "")).lower()
            description = info.get("description", "")
        else:
            status = "normal"
            description = ""

        entry = {"name": name, "description": description}

        if "dangerous" in status:
            dangerous.append(entry)
        elif "signature" in status:
            signature.append(entry)
        else:
            normal.append(entry)

    return dangerous, normal, signature


def _extract_trackers(trackers_raw: Any) -> tuple[int, list]:
    """
    Normalise the MobSF trackers block into a (count, list) tuple.

    MobSF can return trackers as either a list of dicts or a nested dict.
    """
    if not trackers_raw:
        return 0, []

    tracker_list = []

    if isinstance(trackers_raw, dict):
        count = int(trackers_raw.get("detected_trackers", 0) or 0)
        raw = trackers_raw.get("trackers", [])

        if isinstance(raw, list):
            for t in raw:
                if not isinstance(t, dict):
                    continue
                cats = t.get("categories", [])
                if isinstance(cats, str):
                    cats = [cats] if cats else []
                tracker_list.append({"name": t.get("name", ""), "categories": cats})

        elif isinstance(raw, dict):
            for name, info in raw.items():
                if not isinstance(info, dict):
                    tracker_list.append({"name": name, "categories": []})
                    continue
                cats = info.get("categories", "")
                if isinstance(cats, str):
                    cats = [cats] if cats else []
                tracker_list.append({"name": name, "categories": cats})

        # Prefer explicit count; fall back to list length
        if not count:
            count = len(tracker_list)

    elif isinstance(trackers_raw, list):
        for t in trackers_raw:
            if not isinstance(t, dict):
                continue
            cats = t.get("categories", [])
            if isinstance(cats, str):
                cats = [cats] if cats else []
            tracker_list.append({"name": t.get("name", ""), "categories": cats})
        count = len(tracker_list)

    else:
        count = 0

    return count, tracker_list


def _extract_network_findings(network_security: Any) -> list[dict]:
    """
    Parse the network_security block.

    This block can be a list or a dict depending on MobSF version.
    """
    findings = []

    items: list = []
    if isinstance(network_security, list):
        items = network_security
    elif isinstance(network_security, dict):
        items = list(network_security.values())

    for item in items:
        if not isinstance(item, dict):
            continue

        sev = _severity(item.get("severity", ""))
        if sev not in TARGET_SEVERITIES:
            continue

        findings.append({
            "title": item.get("title", "Network Security Issue"),
            "severity": sev,
            "description": item.get("description", "No description available."),
            "category": "Network Security",
            "cwe": item.get("cwe", ""),
            "owasp": item.get("owasp-mobile", ""),
            "cvss": item.get("cvss", None),
        })

    return findings


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def parse_report(report_json: dict) -> dict:
    """
    Extract actionable findings from a raw MobSF JSON report.

    Only Critical and High severity findings are included.  Findings are
    collected from four analysis categories:
      - Code Analysis
      - Manifest Analysis
      - Binary Analysis
      - Network Security

    Args:
        report_json: The dict returned by mobsf_client.get_report().

    Returns:
        A clean dict with the following shape::

            {
              "app_name":       str,
              "package_name":   str,
              "version_name":   str,
              "target_sdk":     str,
              "min_sdk":        str,
              "sha256":         str,
              "file_size":      str,
              "security_score": int | None,
              "findings": [
                {
                  "title":       str,
                  "severity":    "critical" | "high",
                  "description": str,
                  "category":    str,
                  "cwe":         str,
                  "owasp":       str,
                  "cvss":        float | None,
                }
              ],
              "total_findings": int,
              "critical_count": int,
              "high_count":     int,
            }
    """
    print(list(report_json.keys()))

    # ------------------------------------------------------------------ #
    # App metadata
    # ------------------------------------------------------------------ #
    app_name = (
        report_json.get("app_name")
        or report_json.get("file_name", "Unknown")
    )
    package_name = (
        report_json.get("package_name")
        or report_json.get("packagename", "Unknown")
    )

    # Security score lives at the top level in recent MobSF versions
    security_score = report_json.get("security_score") or report_json.get("appsec", {}).get("security_score")
    if security_score is not None:
        try:
            security_score = int(security_score)
        except (ValueError, TypeError):
            security_score = None

    # Extra metadata fields
    version_name = str(
        report_json.get("version_name")
        or report_json.get("app_version")
        or ""
    )
    target_sdk = str(
        report_json.get("target_sdk")
        or report_json.get("target_sdk_version")
        or ""
    )
    min_sdk = str(
        report_json.get("min_sdk")
        or report_json.get("min_sdk_version")
        or ""
    )
    sha256 = str(
        report_json.get("sha256")
        or report_json.get("hash")
        or ""
    )
    file_size = str(report_json.get("file_name") or report_json.get("size") or "")

    # ------------------------------------------------------------------ #
    # Permissions
    # ------------------------------------------------------------------ #
    raw_perms = report_json.get("permissions", {}) or {}
    if isinstance(raw_perms, dict):
        perms_dangerous, perms_normal, perms_signature = _extract_permissions(raw_perms)
    else:
        perms_dangerous, perms_normal, perms_signature = [], [], []

    # ------------------------------------------------------------------ #
    # Hardcoded secrets / URLs
    # ------------------------------------------------------------------ #
    secrets = list(report_json.get("secrets", []) or [])
    firebase_urls = list(report_json.get("firebase_urls", []) or [])

    raw_urls = report_json.get("urls", []) or []
    hardcoded_urls = []
    for u in (raw_urls if isinstance(raw_urls, list) else []):
        if isinstance(u, dict):
            url_str = u.get("url", "")
            if url_str:
                hardcoded_urls.append(url_str)
        elif isinstance(u, str) and u.strip():
            hardcoded_urls.append(u.strip())
    # Deduplicate while preserving order
    _seen: set = set()
    hardcoded_urls = [u for u in hardcoded_urls if not (u in _seen or _seen.add(u))]  # type: ignore[func-returns-value]

    # ------------------------------------------------------------------ #
    # Domains
    # ------------------------------------------------------------------ #
    raw_domains = report_json.get("domains", {}) or {}
    domains: list[dict] = []
    if isinstance(raw_domains, dict):
        for domain, info in raw_domains.items():
            if isinstance(info, dict):
                domains.append({
                    "domain": domain,
                    "ip": info.get("ip", ""),
                    "geolocation": info.get("geolocation", ""),
                    "bad": bool(info.get("bad_domains", False)),
                })
            else:
                domains.append({"domain": domain, "ip": "", "geolocation": "", "bad": False})
    elif isinstance(raw_domains, list):
        for d in raw_domains:
            if isinstance(d, dict):
                domains.append({
                    "domain": d.get("url", d.get("domain", "")),
                    "ip": d.get("ip", ""),
                    "geolocation": d.get("geolocation", ""),
                    "bad": bool(d.get("bad_domains", False)),
                })
            elif isinstance(d, str):
                domains.append({"domain": d, "ip": "", "geolocation": "", "bad": False})

    # ------------------------------------------------------------------ #
    # Certificate analysis
    # ------------------------------------------------------------------ #
    cert_issues: list[dict] = []
    raw_cert = report_json.get("certificate_analysis", {}) or {}
    if isinstance(raw_cert, dict):
        raw_cert_findings = raw_cert.get("certificate_findings", [])
        if isinstance(raw_cert_findings, list):
            for item in raw_cert_findings:
                if isinstance(item, (list, tuple)) and len(item) >= 3:
                    sev = str(item[0]).lower()
                    if sev not in ("info", "good", "secure", ""):
                        cert_issues.append({
                            "severity": sev,
                            "title": str(item[1]).replace("_", " ").title(),
                            "description": str(item[2]),
                        })
                elif isinstance(item, dict):
                    sev = str(item.get("severity", "")).lower()
                    if sev not in ("info", "good", "secure", ""):
                        cert_issues.append({
                            "severity": sev,
                            "title": item.get("title", item.get("issue", "")),
                            "description": item.get("description", ""),
                        })

    # ------------------------------------------------------------------ #
    # Trackers
    # ------------------------------------------------------------------ #
    trackers_count, trackers_list = _extract_trackers(report_json.get("trackers", {}))

    # ------------------------------------------------------------------ #
    # Gather findings from every analysis block
    # ------------------------------------------------------------------ #
    all_findings: list[dict] = []

    code_analysis = report_json.get("code_analysis", {})
    if code_analysis:
        code_findings = _extract_code_findings(code_analysis)
        logger.debug("Code analysis: %d critical/high findings", len(code_findings))
        all_findings.extend(code_findings)

    manifest_analysis = report_json.get("manifest_analysis", {})
    if manifest_analysis:
        manifest_findings = _extract_manifest_findings(manifest_analysis)
        logger.debug("Manifest analysis: %d critical/high findings", len(manifest_findings))
        all_findings.extend(manifest_findings)

    binary_analysis = report_json.get("binary_analysis", {})
    if binary_analysis:
        binary_findings = _extract_binary_findings(binary_analysis)
        logger.debug("Binary analysis: %d critical/high findings", len(binary_findings))
        all_findings.extend(binary_findings)

    network_security = report_json.get("network_security", [])
    if network_security:
        network_findings = _extract_network_findings(network_security)
        logger.debug("Network security: %d critical/high findings", len(network_findings))
        all_findings.extend(network_findings)

    # ------------------------------------------------------------------ #
    # Sort: critical first, then high; then alphabetically by title
    # ------------------------------------------------------------------ #
    severity_order = {"critical": 0, "high": 1}
    all_findings.sort(
        key=lambda f: (severity_order.get(f["severity"], 99), f["title"].lower())
    )

    critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
    high_count = sum(1 for f in all_findings if f["severity"] == "high")

    logger.info(
        "Parsed report for '%s': %d critical, %d high findings",
        app_name,
        critical_count,
        high_count,
    )

    return {
        "app_name": app_name,
        "package_name": package_name,
        "version_name": version_name,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "sha256": sha256,
        "file_size": file_size,
        "security_score": security_score,
        "findings": all_findings,
        "total_findings": len(all_findings),
        "critical_count": critical_count,
        "high_count": high_count,
        # Permissions
        "permissions_dangerous": perms_dangerous,
        "permissions_normal": perms_normal,
        "permissions_signature": perms_signature,
        # Secrets / hardcoded data
        "secrets": secrets,
        "firebase_urls": firebase_urls,
        "hardcoded_urls": hardcoded_urls,
        # Network
        "domains": domains,
        "certificate_analysis": cert_issues,
        # Trackers
        "trackers_count": trackers_count,
        "trackers_list": trackers_list,
    }
