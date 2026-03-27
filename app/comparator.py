"""
Scan Comparator — Phase 4
Diffs two ScanResult database objects to surface what changed security-wise
between two versions of the same (or different) APKs.

Findings are matched by title. The three output buckets are:
  fixed   — in A but not in B  (vulnerability resolved)
  new     — in B but not in A  (new vulnerability introduced)
  common  — in both A and B    (still present / unchanged)
"""

import logging

import pandas as pd

logger = logging.getLogger(__name__)


def compare_scans(scan_a, scan_b) -> dict:
    """
    Compare two ScanResult objects and return a structured diff.

    Args:
        scan_a: ScanResult baseline (the older / reference scan).
        scan_b: ScanResult target   (the newer / candidate scan).

    Returns::

        {
          "app_a":        str,          # app name of scan A
          "app_b":        str,          # app name of scan B
          "version_a":    str,          # version string of scan A (may be "")
          "version_b":    str,          # version string of scan B (may be "")
          "score_a":      int | None,
          "score_b":      int | None,
          "score_delta":  int | None,   # score_b - score_a
          "fixed":        list[dict],   # findings resolved in B
          "new":          list[dict],   # findings introduced in B
          "common":       list[dict],   # findings present in both
          "summary": {
              "fixed":    int,
              "new":      int,
              "common":   int,
          }
        }
    """
    findings_a: list[dict] = scan_a.findings
    findings_b: list[dict] = scan_b.findings

    meta_a: dict = scan_a.meta if hasattr(scan_a, "meta") else {}
    meta_b: dict = scan_b.meta if hasattr(scan_b, "meta") else {}

    score_a = scan_a.security_score
    score_b = scan_b.security_score
    score_delta = (score_b - score_a) if (score_a is not None and score_b is not None) else None

    base = {
        "app_a":       scan_a.app_name,
        "app_b":       scan_b.app_name,
        "version_a":   meta_a.get("version_name", ""),
        "version_b":   meta_b.get("version_name", ""),
        "score_a":     score_a,
        "score_b":     score_b,
        "score_delta": score_delta,
    }

    # ------------------------------------------------------------------ #
    # Edge cases — one or both scans have no findings
    # ------------------------------------------------------------------ #
    if not findings_a and not findings_b:
        return {**base, "fixed": [], "new": [], "common": [],
                "summary": {"fixed": 0, "new": 0, "common": 0}}

    if not findings_a:
        return {**base, "fixed": [], "new": findings_b, "common": [],
                "summary": {"fixed": 0, "new": len(findings_b), "common": 0}}

    if not findings_b:
        return {**base, "fixed": findings_a, "new": [], "common": [],
                "summary": {"fixed": len(findings_a), "new": 0, "common": 0}}

    # ------------------------------------------------------------------ #
    # Pandas outer merge — match findings by title
    # ------------------------------------------------------------------ #
    df_a = pd.DataFrame(findings_a)[["title"]].assign(_in_a=True)
    df_b = pd.DataFrame(findings_b)[["title"]].assign(_in_b=True)

    merged = pd.merge(df_a, df_b, on="title", how="outer")

    fixed_titles  = set(merged.loc[merged["_in_b"].isna(),              "title"])
    new_titles    = set(merged.loc[merged["_in_a"].isna(),              "title"])
    common_titles = set(merged.loc[merged["_in_a"].eq(True) & merged["_in_b"].eq(True), "title"])

    fixed  = [f for f in findings_a if f.get("title") in fixed_titles]
    new    = [f for f in findings_b if f.get("title") in new_titles]
    common = [f for f in findings_b if f.get("title") in common_titles]

    logger.info(
        "Comparison %s→%s: %d fixed, %d new, %d common (delta %s)",
        scan_a.app_name, scan_b.app_name,
        len(fixed), len(new), len(common),
        f"{score_delta:+d}" if score_delta is not None else "N/A",
    )

    return {
        **base,
        "fixed":  fixed,
        "new":    new,
        "common": common,
        "summary": {"fixed": len(fixed), "new": len(new), "common": len(common)},
    }
