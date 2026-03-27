"""
Scan Comparator
Uses Pandas to diff two scan results and highlight regressions (new findings)
and improvements (fixed findings) between APK versions.

Intended for Phase 3 — the /compare route will use this module.
"""

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def _findings_to_df(findings: list[dict]) -> pd.DataFrame:
    """Convert a findings list into a DataFrame keyed on (title, category)."""
    if not findings:
        return pd.DataFrame(columns=["title", "severity", "description", "category"])
    return pd.DataFrame(findings)


def compare_scans(scan_a: dict, scan_b: dict) -> dict:
    """
    Compare two parsed scan results and return a structured diff.

    Args:
        scan_a: Output of parser.parse_report() for the *baseline* APK.
        scan_b: Output of parser.parse_report() for the *new* APK.

    Returns:
        A dict with:
          - ``new_findings``     — findings present in B but not A (regressions)
          - ``fixed_findings``   — findings present in A but not B (improvements)
          - ``common_findings``  — findings present in both
          - ``score_delta``      — security_score change (B - A), None if unavailable
          - ``summary``          — human-readable summary string
    """
    df_a = _findings_to_df(scan_a.get("findings", []))
    df_b = _findings_to_df(scan_b.get("findings", []))

    merge_keys = ["title", "category"]

    if df_a.empty and df_b.empty:
        return _empty_result()

    if df_a.empty:
        return {
            "new_findings": scan_b.get("findings", []),
            "fixed_findings": [],
            "common_findings": [],
            "score_delta": _score_delta(scan_a, scan_b),
            "summary": f"{len(scan_b['findings'])} new finding(s) introduced.",
        }

    if df_b.empty:
        return {
            "new_findings": [],
            "fixed_findings": scan_a.get("findings", []),
            "common_findings": [],
            "score_delta": _score_delta(scan_a, scan_b),
            "summary": f"{len(scan_a['findings'])} finding(s) fixed.",
        }

    # Outer merge to identify new / fixed / common
    merged = pd.merge(
        df_a[merge_keys].assign(_in_a=True),
        df_b[merge_keys].assign(_in_b=True),
        on=merge_keys,
        how="outer",
    )

    new_mask = merged["_in_a"].isna() & merged["_in_b"].eq(True)
    fixed_mask = merged["_in_b"].isna() & merged["_in_a"].eq(True)
    common_mask = merged["_in_a"].eq(True) & merged["_in_b"].eq(True)

    new_titles = set(
        zip(merged.loc[new_mask, "title"], merged.loc[new_mask, "category"])
    )
    fixed_titles = set(
        zip(merged.loc[fixed_mask, "title"], merged.loc[fixed_mask, "category"])
    )
    common_titles = set(
        zip(merged.loc[common_mask, "title"], merged.loc[common_mask, "category"])
    )

    def _filter(findings, key_set):
        return [
            f for f in findings
            if (f.get("title"), f.get("category")) in key_set
        ]

    new_findings = _filter(scan_b["findings"], new_titles)
    fixed_findings = _filter(scan_a["findings"], fixed_titles)
    common_findings = _filter(scan_b["findings"], common_titles)

    delta = _score_delta(scan_a, scan_b)
    delta_str = f"Score delta: {delta:+d}. " if delta is not None else ""

    summary = (
        f"{delta_str}"
        f"{len(new_findings)} new finding(s), "
        f"{len(fixed_findings)} fixed, "
        f"{len(common_findings)} unchanged."
    )

    logger.info("Comparison complete: %s", summary)

    return {
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "common_findings": common_findings,
        "score_delta": delta,
        "summary": summary,
    }


def _score_delta(scan_a: dict, scan_b: dict) -> int | None:
    score_a = scan_a.get("security_score")
    score_b = scan_b.get("security_score")
    if score_a is not None and score_b is not None:
        return score_b - score_a
    return None


def _empty_result() -> dict:
    return {
        "new_findings": [],
        "fixed_findings": [],
        "common_findings": [],
        "score_delta": None,
        "summary": "Both scans have no findings.",
    }
