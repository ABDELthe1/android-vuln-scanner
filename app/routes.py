"""
Flask Routes / Blueprint
Defines every HTTP endpoint exposed by the scanner web app.

Endpoints:
  GET  /                  — Upload dashboard.
  POST /scan              — Accept an APK, run MobSF analysis, redirect to report.
  GET  /report/<scan_id>  — Full report page for a completed scan.
  GET  /history           — Scan history page.
  GET  /scan/<id>         — JSON API: single scan result (kept for backwards compat).
"""

import os
import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
)
from werkzeug.utils import secure_filename

from app import db
from app.models import ScanResult
from app.mobsf_client import MobSFError, get_report, get_scorecard, start_scan, upload_apk
from app.parser import parse_report

logger = logging.getLogger(__name__)

main_bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {"apk"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@main_bp.route("/", methods=["GET"])
def index():
    """Render the main upload dashboard."""
    return render_template("dashboard.html")


@main_bp.route("/scan", methods=["POST"])
def scan():
    """
    Accept an APK file upload, run MobSF analysis, persist to DB, and
    redirect the browser to the dedicated report page.

    On failure, flash an error message and redirect back to the upload page.
    """
    # ------------------------------------------------------------------ #
    # 1. Validate the uploaded file
    # ------------------------------------------------------------------ #
    if "file" not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for("main.index"))

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("main.index"))

    if not _allowed_file(uploaded_file.filename):
        flash("Invalid file type. Only .apk files are accepted.", "error")
        return redirect(url_for("main.index"))

    filename = secure_filename(uploaded_file.filename)
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    save_path = os.path.join(upload_folder, filename)

    # ------------------------------------------------------------------ #
    # 2. Save APK to disk
    # ------------------------------------------------------------------ #
    try:
        uploaded_file.save(save_path)
        logger.info("APK saved to: %s", save_path)
    except OSError as exc:
        logger.exception("Failed to save APK")
        flash(f"Could not save uploaded file: {exc}", "error")
        return redirect(url_for("main.index"))

    # ------------------------------------------------------------------ #
    # 3. Run MobSF pipeline: upload → scan → report → scorecard
    # ------------------------------------------------------------------ #
    try:
        scan_hash = upload_apk(save_path)
        start_scan(scan_hash)
        report_json = get_report(scan_hash)
        try:
            scorecard = get_scorecard(scan_hash)
            if report_json.get("security_score") is None and scorecard:
                report_json["security_score"] = scorecard.get("security_score")
        except MobSFError as sc_err:
            logger.warning("Scorecard fetch failed (non-fatal): %s", sc_err)

    except MobSFError as exc:
        logger.error("MobSF pipeline error: %s", exc)
        flash(f"Analysis failed: {exc}", "error")
        return redirect(url_for("main.index"))

    # ------------------------------------------------------------------ #
    # 4. Parse the report
    # ------------------------------------------------------------------ #
    parsed = parse_report(report_json)

    # ------------------------------------------------------------------ #
    # 5. Persist to the database
    # ------------------------------------------------------------------ #
    existing = ScanResult.query.filter_by(scan_hash=scan_hash).first()
    if existing:
        logger.info("Scan hash %s already stored as id=%d, skipping insert", scan_hash, existing.id)
        return redirect(url_for("main.report", scan_id=existing.id))

    try:
        scan_record = ScanResult(
            scan_hash=scan_hash,
            app_name=parsed["app_name"],
            package_name=parsed["package_name"],
            apk_filename=filename,
            security_score=parsed["security_score"],
            critical_count=parsed["critical_count"],
            high_count=parsed["high_count"],
            total_findings=parsed["total_findings"],
        )
        scan_record.findings = parsed["findings"]
        scan_record.meta = {
            # App metadata
            "version_name":         parsed.get("version_name", ""),
            "target_sdk":           parsed.get("target_sdk", ""),
            "min_sdk":              parsed.get("min_sdk", ""),
            "sha256":               parsed.get("sha256", ""),
            "file_size":            parsed.get("file_size", ""),
            # Permissions
            "permissions_dangerous":  parsed.get("permissions_dangerous", []),
            "permissions_normal":     parsed.get("permissions_normal", []),
            "permissions_signature":  parsed.get("permissions_signature", []),
            # Secrets / hardcoded data
            "secrets":              parsed.get("secrets", []),
            "firebase_urls":        parsed.get("firebase_urls", []),
            "hardcoded_urls":       parsed.get("hardcoded_urls", []),
            # Network
            "domains":              parsed.get("domains", []),
            "certificate_analysis": parsed.get("certificate_analysis", []),
            # Trackers
            "trackers_count":       parsed.get("trackers_count", 0),
            "trackers_list":        parsed.get("trackers_list", []),
        }
        db.session.add(scan_record)
        db.session.commit()
        logger.info("Scan result saved with id=%d", scan_record.id)
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        logger.exception("Failed to persist scan result: %s", exc)
        flash("Scan completed but could not be saved to history.", "error")
        return redirect(url_for("main.index"))

    return redirect(url_for("main.report", scan_id=scan_record.id))


@main_bp.route("/report/<int:scan_id>", methods=["GET"])
def report(scan_id: int):
    """
    Render the full report page for a stored scan result.

    Args (path):
        scan_id: The integer primary-key of the scan.
    """
    scan = ScanResult.query.get_or_404(scan_id)
    return render_template("report.html", scan=scan)


@main_bp.route("/history", methods=["GET"])
def history():
    """
    Render the scan history page showing the 50 most recent scans.
    """
    scans = (
        ScanResult.query
        .order_by(ScanResult.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("history.html", scans=scans)


@main_bp.route("/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """
    JSON API: return full details for a single stored scan result.
    Kept for backwards compatibility with any external tooling.
    """
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())
