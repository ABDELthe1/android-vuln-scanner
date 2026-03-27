"""
SQLAlchemy Database Models
Stores scan history so users can review past results without re-scanning.
"""

import json
from datetime import datetime, timezone

from app import db


class ScanResult(db.Model):
    """Persists every completed APK scan and its parsed findings."""

    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # App metadata
    app_name = db.Column(db.String(255), nullable=False, default="Unknown")
    package_name = db.Column(db.String(255), nullable=False, default="Unknown")
    apk_filename = db.Column(db.String(255), nullable=False)

    # Scores
    security_score = db.Column(db.Integer, nullable=True)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)

    # Full findings stored as JSON text
    findings_json = db.Column(db.Text, nullable=True)

    # Extra app metadata (version, SDK levels, hash, file size) stored as JSON
    meta_json = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #

    @property
    def findings(self) -> list:
        """Deserialise the stored JSON findings list."""
        if self.findings_json:
            return json.loads(self.findings_json)
        return []

    @findings.setter
    def findings(self, value: list) -> None:
        """Serialise findings list to JSON for storage."""
        self.findings_json = json.dumps(value)

    @property
    def meta(self) -> dict:
        """Deserialise the stored extra metadata dict, guaranteeing all expected keys."""
        defaults = {
            # App metadata
            "file_size": "", "target_sdk": "", "min_sdk": "",
            "version_name": "", "sha256": "",
            # Permissions
            "permissions_dangerous": [], "permissions_normal": [], "permissions_signature": [],
            # Secrets / hardcoded data
            "secrets": [], "firebase_urls": [], "hardcoded_urls": [],
            # Network
            "domains": [], "certificate_analysis": [],
            # Trackers
            "trackers_count": 0, "trackers_list": [],
        }
        if self.meta_json:
            stored = json.loads(self.meta_json)
            return {**defaults, **stored}
        return defaults

    @meta.setter
    def meta(self, value: dict) -> None:
        """Serialise extra metadata dict to JSON for storage."""
        self.meta_json = json.dumps(value)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation for API responses."""
        return {
            "id": self.id,
            "scan_hash": self.scan_hash,
            "app_name": self.app_name,
            "package_name": self.package_name,
            "apk_filename": self.apk_filename,
            "security_score": self.security_score,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "total_findings": self.total_findings,
            "findings": self.findings,
            "meta": self.meta,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"<ScanResult id={self.id} app='{self.app_name}' "
            f"score={self.security_score}>"
        )
