"""
Android APK Vulnerability Scanner - Flask Application Factory
Initializes the Flask app, loads environment variables, and configures extensions.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables from .env before anything else
load_dotenv()

# Shared SQLAlchemy instance — imported by models and routes
db = SQLAlchemy()


def create_app() -> Flask:
    """
    Application factory.  Returns a fully configured Flask app instance.
    Separating creation from instantiation makes the app testable and
    avoids circular-import issues between routes and models.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
    )

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(32))

    # PostgreSQL connection string — falls back to SQLite for local dev
    database_url = os.getenv(
        "DATABASE_URL",
        "sqlite:///vuln_scanner.db",  # SQLite fallback so the app runs without Postgres
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Max upload size: 100 MB (typical APK ceiling)
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

    # Absolute path to the uploads directory (project root / uploads/)
    app.config["UPLOAD_FOLDER"] = os.path.join(
        os.path.dirname(__file__), "..", "uploads"
    )
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # MobSF settings (read once here so every module can pull from app.config)
    app.config["MOBSF_URL"] = os.getenv("MOBSF_URL", "http://localhost:8000")
    app.config["MOBSF_API_KEY"] = os.getenv("MOBSF_API_KEY", "")

    # ------------------------------------------------------------------ #
    # Extensions
    # ------------------------------------------------------------------ #
    db.init_app(app)

    # ------------------------------------------------------------------ #
    # Blueprints / Routes
    # ------------------------------------------------------------------ #
    from app.routes import main_bp  # noqa: E402  (avoid circular import)

    app.register_blueprint(main_bp)

    # ------------------------------------------------------------------ #
    # Database tables
    # ------------------------------------------------------------------ #
    with app.app_context():
        db.create_all()
        _migrate_db(app)

    return app


def _migrate_db(app) -> None:
    """
    Apply lightweight schema migrations that db.create_all() won't handle
    (i.e. adding new columns to existing tables).

    Safe to run on every startup — each statement is guarded against errors.
    """
    from sqlalchemy import text

    migrations = [
        # Add meta_json column introduced in the v2 frontend redesign
        "ALTER TABLE scan_results ADD COLUMN meta_json TEXT",
    ]

    with app.app_context():
        for stmt in migrations:
            try:
                db.session.execute(text(stmt))
                db.session.commit()
            except Exception:
                # Column already exists or table doesn't exist yet — both fine
                db.session.rollback()
