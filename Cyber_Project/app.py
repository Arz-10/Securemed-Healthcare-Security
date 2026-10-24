"""
app.py – SecureMed Flask application entry point.

Responsibilities:
  - Load environment variables from .env
  - Apply configuration from config.py
  - Register all blueprints
  - Ensure the uploads folder exists
  - Run the development server when executed directly
"""

import os
import secrets
from flask import Flask, session, flash, redirect, url_for, request
from dotenv import load_dotenv

# Load .env before importing Config so os.environ is already populated.
load_dotenv()

from config import Config
from routes.auth    import auth_bp
from routes.admin   import admin_bp
from routes.doctor  import doctor_bp
from routes.patient import patient_bp
from routes.reports import reports_bp


def create_app() -> Flask:
    """Application factory – creates and configures the Flask app."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure the uploads directory exists (it is git-ignored).
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # ── CSRF protection helpers ────────────────────────────────
    @app.before_request
    def ensure_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": session.get("csrf_token", "")}

    # ── Error handlers ─────────────────────────────────────────
    @app.errorhandler(413)
    def request_entity_too_large(error):
        flash("Uploaded file is too large. Maximum allowed size is 5 MB.", "danger")
        dest = url_for("doctor.dashboard") if session.get("role") == "doctor" else url_for("auth.login")
        referrer = request.referrer
        # Open-redirect defense: only redirect to referrer if it matches the current host
        if referrer and referrer.startswith(request.host_url):
            return redirect(referrer), 413
        return redirect(dest), 413

    # ── Register blueprints ────────────────────────────────────
    app.register_blueprint(auth_bp)          # / and /login and /logout
    app.register_blueprint(admin_bp)         # /admin/...
    app.register_blueprint(doctor_bp)        # /doctor/...
    app.register_blueprint(patient_bp)       # /patient/...
    app.register_blueprint(reports_bp)       # /reports/...

    return app


# ── Dev-server entry point ─────────────────────────────────────
app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
    )
