"""
config.py – Centralised application configuration.

All sensitive values are read from environment variables (loaded from .env
by python-dotenv in app.py).  Nothing secret is hardcoded here.
"""

import os


class Config:
    # ------------------------------------------------------------------ #
    # Flask core                                                           #
    # ------------------------------------------------------------------ #
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

    # ------------------------------------------------------------------ #
    # Database                                                             #
    # ------------------------------------------------------------------ #
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", 3306))
    DB_NAME = os.environ.get("DB_NAME", "securemed_db")
    DB_USER = os.environ.get("DB_USER", "root")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

    # ------------------------------------------------------------------ #
    # File uploads                                                         #
    # ------------------------------------------------------------------ #
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB request cap
    MAX_UPLOAD_SIZE = 5 * 1024 * 1024      # 5 MB per report limit
    ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}

    # ------------------------------------------------------------------ #
    # Session Security                                                     #
    # ------------------------------------------------------------------ #
    SESSION_COOKIE_HTTPONLY = True         # Prevent client script reading session cookie
    SESSION_COOKIE_SAMESITE = "Lax"        # Defense-in-depth CSRF mitigation
    # Set to True in production with TLS/HTTPS; False for local HTTP development
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 1800      # 30-minute session expiry

    # ------------------------------------------------------------------ #
    # Rate Limiting & Brute-Force Throttling                             #
    # ------------------------------------------------------------------ #
    AUTH_MAX_FAILED_ATTEMPTS = int(os.environ.get("AUTH_MAX_FAILED_ATTEMPTS", 5))
    AUTH_LOCKOUT_SECONDS = int(os.environ.get("AUTH_LOCKOUT_SECONDS", 60))

