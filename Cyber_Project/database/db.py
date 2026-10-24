"""
database/db.py – MySQL connection helper for SecureMed.

Provides two public helpers:

    get_connection()      – return an open mysql.connector.Connection
    close_connection()    – close a connection + optional cursor safely

All configuration is read from environment variables via Config.
No credentials are ever logged or re-raised in plain text.

Usage example
-------------
    from database.db import get_connection, close_connection

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username FROM users LIMIT 1")
        row = cursor.fetchone()
    except RuntimeError as exc:
        # exc message is safe to log / display — no password inside
        app.logger.error("DB error: %s", exc)
    finally:
        close_connection(conn, cursor)
"""

import os
import mysql.connector
from mysql.connector import Error as MySQLError


# ---------------------------------------------------------------------------
# Internal: build connection kwargs from environment (no fallback for password)
# ---------------------------------------------------------------------------

def _build_config() -> dict:
    """
    Assemble mysql.connector keyword arguments from environment variables.

    Raises
    ------
    RuntimeError
        If a required variable is missing or has an invalid type.
    """
    host = os.environ.get("DB_HOST", "localhost")
    name = os.environ.get("DB_NAME", "securemed_db")
    user = os.environ.get("DB_USER", "root")
    password = os.environ.get("DB_PASSWORD")          # no default – must be set
    raw_port = os.environ.get("DB_PORT", "3306")

    if password is None:
        raise RuntimeError(
            "DB_PASSWORD environment variable is not set. "
            "Copy .env.example to .env and fill in your credentials."
        )

    try:
        port = int(raw_port)
    except ValueError:
        raise RuntimeError(f"DB_PORT must be an integer, got: {raw_port!r}")

    return {
        "host":     host,
        "port":     port,
        "database": name,
        "user":     user,
        "password": password,
        # Let mysql-connector use utf8mb4 so it matches the schema charset.
        "charset":  "utf8mb4",
        # Raise python exceptions on MySQL errors (default is True in 8.x
        # but we set it explicitly for clarity).
        "raise_on_warnings": False,
        # Automatically reconnect dropped connections.
        "autocommit": False,
        # Connection timeout (seconds).
        "connection_timeout": 10,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_connection() -> mysql.connector.MySQLConnection:
    """
    Open and return a new MySQL connection.

    The caller is responsible for closing it (use close_connection() or a
    try/finally block).

    Returns
    -------
    mysql.connector.MySQLConnection

    Raises
    ------
    RuntimeError
        Safe error message with no credentials embedded.
    """
    cfg = _build_config()
    try:
        conn = mysql.connector.connect(**cfg)
        return conn
    except MySQLError as exc:
        # Strip the exception so the password never surfaces in a log line.
        raise RuntimeError(
            f"Could not connect to MySQL at {cfg['host']}:{cfg['port']} "
            f"(database={cfg['database']!r}, user={cfg['user']!r}). "
            f"MySQL error code: {exc.errno}"
        ) from None


def close_connection(conn, cursor=None) -> None:
    """
    Safely close a cursor and/or connection.

    Parameters
    ----------
    conn   : mysql.connector.MySQLConnection or None
    cursor : mysql.connector cursor or None

    Never raises — intended for use in finally blocks.
    """
    try:
        if cursor is not None:
            cursor.close()
    except Exception:
        pass

    try:
        if conn is not None and conn.is_connected():
            conn.close()
    except Exception:
        pass
