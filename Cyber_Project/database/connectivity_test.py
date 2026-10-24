"""
database/connectivity_test.py – SecureMed MySQL connectivity test.

Verifies:
  1. python-dotenv loads the .env file
  2. config.py exposes the correct DB settings (name printed, not password)
  3. mysql-connector-python can open a connection to securemed_db
  4. All six expected tables are present

Run from the project root:
    python database/connectivity_test.py

SAFE OUTPUT GUARANTEE
---------------------
This script never prints DB_PASSWORD, the connection string, or any secret.
Only the DB host, port, name, and user are shown.
"""

import sys
import os

# ── 1. Ensure project root is on sys.path ─────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ── 2. Load .env so environment variables are available ───────────────────
from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# ── 3. Import config and db helper ────────────────────────────────────────
from config import Config
from database.db import get_connection, close_connection

EXPECTED_TABLES = {
    "users",
    "patients",
    "doctors",
    "appointments",
    "medical_records",
    "uploads",
    "audit_logs",
}

PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[INFO]"


def _section(title: str) -> None:
    print(f"\n{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}")


def run_test() -> bool:
    all_passed = True

    # ── Check 1: Config loaded ─────────────────────────────────────────
    _section("1 · Flask / Config")
    print(f"{INFO} DB_HOST  : {Config.DB_HOST}")
    print(f"{INFO} DB_PORT  : {Config.DB_PORT}")
    print(f"{INFO} DB_NAME  : {Config.DB_NAME}")
    print(f"{INFO} DB_USER  : {Config.DB_USER}")
    print(f"{INFO} DB_PASSWORD : {'[set]' if Config.DB_PASSWORD else '[MISSING]'}")

    if Config.DB_NAME != "securemed_db":
        print(f"{FAIL} DB_NAME is {Config.DB_NAME!r} — expected 'securemed_db'")
        all_passed = False
    else:
        print(f"{PASS} DB_NAME correctly set to 'securemed_db'")

    if not Config.DB_PASSWORD:
        print(f"{FAIL} DB_PASSWORD is not set — cannot connect.")
        print(f"       Copy .env.example → .env and set DB_PASSWORD.")
        return False
    else:
        print(f"{PASS} DB_PASSWORD is present (not displayed)")

    # ── Check 2: Open connection ───────────────────────────────────────
    _section("2 · MySQL Connection")
    conn = cursor = None
    try:
        conn = get_connection()
        print(f"{PASS} Connected to MySQL at {Config.DB_HOST}:{Config.DB_PORT}")
    except RuntimeError as exc:
        print(f"{FAIL} {exc}")
        all_passed = False
        return all_passed

    # ── Check 3: Correct database selected ────────────────────────────
    _section("3 · Database Identity")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE();")
        (active_db,) = cursor.fetchone()
        if active_db == "securemed_db":
            print(f"{PASS} Active database: {active_db!r}")
        else:
            print(f"{FAIL} Active database is {active_db!r}, expected 'securemed_db'")
            all_passed = False
        cursor.close()
        cursor = None
    except Exception as exc:
        print(f"{FAIL} Could not query active database: {exc}")
        all_passed = False

    # ── Check 4: Tables present ────────────────────────────────────────
    _section("4 · Tables in securemed_db")
    try:
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES;")
        found_tables = {row[0].lower() for row in cursor.fetchall()}
        cursor.close()
        cursor = None

        for tbl in sorted(EXPECTED_TABLES):
            if tbl in found_tables:
                print(f"{PASS} Table exists: {tbl}")
            else:
                print(f"{FAIL} Table MISSING: {tbl}")
                all_passed = False

        extra = found_tables - EXPECTED_TABLES
        if extra:
            print(f"{INFO} Extra tables (not in expected set): {sorted(extra)}")

    except Exception as exc:
        print(f"{FAIL} Could not list tables: {exc}")
        all_passed = False

    finally:
        close_connection(conn, cursor)

    # ── Summary ────────────────────────────────────────────────────────
    _section("Summary")
    if all_passed:
        print(f"{PASS} All checks passed — securemed_db is ready for Flask integration.")
    else:
        print(f"{FAIL} One or more checks failed — review output above.")

    return all_passed


if __name__ == "__main__":
    ok = run_test()
    sys.exit(0 if ok else 1)
