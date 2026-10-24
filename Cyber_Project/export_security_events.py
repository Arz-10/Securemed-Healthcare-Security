"""
export_security_events.py – Command-line utility for exporting SecureMed security audit events.

Usage:
    python export_security_events.py [--limit N] [--since-id ID] [--output FILE]

Examples:
    python export_security_events.py --limit 20
    python export_security_events.py --output exported_events.json
"""

import sys
import argparse
from dotenv import load_dotenv

# Preload environment variables before importing database modules
load_dotenv()

from database.monitoring_export import export_security_events_to_json, fetch_sanitized_security_events


def main():
    parser = argparse.ArgumentParser(description="SecureMed Security Event Exporter")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of events to export (default: 50)")
    parser.add_argument("--since-id", type=int, default=None, help="Export only events with ID strictly greater than this value")
    parser.add_argument("--output", type=str, default=None, help="Destination JSON file path (prints to stdout if omitted)")
    args = parser.parse_args()

    try:
        json_output = export_security_events_to_json(output_path=args.output, limit=args.limit, since_id=args.since_id)
        if args.output:
            print(f"[+] Successfully exported security events to {args.output}")
        else:
            print(json_output)
    except Exception as exc:
        print(f"[-] Export failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
