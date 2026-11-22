#!/usr/bin/env python3
"""
migrate_to_supabase.py — Apply the unified SEKRE v3 + Master Profiler schema
to your existing Supabase PostgreSQL database.

Usage:
    python backend/scripts/migrate_to_supabase.py

Reads DIRECT_URL from backend/.env and applies supabase_schema.sql.
Idempotent: uses CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS.
"""
import os
import sys
from pathlib import Path

try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2-binary not installed. Run: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
ENV_PATH = BACKEND_DIR / ".env"
SCHEMA_PATH = SCRIPT_DIR / "supabase_schema.sql"


def main():
    # Load .env
    if not ENV_PATH.exists():
        print(f"ERROR: {ENV_PATH} not found. Create it with DATABASE_URL/DIRECT_URL.", file=sys.stderr)
        sys.exit(1)
    load_dotenv(ENV_PATH)

    direct_url = os.environ.get("DIRECT_URL") or os.environ.get("DATABASE_URL")
    if not direct_url:
        print("ERROR: DIRECT_URL or DATABASE_URL not set in .env", file=sys.stderr)
        sys.exit(1)

    if "[PROJECT_REF]" in direct_url or "[YOUR_PASSWORD]" in direct_url:
        print("ERROR: .env still has placeholder values. Edit backend/.env with your real Supabase credentials.", file=sys.stderr)
        print("       Get them from: Supabase Dashboard > Project Settings > Database > Connection string", file=sys.stderr)
        sys.exit(1)

    if not SCHEMA_PATH.exists():
        print(f"ERROR: {SCHEMA_PATH} not found.", file=sys.stderr)
        sys.exit(1)

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")

    print(f"Connecting to Supabase PostgreSQL...")
    print(f"  URL: {direct_url.split('@')[1] if '@' in direct_url else '(masked)'}")

    try:
        conn = psycopg2.connect(direct_url)
        conn.autocommit = True
    except Exception as e:
        print(f"ERROR: Failed to connect to Supabase: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected. Applying schema ({len(schema_sql)} bytes)...")

    try:
        with conn.cursor() as cur:
            cur.execute(schema_sql)

        # Count tables
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            tables = [row[0] for row in cur.fetchall()]

        print(f"\nSchema applied successfully. {len(tables)} tables in public schema:")
        for t in tables:
            print(f"  - {t}")

        # Verify all 10 live tables exist
        expected_tables = {
            "owner_profiles", "organizations", "audit_events",
            "scraped_messages", "customer_master_profiles", "master_profile_staging",
            "tickets", "ticket_actions", "ticket_findings", "outbox_queue",
        }
        missing = expected_tables - set(tables)
        if missing:
            print(f"\nWARNING: Expected tables missing: {missing}", file=sys.stderr)
        else:
            print(f"\nAll 10 unified SEKRE v3 + Master Profiler tables confirmed present.")

    except Exception as e:
        print(f"ERROR: Schema application failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
