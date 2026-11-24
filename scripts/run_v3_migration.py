#!/usr/bin/env python3
"""
run_v3_migration.py — Apply migrate_v3_intelligence.sql to Supabase PostgreSQL
and verify all 8 new columns exist on public.customer_master_profiles.
"""
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

import master_profiler as mp  # noqa: E402

EXPECTED_COLUMNS = {
    "character_style",
    "churn_risk_level",
    "communication_prefs",
    "character_profile",
    "motivation_and_pain",
    "persuasion_profile",
    "relationship_health",
    "agent_brief",
}


def main() -> None:
    sql_path = SCRIPT_DIR / "migrate_v3_intelligence.sql"
    sql = sql_path.read_text(encoding="utf-8")

    conn = mp.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'customer_master_profiles'
                  AND column_name = ANY(%s)
                ORDER BY column_name
                """,
                (sorted(EXPECTED_COLUMNS),),
            )
            found = cur.fetchall()
        conn.commit()
    finally:
        conn.close()

    found_names = {row[0] for row in found}
    missing = EXPECTED_COLUMNS - found_names
    print("Migration applied successfully.")
    for col_name, data_type in found:
        print(f"  - {col_name}: {data_type}")
    if missing:
        print(f"ERROR: Missing columns after migration: {sorted(missing)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
