"""
services.py — Shared service layer for the Master Customer Profiler.

Both the FastAPI app (main.py) and the WorkBuddy MCP server (mcp_server.py)
call these functions. This avoids duplicating pipeline logic and keeps the
CLI (scripts/master_profiler.py) as the single source of truth.

The service layer calls the CLI command functions in-process with a
SimpleNamespace, capturing their JSON output — no subprocess overhead.
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BACKEND_DIR / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import master_profiler as profiler  # noqa: E402
from app.core.security import (  # noqa: E402
    create_access_token, decode_access_token, verify_password, normalize_owner_id,
)

# ---------------------------------------------------------------------------
# Command dispatch map
# ---------------------------------------------------------------------------
COMMANDS = {
    "ingest-omni": profiler.cmd_ingest_omni,
    "pending": profiler.cmd_pending,
    "write": profiler.cmd_write,
    "build-master": profiler.cmd_build_master,
    "approve-staging": profiler.cmd_approve_staging,
    "report": profiler.cmd_report,
    "ticket-pending": profiler.cmd_ticket_pending,
    "ticket-publish": profiler.cmd_ticket_publish,
    "ticket-approve": profiler.cmd_ticket_approve,
}

DEFAULTS = {
    "ingest-omni": {"source": "all", "trigger": "scheduled", "stdin": False,
                    "feed_file": None, "owner": "owner_rifat", "payloads": None},
    "pending": {"limit": 20},
    "write": {"version": "v2", "model": "workbuddy-expert", "file": "",
              "owner": "owner_rifat"},
    "build-master": {"owner": "owner_rifat"},
    "approve-staging": {"id": 0, "decision": "approve", "hash": None,
                        "owner": "owner_rifat"},
    "report": {"tz_group": None},
    "ticket-pending": {"limit": 20},
    "ticket-publish": {"file": None, "payloads": None, "owner": "owner_rifat"},
    "ticket-approve": {"request_id": "", "decision": "approve", "hash": None,
                       "owner": "owner_rifat"},
}


def _run_command(subcommand: str, **params: Any) -> Any:
    """Call a profiler CLI command in-process, returning parsed JSON."""
    if subcommand not in COMMANDS:
        raise ValueError(f"Unknown subcommand: {subcommand}")

    args = SimpleNamespace(**{**DEFAULTS[subcommand], **params})
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        COMMANDS[subcommand](args)
    output = buffer.getvalue().strip()
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"output": output}


def _safe(subcommand: str, **params: Any) -> dict:
    """Run a command, catching errors into a structured response."""
    try:
        return _run_command(subcommand, **params)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc), "command": subcommand}


# ============================================================================
# Public service functions
# ============================================================================

def check_health() -> dict:
    """Report configuration and database connectivity."""
    import psycopg2

    raw_url = os.environ.get("DIRECT_URL") or os.environ.get("DATABASE_URL")
    url = profiler._clean_pg_dsn(raw_url or "")
    result = {
        "service": "customer-master-profiler",
        "status": "ok",
        "database_configured": bool(url) and "[PROJECT_REF]" not in url,
        "database_connected": False,
        "profile_script": str(SCRIPTS_DIR / "master_profiler.py"),
    }
    if result["database_configured"]:
        try:
            conn = psycopg2.connect(url, connect_timeout=5)
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            conn.close()
            result["database_connected"] = True
        except Exception as exc:  # noqa: BLE001
            result["status"] = "degraded"
            result["database_error"] = str(exc)
    else:
        result["status"] = "degraded"
        result["message"] = "Supabase is not configured — edit backend/.env"
    return result


def run_ingest(source: str = "all", trigger: str = "scheduled",
               payloads: list[dict] | None = None, feed_file: str | None = None,
               owner: str = "owner_rifat") -> dict:
    """Ingest messages from payloads, a feed file, or the default fixture."""
    return _safe("ingest-omni", source=source, trigger=trigger,
                 payloads=payloads, feed_file=feed_file, owner=owner)


def get_pending(limit: int = 20) -> list[dict]:
    """Fetch PII-redacted pending messages for Expert analysis."""
    result = _safe("pending", limit=limit)
    if isinstance(result, dict) and result.get("status") == "error":
        return [result]  # Error surfaced as a single item
    return result if isinstance(result, list) else []


def write_enrichment(results: list[dict], version: str = "v2",
                     model: str = "workbuddy-expert",
                     owner: str = "owner_rifat") -> dict:
    """Validate and write Expert enrichment results to Supabase."""
    if not isinstance(results, list):
        return {"status": "error", "error": "results must be a JSON array"}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as handle:
        json.dump(results, handle, ensure_ascii=False)
        temp_path = handle.name

    try:
        return _safe("write", version=version, model=model,
                     file=temp_path, owner=owner)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def build_master_profiles(owner: str = "owner_rifat") -> dict:
    """Aggregate enriched messages into master customer profiles."""
    return _safe("build-master", owner=owner)


def approve_staging(staging_id: str | int, decision: str = "approve",
                    owner: str = "owner_rifat",
                    approval_hash: str | None = None) -> dict:
    """Approve or reject a staged profile change."""
    return _safe("approve-staging", id=str(staging_id), decision=decision,
                 hash=approval_hash, owner=owner)


def get_report(tz_group: str | None = None) -> str:
    """Build the Markdown master profile report."""
    result = _safe("report", tz_group=tz_group)
    if isinstance(result, dict) and "output" in result:
        return result["output"]
    return json.dumps(result, indent=2, ensure_ascii=False)


def query_profiles(contact_id: str = "", full_name: str = "", org_name: str = "",
                   city: str = "", tz_label: str = "", category: str = "",
                   verification_status: str = "",
                   needs_review_only: bool = False,
                   viewer_owner_id: str = "",
                   limit: int = 50) -> dict:
    """Query master profiles with optional filters (supports partial full_name lookup and RBAC viewer scoping)."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        conditions: list[str] = []
        params: list[Any] = []

        if contact_id:
            conditions.append("contact_id = %s")
            params.append(contact_id)
        if full_name:
            conditions.append("full_name ILIKE %s")
            params.append(f"%{full_name}%")
        if org_name:
            conditions.append("org_name ILIKE %s")
            params.append(f"%{org_name}%")
        if city:
            conditions.append("city ILIKE %s")
            params.append(f"%{city}%")
        if tz_label:
            conditions.append("tz_label = %s")
            params.append(tz_label)
        if category:
            conditions.append("category = %s")
            params.append(category)
        if verification_status:
            conditions.append("verification_status = %s")
            params.append(verification_status)
        if needs_review_only:
            conditions.append("needs_review = TRUE")
        if viewer_owner_id:
            conditions.append("visible_to_roles @> %s::jsonb")
            params.append(json.dumps([viewer_owner_id]))

        where = " AND ".join(conditions) if conditions else "TRUE"
        params.append(limit)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM public.customer_master_profiles "
                f"WHERE {where} ORDER BY tz_label, full_name LIMIT %s",
                params,
            )
            rows = cur.fetchall()

            staging_count = 0
            if rows:
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM public.master_profile_staging "
                    "WHERE contact_id = ANY(%s) AND status = 'pending_approval'",
                    ([r["contact_id"] for r in rows],),
                )
                staging_count = cur.fetchone()["cnt"]
        conn.close()

        profiles = []
        for row in rows:
            item = {}
            for key, value in row.items():
                if hasattr(value, "isoformat"):
                    item[key] = value.isoformat()
                else:
                    item[key] = value
            profiles.append(item)

        return {
            "success": True,
            "count": len(profiles),
            "ambiguous_match": bool(full_name and len(profiles) > 1),
            "staging_pending": staging_count,
            "profiles": profiles,
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


# ============================================================================
# Ticket & Personalization Bridge Services (For Friend's WorkBuddy #2)
# ============================================================================

def get_pending_tickets(limit: int = 20) -> list[dict]:
    """Fetch enriched messages joined with customer_master_profiles for personalization."""
    result = _safe("ticket-pending", limit=limit)
    if isinstance(result, dict) and result.get("status") == "error":
        return [result]
    return result if isinstance(result, list) else []


def publish_personalized_ticket(
    payload: dict | list[dict],
    owner: str = "owner_rifat",
) -> dict:
    """Auto-map 1 flat JSON (or list) into tickets, ticket_actions, ticket_findings & audit_events."""
    if not isinstance(payload, (dict, list)):
        return {"status": "error", "error": "payload must be a JSON object or array"}
    items = payload if isinstance(payload, list) else [payload]
    return _safe("ticket-publish", payloads=items, owner=owner)


def approve_ticket_to_outbox(
    request_id: str,
    decision: str = "approve",
    owner: str = "owner_rifat",
    approval_hash: str | None = None,
) -> dict:
    """Approve or reject a ticket; approved actions enter outbox_queue (60s undo)."""
    if not request_id:
        return {"status": "error", "error": "request_id is required"}
    return _safe(
        "ticket-approve",
        request_id=request_id,
        decision=decision,
        owner=owner,
        hash=approval_hash,
    )


def query_tickets(status: str = "", owner_id: str = "",
                  viewer_owner_id: str = "", limit: int = 50) -> dict:
    """Query tickets with their nested actions, findings, and owner-scoped can_approve flag."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        conditions: list[str] = []
        params: list[Any] = []
        effective_owner_filter = owner_id or viewer_owner_id
        if status:
            conditions.append("status = %s")
            params.append(status)
        if effective_owner_filter and effective_owner_filter != "all":
            conditions.append("owner_id = %s")
            params.append(effective_owner_filter)
        where = " AND ".join(conditions) if conditions else "TRUE"
        params.append(limit)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM public.tickets WHERE {where} ORDER BY updated_at DESC LIMIT %s",
                params,
            )
            ticket_rows = cur.fetchall()

            request_ids = [r["request_id"] for r in ticket_rows]
            actions_by_req: dict[str, list[dict]] = {}
            findings_by_req: dict[str, list[dict]] = {}

            if request_ids:
                cur.execute(
                    "SELECT * FROM public.ticket_actions WHERE request_id = ANY(%s)",
                    (request_ids,),
                )
                for a in cur.fetchall():
                    item = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in a.items()}
                    actions_by_req.setdefault(a["request_id"], []).append(item)

                cur.execute(
                    "SELECT * FROM public.ticket_findings WHERE request_id = ANY(%s)",
                    (request_ids,),
                )
                for f in cur.fetchall():
                    findings_by_req.setdefault(f["request_id"], []).append(dict(f))
        conn.close()

        tickets = []
        for row in ticket_rows:
            item = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()}
            item["actions"] = actions_by_req.get(row["request_id"], [])
            item["findings"] = findings_by_req.get(row["request_id"], [])
            item["can_approve"] = (
                True if not viewer_owner_id else (row.get("owner_id") == viewer_owner_id)
            )
            tickets.append(item)

        return {
            "success": True,
            "count": len(tickets),
            "viewer_owner_id": viewer_owner_id or None,
            "tickets": tickets,
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


# ============================================================================
# Website Login & Owner Authentication Services (public.owner_profiles)
# ============================================================================

def _parse_owner_row(row: dict) -> dict:
    raw_pjson = row.get("profile_json") or "{}"
    if isinstance(raw_pjson, str):
        try:
            pjson = json.loads(raw_pjson)
        except Exception:
            pjson = {}
    else:
        pjson = dict(raw_pjson)
    return {
        "owner_id": row["owner_id"],
        "name": row["name"],
        "email": pjson.get("email", ""),
        "role": pjson.get("role", "Owner / Admin"),
        "permissions": pjson.get("permissions", ["ingest", "enrich", "build_master", "approve_staging", "send_external"]),
        "visible_categories": pjson.get("visible_categories", ["customer", "peer"]),
        "_password_hash": pjson.get("password_hash", ""),
    }


def authenticate_owner(identifier: str, password: str) -> dict:
    """Authenticate an owner by owner_id, name, or email against public.owner_profiles."""
    from psycopg2.extras import RealDictCursor

    ident = (identifier or "").strip()
    if not ident or not password:
        return {"success": False, "error": "identifier and password are required"}

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT owner_id, name, profile_json FROM public.owner_profiles")
            rows = cur.fetchall()

        matched = None
        ident_lower = ident.lower()
        normalized = normalize_owner_id(ident) if ident_lower in ("rifat", "andi", "owner_rifat", "owner_andi") else ""
        for r in rows:
            parsed = _parse_owner_row(r)
            if (
                parsed["owner_id"].lower() == ident_lower
                or parsed["name"].lower() == ident_lower
                or (parsed["email"] and parsed["email"].lower() == ident_lower)
                or (normalized and parsed["owner_id"] == normalized)
            ):
                matched = parsed
                break

        if not matched or not verify_password(password, matched["_password_hash"]):
            target_id = matched["owner_id"] if matched else ident
            profiler.append_audit(conn, target_id, "auth_login_failed", "owner_profiles", target_id, {
                "identifier": ident,
            })
            conn.commit()
            conn.close()
            return {"success": False, "error": "Invalid credentials"}

        owner_public = {k: v for k, v in matched.items() if not k.startswith("_")}
        token = create_access_token(
            owner_id=owner_public["owner_id"],
            name=owner_public["name"],
            role=owner_public["role"],
            permissions=owner_public["permissions"],
            visible_categories=owner_public["visible_categories"],
        )
        profiler.append_audit(conn, owner_public["owner_id"], "auth_login_success", "owner_profiles", owner_public["owner_id"], {
            "email": owner_public["email"],
            "role": owner_public["role"],
        })
        conn.commit()
        conn.close()
        return {
            "success": True,
            "access_token": token,
            "token_type": "bearer",
            "owner": owner_public,
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def get_owner_profile(owner_id: str) -> dict:
    """Fetch public owner profile from public.owner_profiles by owner_id."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT owner_id, name, profile_json FROM public.owner_profiles WHERE owner_id = %s",
                (owner_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return {"success": False, "error": f"Owner {owner_id} not found"}
        parsed = _parse_owner_row(row)
        return {"success": True, "owner": {k: v for k, v in parsed.items() if not k.startswith("_")}}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def record_logout(owner_id: str) -> dict:
    """Append auth_logout event to public.audit_events."""
    try:
        conn = profiler.get_connection()
        profiler.append_audit(conn, owner_id, "auth_logout", "owner_profiles", owner_id, {})
        conn.commit()
        conn.close()
        return {"success": True, "owner_id": owner_id}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}
