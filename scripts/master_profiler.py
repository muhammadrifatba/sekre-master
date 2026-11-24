#!/usr/bin/env python3
"""
master_profiler.py — Supabase-Native WorkBuddy Master Customer Profiler

Connects directly to Supabase PostgreSQL via psycopg2.
6 subcommands:
  1. ingest-omni     — Multi-channel ingestion (Email/WA/Telegram) -> scraped_messages
  2. pending         — Fetch PII-redacted pending rows for Expert analysis
  3. write           — Validate & write Expert enrichment to scraped_messages
  4. build-master    — Aggregate into customer_master_profiles + sync existing tables
  5. approve-staging — Approve/reject staged conflicts
  6. report          — Print Markdown Master Profile Table + Staging + Audit verification

Usage:
    python backend/scripts/master_profiler.py ingest-omni --source all --trigger scheduled
    python backend/scripts/master_profiler.py pending --limit 20
    python backend/scripts/master_profiler.py write --version v2 --file results.json
    python backend/scripts/master_profiler.py build-master --owner owner_rifat
    python backend/scripts/master_profiler.py approve-staging --id 1 --decision approve --owner owner_rifat
    python backend/scripts/master_profiler.py report --tz-group WITA
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, Json
except ImportError:
    print("ERROR: psycopg2-binary not installed. Run: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Path setup — allow importing from backend.app.core
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

try:
    from dotenv import load_dotenv
    from app.core.security import (
        sha256_hash, canonical_hash, compute_chain_hash, verify_chain,
        scan_injections, redact_pii, extract_phone_e164, extract_email,
        is_landline, check_pdp_blocklist, clean_body, compute_features,
        normalize_owner_id,
    )
    from app.core.rules_engine import (
        resolve_timezone, compute_best_contact_window, apply_peer_privacy,
        extract_fleet_units, infer_salutation, generate_contact_id,
        generate_master_id, compute_scheduled_send_at, build_wa_handoff_link,
        TZ_WIB, TZ_WITA, TZ_WIT,
    )
except ImportError as e:
    print(f"ERROR importing modules: {e}", file=sys.stderr)
    print("Make sure you're running from the project root with backend/ in the path.", file=sys.stderr)
    sys.exit(1)

# Load .env
ENV_PATH = BACKEND_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_LIMIT = 20
CONFIDENCE_THRESHOLD = 0.6
FIXTURES_DIR = BACKEND_DIR / "config" / "fixtures"

# ============================================================================
# Database Connection
# ============================================================================

def _clean_pg_dsn(url: str) -> str:
    """Strip Prisma-only query params like pgbouncer=true that psycopg2 rejects."""
    if not url or "pgbouncer=" not in url:
        return url
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url)
    filtered = [(k, v) for k, v in parse_qsl(parts.query) if k.lower() != "pgbouncer"]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(filtered), parts.fragment))


def get_connection():
    """Get a psycopg2 connection to Supabase PostgreSQL."""
    raw_url = os.environ.get("DIRECT_URL") or os.environ.get("DATABASE_URL")
    if not raw_url:
        print("ERROR: DATABASE_URL not set in .env", file=sys.stderr)
        sys.exit(1)
    url = _clean_pg_dsn(raw_url)
    conn = psycopg2.connect(url, connect_timeout=5)
    conn.autocommit = False
    return conn


def get_hmac_key():
    return os.environ.get("AUDIT_HMAC_KEY", "")

# ============================================================================
# Audit Helper
# ============================================================================

def append_audit(conn, actor, action, target_type="", target_id="", details=None):
    """Append to the live DBeaver HMAC-SHA256 hash-chained audit_events table."""
    if details is None:
        details = {}
    hmac_key = get_hmac_key()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT curr_hash FROM public.audit_events ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = (row["curr_hash"] if row and row["curr_hash"] else "")

    request_id = str(target_id or f"{target_type}:{action}")
    payload_json = {
        "actor": actor,
        "target_type": target_type,
        "target_id": target_id,
        **details,
    }
    curr_hash = compute_chain_hash(prev_hash or None, actor, action, target_type, target_id, details, hmac_key)
    ts_iso = datetime.now(timezone.utc).isoformat()

    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO public.audit_events
               (timestamp, request_id, event_type, payload_json, prev_hash, curr_hash)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (ts_iso, request_id, action, json.dumps(payload_json, ensure_ascii=False, default=str), prev_hash, curr_hash)
        )

# ============================================================================
# Command: ingest-omni
# ============================================================================

def _flatten_contact(val) -> tuple[str, str, str]:
    """
    Safely flatten a string, nested Zapier dict ({'name': ..., 'email': ...}),
    or list of dicts/strings into (raw_display, name, identifier).
    Prevents psycopg2 'can't adapt type dict' errors on TEXT columns.
    """
    if val is None:
        return "", "", ""
    if isinstance(val, list):
        parts = [_flatten_contact(v) for v in val if v is not None]
        raw = ", ".join(p[0] for p in parts if p[0])
        name = parts[0][1] if parts else ""
        ident = parts[0][2] if parts else ""
        return raw, name, ident
    if isinstance(val, dict):
        name = str(val.get("name") or val.get("full_name") or val.get("display_name") or "").strip()
        email = str(val.get("email") or val.get("address") or val.get("phone") or val.get("username") or "").strip()
        if name and email:
            raw = f"{name} <{email}>"
        else:
            raw = email or name or json.dumps(val, ensure_ascii=False)
        return raw, name or email or raw, email or name or raw
    text = str(val).strip()
    extracted = extract_email(text) or text
    name = text.split("<")[0].strip().strip('"') if "<" in text else text
    return text, name, extracted


def _normalize_wa_jid(val: str) -> str:
    """
    Normalize a WhatsApp JID (e.g. '628123456789@s.whatsapp.net' or
    '628123456789:12@s.whatsapp.net') or local phone into E.164 ('+628123456789').
    Leaves non-WA identifiers (emails, @telegram handles) unchanged.
    """
    text = str(val or "").strip()
    if not text:
        return ""
    if any(text.lower().endswith(sfx) for sfx in ("@s.whatsapp.net", "@c.us", "@lid")):
        local_part = text.split("@", 1)[0].split(":", 1)[0]
        digits = "".join(ch for ch in local_part if ch.isdigit())
        if digits.startswith("62"):
            return f"+{digits}"
        if digits.startswith("0"):
            return f"+62{digits[1:]}"
        return f"+{digits}" if digits else text
    if text.startswith("62") and text.isdigit():
        return f"+{text}"
    if text.startswith("08") and text.isdigit():
        return f"+62{text[1:]}"
    return text


def _strip_customer_prefix(name: str) -> str:
    """Strip leading 'Customer' prefix (e.g. 'Customer - Budi' -> 'Budi') if a name remains."""
    import re
    cleaned = re.sub(r"(?i)^customer\s*[-_:|/]*\s*", "", str(name or "").strip()).strip()
    return cleaned or str(name or "").strip()


def _flatten_text(val) -> str:
    """Safely convert nested dict/list/primitive payload fields to a plain string."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return str(val.get("plain") or val.get("text") or val.get("body") or val.get("html") or json.dumps(val, ensure_ascii=False))
    if isinstance(val, list):
        return "\n".join(_flatten_text(v) for v in val if v is not None)
    return str(val)


def cmd_ingest_omni(args):
    """Ingest messages from Email/WhatsApp/Telegram into scraped_messages."""
    conn = get_connection()
    messages_new = 0
    messages_skipped = 0
    sources_processed = []

    # Determine sources
    if args.source == "all":
        sources = ["email", "whatsapp", "telegram"]
    else:
        sources = [args.source]

    # Try in-memory payloads (from FastAPI/MCP service layer) first,
    # then stdin (Zapier MCP), then fixtures file.
    payloads = []
    if getattr(args, "payloads", None):
        payloads = args.payloads
    elif getattr(args, "stdin", False):
        raw_input = sys.stdin.read()
        if raw_input.strip():
            try:
                data = json.loads(raw_input)
                payloads = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                print(json.dumps({"error": "Invalid JSON on stdin"}), file=sys.stderr)
                sys.exit(1)
    elif getattr(args, "feed_file", None):
        feed_path = Path(args.feed_file)
        if not feed_path.exists():
            # Try fixtures dir
            feed_path = FIXTURES_DIR / args.feed_file
        if feed_path.exists():
            with open(feed_path, "r", encoding="utf-8") as f:
                payloads = json.load(f)
    else:
        # Default: try omnichannel_scrape_feed.json from fixtures
        default_feed = FIXTURES_DIR / "omnichannel_scrape_feed.json"
        if default_feed.exists():
            with open(default_feed, "r", encoding="utf-8") as f:
                payloads = json.load(f)

    if not payloads:
        print(json.dumps({
            "status": "no_input",
            "message": "No messages to ingest. Use --stdin, --feed-file, or place omnichannel_scrape_feed.json in fixtures."
        }, indent=2))
        conn.close()
        return

    run_id = f"ingest_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    for payload in payloads:
        source = payload.get("source", "email")
        if source not in sources and args.source != "all":
            continue

        # Compute SHA-256 of raw payload early (also used as deterministic fallback source_id)
        raw_payload_str = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        payload_hash = sha256_hash(raw_payload_str)

        source_id = str(
            payload.get("source_id")
            or payload.get("id")
            or payload.get("message_id")
            or payload.get("gmail_id")
            or payload.get("thread_id")
            or payload.get("uid")
            or f"auto_{payload_hash[:16]}"
        ).strip()

        # Check for duplicate
        with conn.cursor() as cur:
            cur.execute(
                "SELECT message_pk FROM public.scraped_messages WHERE source=%s AND source_id=%s",
                (source, source_id)
            )
            if cur.fetchone():
                messages_skipped += 1
                continue

        # Extract fields (safely flattens nested Zapier Gmail & GOWA WhatsApp objects)
        raw_from = (
            payload.get("sender")
            if payload.get("sender") is not None
            else payload.get("from")
            if payload.get("from") is not None
            else payload.get("sender_jid")
            or payload.get("chat_jid")
            or payload.get("from_email")
            or payload.get("from_name")
            or ""
        )
        sender_raw, parsed_name, parsed_ident = _flatten_contact(raw_from)
        sender_name = (
            _flatten_text(
                payload.get("sender_name")
                or payload.get("from_name")
                or payload.get("push_name")
                or payload.get("chat_name")
            )
            or parsed_name
        )
        sender_identifier = (
            _flatten_text(
                payload.get("sender_identifier")
                or payload.get("from_email")
                or payload.get("sender_jid")
                or payload.get("chat_jid")
            )
            or parsed_ident
        )
        raw_to = (
            payload.get("recipient")
            if payload.get("recipient") is not None
            else payload.get("to")
            if payload.get("to") is not None
            else payload.get("to_email") or ""
        )
        recipient, _, _ = _flatten_contact(raw_to)
        if source == "whatsapp":
            sender_identifier = _normalize_wa_jid(sender_identifier)
            recipient = _normalize_wa_jid(recipient)
            sender_name = _strip_customer_prefix(sender_name)
        subject = _flatten_text(payload.get("subject"))
        raw_body = _flatten_text(
            payload.get("body")
            or payload.get("body_plain")
            or payload.get("text")
            or payload.get("content")
            or payload.get("message")
            or payload.get("caption")
            or payload.get("snippet")
        )
        raw_date_val = (
            payload.get("date")
            or payload.get("message_date")
            or payload.get("timestamp")
        )
        message_date = None
        if isinstance(raw_date_val, (int, float)):
            try:
                ts = raw_date_val / 1000.0 if raw_date_val > 1e12 else float(raw_date_val)
                message_date = datetime.fromtimestamp(ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                message_date = None
        else:
            message_date_str = _flatten_text(raw_date_val)
            if message_date_str:
                try:
                    message_date = datetime.fromisoformat(message_date_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    message_date = None

        # Clean body
        clean = clean_body(raw_body)

        # Scan for prompt injection / profile poisoning
        injection_flags = scan_injections(raw_body)

        # PII redact
        redacted = redact_pii(clean)

        # Compute deterministic features
        features = compute_features(clean, message_date)

        # Insert into scraped_messages
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO public.scraped_messages
                   (source, source_id, payload_hash, sender_raw, sender_name,
                    sender_identifier, recipient, subject, raw_payload, clean_body,
                    redacted_body, pii_redacted, injection_flags, consent_status,
                    features_json, enrichment_status, message_date)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (source, source_id, payload_hash, sender_raw, sender_name,
                 sender_identifier, recipient, subject, Json(payload), clean,
                 redacted, True, Json(injection_flags), "granted",
                 Json(features), "pending",
                 message_date)
            )
        messages_new += 1

        if source not in sources_processed:
            sources_processed.append(source)

    # Audit
    append_audit(conn, args.owner, "ingest_omni", "scraped_messages", run_id, {
        "source": args.source,
        "trigger": args.trigger,
        "messages_new": messages_new,
        "messages_skipped": messages_skipped,
    })

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": "completed",
        "run_id": run_id,
        "sources_processed": sources_processed,
        "messages_new": messages_new,
        "messages_skipped": messages_skipped,
        "trigger": args.trigger,
    }, indent=2))

# ============================================================================
# Command: pending
# ============================================================================

def cmd_pending(args):
    """Fetch PII-redacted pending messages for Expert analysis."""
    conn = get_connection()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT message_pk, source, source_id, subject, sender_name,
                      sender_identifier, redacted_body, features_json,
                      message_date, ingested_at
               FROM public.scraped_messages
               WHERE enrichment_status = 'pending'
               ORDER BY message_date DESC NULLS LAST, ingested_at DESC
               LIMIT %s""",
            (args.limit,)
        )
        rows = cur.fetchall()

    result = []
    for row in rows:
        result.append({
            "message_pk": row["message_pk"],
            "source": row["source"],
            "source_id": row["source_id"],
            "subject": row["subject"],
            "sender_name": row["sender_name"],
            "sender_identifier": row["sender_identifier"],
            "text": row["redacted_body"],
            "features": row["features_json"] if row["features_json"] else {},
            "message_date": row["message_date"].isoformat() if row["message_date"] else None,
            "ingested_at": row["ingested_at"].isoformat() if row["ingested_at"] else None,
        })

    conn.close()
    print(json.dumps(result, indent=2, ensure_ascii=False))

# ============================================================================
# Command: write
# ============================================================================

def cmd_write(args):
    """Validate and write Expert enrichment results to scraped_messages."""
    with open(args.file, "r", encoding="utf-8") as f:
        results = json.load(f)

    if isinstance(results, dict):
        results = results.get("results", [results])

    conn = get_connection()
    written = 0
    reviewed = 0
    rejected = 0

    for item in results:
        pk = item.get("message_pk")
        if not isinstance(pk, int):
            rejected += 1
            continue

        # Validate sentiment
        sentiment = item.get("sentiment")
        if sentiment not in ("positive", "negative", "neutral", "mixed"):
            rejected += 1
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.scraped_messages SET enrichment_status='dead_letter'
                       WHERE message_pk=%s""",
                    (pk,)
                )
            append_audit(conn, args.owner, "enrichment_rejected", "scraped_messages", str(pk), {
                "reason": "invalid sentiment",
                "payload": item,
            })
            continue

        # Validate formality
        formality = item.get("formality")
        if formality not in ("formal", "neutral", "informal"):
            rejected += 1
            continue

        # Check PDP blocklist (covers v2 + v3 enrichment text fields)
        pdp_check_list = list(item.get("topics", []) or [])
        for extra_key in ("primary_jobs", "value_drivers", "pain_quotes"):
            val = item.get(extra_key)
            if isinstance(val, list):
                pdp_check_list.extend(str(x) for x in val)
        if item.get("key_moment"):
            km = item["key_moment"]
            pdp_check_list.append(str(km.get("summary", "") if isinstance(km, dict) else km))
        blocked = check_pdp_blocklist(item.get("intent", ""), pdp_check_list)
        if blocked:
            rejected += 1
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.scraped_messages SET enrichment_status='dead_letter'
                       WHERE message_pk=%s""",
                    (pk,)
                )
            append_audit(conn, args.owner, "enrichment_rejected", "scraped_messages", str(pk), {
                "reason": f"blocked sensitive attribute: {blocked}",
                "analyzer_version": args.version,
            })
            continue

        # Validate confidence
        confidence = item.get("confidence", 0)
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            rejected += 1
            continue

        needs_review = confidence < CONFIDENCE_THRESHOLD

        # Extract additional enrichment fields (v2 core + v3 intelligence cues)
        enrichment = {
            "intent": item.get("intent", ""),
            "topics": item.get("topics", []),
            "sentiment": sentiment,
            "formality": formality,
            "open_questions": item.get("open_questions", []),
            "commitments": item.get("commitments", []),
            "complaints": item.get("complaints", []),
            "resolved_complaints": item.get("resolved_complaints", []),
            "resolved_commitments": item.get("resolved_commitments", []),
            "fleet_units": item.get("fleet_units", []),
            "org_name": item.get("org_name", ""),
            "role_title": item.get("role_title", ""),
            "city": item.get("city", ""),
            "confidence": confidence,
            "analyzer_version": args.version,
            "model": args.model,
            # v3 Deep Customer Intelligence optional cues
            "channel_preference_cue": item.get("channel_preference_cue") or {},
            "language_mix": item.get("language_mix", ""),
            "style_cue": item.get("style_cue", ""),
            "primary_jobs": item.get("primary_jobs", []),
            "value_drivers": item.get("value_drivers", []),
            "regulatory_focus": item.get("regulatory_focus", ""),
            "pain_quotes": item.get("pain_quotes", []),
            "processing_route_cue": item.get("processing_route_cue", ""),
            "persuasion_cue": item.get("persuasion_cue", ""),
            "promises": item.get("promises", []),
            "key_moment": item.get("key_moment"),
        }

        # Try to resolve contact_id from sender
        contact_id = None
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT sender_identifier, sender_name FROM public.scraped_messages WHERE message_pk=%s",
                (pk,)
            )
            msg_row = cur.fetchone()
            if msg_row:
                # Check if this sender matches an existing customer_master_profiles row
                cur.execute(
                    """SELECT contact_id FROM public.customer_master_profiles
                       WHERE email=%s OR phone_wa=%s OR telegram_handle=%s LIMIT 1""",
                    (msg_row["sender_identifier"], msg_row["sender_identifier"], msg_row["sender_identifier"])
                )
                profile = cur.fetchone()
                if profile:
                    contact_id = profile["contact_id"]

        with conn.cursor() as cur:
            cur.execute(
                """UPDATE public.scraped_messages
                   SET enrichment_status=%s, enrichment_json=%s, needs_review=%s,
                       contact_id=%s
                   WHERE message_pk=%s""",
                ("review" if needs_review else "done", Json(enrichment),
                 needs_review, contact_id, pk)
            )

        append_audit(conn, args.owner, "message_enriched", "scraped_messages", str(pk), {
            "analyzer_version": args.version,
            "model": args.model,
            "confidence": confidence,
            "needs_review": needs_review,
        })

        written += 1
        reviewed += 1 if needs_review else 0

    conn.commit()
    conn.close()

    print(json.dumps({
        "analyzer_version": args.version,
        "model": args.model,
        "written": written,
        "needs_review": reviewed,
        "rejected": rejected,
    }, indent=2))

# ============================================================================
# Continuous-Conversation Aggregation Helpers (used by cmd_build_master)
# ============================================================================

import re as _re

_COMPLAINT_RESOLVED_RE = _re.compile(
    r"\b("
    r"sudah\s+(?:beres|selesai|teratasi|normal|jalan|running|ok|oke|aman|diperbaiki|diganti|sampai|masuk|diterima)"
    r"|masalah(?:nya)?\s+(?:sudah\s+)?(?:selesai|beres|teratasi)"
    r"|komplain(?:nya)?\s+(?:sudah\s+)?(?:selesai|beres|teratasi)"
    r"|unit(?:nya)?\s+(?:sudah\s+)?(?:normal|jalan|running|operasi)"
    r"|issue\s+resolved|problem\s+solved|case\s+closed|already\s+fixed"
    r")\b",
    _re.IGNORECASE,
)

_COMMITMENT_RESOLVED_RE = _re.compile(
    r"\b("
    r"(?:brosur|penawaran|quotation|quote|jadwal|dokumen|katalog|invoice|po)\s+(?:sudah\s+)?(?:diterima|masuk|saya\s+terima|kami\s+terima|dikonfirmasi|oke|ok)"
    r"|sudah\s+(?:saya|kami)\s+terima"
    r"|terima\s+kasih.*(?:penawaran|brosur|jadwal|katalog)"
    r"|received|confirmed|schedule\s+confirmed"
    r")\b",
    _re.IGNORECASE,
)


def _is_poisoning_message(msg: dict) -> bool:
    """Return True if a message was flagged as prompt-injection/profile-poisoning."""
    flags = msg.get("injection_flags") or []
    if flags:
        return True
    enrichment = msg.get("enrichment_json") or {}
    intent = str(enrichment.get("intent") or "").lower()
    if "poisoning" in intent or "injection" in intent or "exfiltration" in intent:
        return True
    return False


def _extract_display_name(msg: dict) -> str:
    """Extract a clean display name from sender_raw / sender_name / sender_identifier."""
    sender_raw = str(msg.get("sender_raw") or "").strip()
    if "<" in sender_raw:
        parsed = sender_raw.split("<")[0].strip().strip('"')
        if parsed:
            return parsed
    return str(msg.get("sender_name") or msg.get("sender_identifier") or "").strip()


def _resolve_last_non_empty(
    msgs: list[dict],
    field: str,
    existing_profile: dict | None = None,
) -> tuple[str, str]:
    """
    Edge Case 1 fix (Sticky Last-Non-Empty):
    Return (value, provenance) from the most recent non-poisoning message that
    has a non-empty value for `field`, falling back to `existing_profile[field]`.
    Prevents short follow-up replies like 'Oke siap Pak' from wiping org/role/city.
    """
    for m in reversed(msgs):
        if _is_poisoning_message(m):
            continue
        e = m.get("enrichment_json") or {}
        val = str(e.get(field) or "").strip()
        if val:
            return val, f"scraped_msg_pk_{m['message_pk']}"

    if existing_profile:
        existing_val = str(existing_profile.get(field) or "").strip()
        if existing_val:
            existing_prov = (existing_profile.get("field_provenance") or {}).get(field, "existing_profile")
            return existing_val, existing_prov

    return "", ""


def _resolve_profile_confidence(
    msgs: list[dict],
    existing_profile: dict | None = None,
) -> float:
    """
    Compute consolidated profile confidence across a contact's message history.
    Uses the highest confidence among non-poisoning messages (and existing
    verified profile) so a brief low-confidence reply ('Oke Pak') doesn't
    downgrade an already-established high-confidence profile, while a contact
    whose ONLY messages are vague (< 0.6) still triggers needs_review.
    """
    confs = []
    for m in msgs:
        if _is_poisoning_message(m):
            continue
        e = m.get("enrichment_json") or {}
        c = e.get("confidence")
        if isinstance(c, (int, float)):
            confs.append(float(c))

    if existing_profile and existing_profile.get("verification_status") == "verified":
        ec = existing_profile.get("confidence")
        if isinstance(ec, (int, float)):
            confs.append(float(ec))

    if confs:
        return max(confs)

    # Fallback if all messages were flagged as poisoning
    latest_e = (msgs[-1].get("enrichment_json") or {}) if msgs else {}
    return float(latest_e.get("confidence", 0.5))


def group_messages_by_contact(
    messages: list[dict],
    ident_to_contact: dict[str, str] | None = None,
) -> dict[str, list[dict]]:
    """
    Edge Case 2 fix (Cross-Channel Grouping):
    Group chronologically ordered messages by canonical `contact_id` instead of
    raw `sender_identifier`, so Email + WhatsApp + Telegram messages from the
    same person merge into one unified master profile.
    """
    ident_map = dict(ident_to_contact or {})
    groups: dict[str, list[dict]] = {}

    for msg in messages:
        ident = str(msg.get("sender_identifier") or "").strip().lower()
        contact_id = msg.get("contact_id") or (ident_map.get(ident) if ident else None)

        if not contact_id:
            # Also check if phone/email inside clean_body links to a known contact
            body = msg.get("clean_body") or ""
            if not _is_poisoning_message(msg):
                body_email = (extract_email(body) or "").lower()
                body_phone = (extract_phone_e164(body) or "").lower()
                if body_email and body_email in ident_map:
                    contact_id = ident_map[body_email]
                elif body_phone and body_phone in ident_map:
                    contact_id = ident_map[body_phone]

        if not contact_id:
            full_name = _extract_display_name(msg)
            contact_id = generate_contact_id(full_name)

        # Register clean identifiers for subsequent messages in the same batch
        if not _is_poisoning_message(msg):
            if ident:
                ident_map.setdefault(ident, contact_id)
            body = msg.get("clean_body") or ""
            body_email = (extract_email(body) or "").lower()
            body_phone = (extract_phone_e164(body) or "").lower()
            if body_email:
                ident_map.setdefault(body_email, contact_id)
            if body_phone and not is_landline(body_phone):
                ident_map.setdefault(body_phone, contact_id)

        groups.setdefault(contact_id, []).append(msg)

    return groups


def aggregate_complaints_and_commitments(
    msgs: list[dict],
) -> tuple[list[dict], list[dict]]:
    """
    Edge Case 3 fix (Lifecycle & Resolution Tracking):
    Chronologically track complaints and commitments across a conversation:
    - Deduplicates repeated complaints/commitments by normalized text.
    - Auto-resolves prior open items when a subsequent message explicitly lists
      `resolved_complaints` / `resolved_commitments` OR contains clear
      resolution cues (matching fleet unit if mentioned, else all prior items).
    - Returns only still-open (active) complaints and commitments.
    """
    complaints_items: list[dict] = []
    commitments_items: list[dict] = []
    seen_complaints: set[str] = set()
    seen_commitments: set[str] = set()

    def _norm(text: str) -> str:
        return " ".join(text.lower().split())

    for m in msgs:
        if _is_poisoning_message(m):
            continue
        pk = m.get("message_pk")
        e = m.get("enrichment_json") or {}
        body = m.get("clean_body") or ""
        sentiment = str(e.get("sentiment") or "").lower()
        msg_units = set(extract_fleet_units(body)) | {
            str(u).upper() for u in (e.get("fleet_units") or [])
        }

        # 1. Explicit LLM resolution lists (if present)
        for resolved_text in (e.get("resolved_complaints") or []):
            rt = _norm(str(resolved_text))
            for item in complaints_items:
                if item["status"] == "open" and (rt in _norm(item["text"]) or _norm(item["text"]) in rt):
                    item["status"] = "resolved"
                    item["resolved_by_message_pk"] = pk

        for resolved_text in (e.get("resolved_commitments") or []):
            rt = _norm(str(resolved_text))
            for item in commitments_items:
                if item["status"] == "open" and (rt in _norm(item["text"]) or _norm(item["text"]) in rt):
                    item["status"] = "resolved"
                    item["resolved_by_message_pk"] = pk

        # 2. Deterministic resolution cues in a later message
        new_complaints = e.get("complaints") or []
        if complaints_items and not new_complaints and sentiment in ("positive", "neutral", ""):
            if _COMPLAINT_RESOLVED_RE.search(body):
                for item in complaints_items:
                    if item["status"] != "open":
                        continue
                    item_units = set(extract_fleet_units(item["text"]))
                    # Close if same unit mentioned, or if resolution message is general (no specific unit)
                    if not msg_units or not item_units or (msg_units & item_units):
                        item["status"] = "resolved"
                        item["resolved_by_message_pk"] = pk

        if commitments_items and sentiment in ("positive", "neutral", ""):
            if _COMMITMENT_RESOLVED_RE.search(body):
                for item in commitments_items:
                    if item["status"] != "open":
                        continue
                    item_units = set(extract_fleet_units(item["text"]))
                    if not msg_units or not item_units or (msg_units & item_units):
                        item["status"] = "resolved"
                        item["resolved_by_message_pk"] = pk

        # 3. Append new open complaints & commitments (deduplicated)
        for c in new_complaints:
            text = str(c).strip()
            key = _norm(text)
            if text and key not in seen_complaints:
                seen_complaints.add(key)
                complaints_items.append({
                    "text": text,
                    "source_message_pk": pk,
                    "status": "open",
                })

        for c in (e.get("commitments") or []):
            text = str(c).strip()
            key = _norm(text)
            if text and key not in seen_commitments:
                seen_commitments.add(key)
                commitments_items.append({
                    "text": text,
                    "source_message_pk": pk,
                    "status": "open",
                })

    open_complaints = [c for c in complaints_items if c["status"] == "open"]
    open_commitments = [c for c in commitments_items if c["status"] == "open"]
    return open_complaints, open_commitments


# ============================================================================
# Deep Customer Intelligence Builders (v3: 5 JSONB + 2 Scalars + agent_brief)
# ============================================================================

VALID_CHARACTER_STYLES = ("Driver", "Analytical", "Amiable", "Expressive", "unknown")
VALID_CHURN_LEVELS = ("low", "medium", "high")
_MAX_PAIN_QUOTES = 10
_MAX_KEY_MOMENTS = 20
_MAX_OPEN_PROMISES = 20


def _deep_merge_preserving_manual(
    ai_dict: dict,
    existing_dict: dict,
    provenance: dict,
    prefix: str,
) -> dict:
    """
    Merge AI-computed dict with existing dict while strictly enforcing TR-08:
    any key (or nested key) marked 'user_confirmed' in field_provenance is NEVER
    overwritten by AI aggregation.
    """
    merged = dict(ai_dict)
    for k, existing_val in (existing_dict or {}).items():
        path = f"{prefix}.{k}"
        if provenance.get(path) == "user_confirmed":
            merged[k] = existing_val
        elif isinstance(existing_val, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge_preserving_manual(merged[k], existing_val, provenance, path)
        elif k not in merged and existing_val not in (None, "", [], {}):
            merged[k] = existing_val
    return merged


def _compute_peak_hours(msgs: list[dict], tz_label: str) -> list[str]:
    """Deterministically infer top 2 active local-hour windows from message timestamps/features."""
    hour_buckets: dict[str, int] = {}
    for m in msgs:
        feats = m.get("features_json") or {}
        hr = feats.get("hour_of_day")
        if hr is None and m.get("message_date") and hasattr(m["message_date"], "hour"):
            hr = m["message_date"].hour
        if isinstance(hr, int) and 0 <= hr <= 23:
            start = (hr // 2) * 2
            end = (start + 2) % 24
            bucket = f"{start:02d}:00-{end:02d}:00 {tz_label}"
            hour_buckets[bucket] = hour_buckets.get(bucket, 0) + 1
    ranked = sorted(hour_buckets.items(), key=lambda kv: (-kv[1], kv[0]))
    return [b for b, _ in ranked[:2]]


def _compute_sentiment_trend(clean_msgs: list[dict]) -> dict:
    """Compute recent sentiment sequence (last 6 messages) and trend direction."""
    seq = []
    for m in clean_msgs[-6:]:
        s = (m.get("enrichment_json") or {}).get("sentiment")
        if s in ("positive", "negative", "neutral", "mixed"):
            seq.append(s)
    score_map = {"positive": 1, "neutral": 0, "mixed": -0.25, "negative": -1}
    direction = "stable"
    if len(seq) >= 2:
        half = max(1, len(seq) // 2)
        early = sum(score_map[s] for s in seq[:half]) / half
        recent = sum(score_map[s] for s in seq[half:]) / len(seq[half:])
        if recent - early >= 0.4:
            direction = "improving"
        elif early - recent >= 0.4:
            direction = "declining"
    elif seq == ["negative"]:
        direction = "declining"
    return {"recent_sequence": seq, "direction": direction}


def build_intelligence_dimensions(
    clean_msgs: list[dict],
    existing: dict | None,
    full_name: str,
    salutation: str,
    tz_label: str,
    dominant_formality: str,
    complaints: list[dict],
    commitments: list[dict],
    last_msg_date: datetime | None,
    now: datetime,
) -> tuple[dict, dict, dict, dict, dict, str, str]:
    """
    Build the 5 v3 JSONB dimensions + 2 scalar filters (character_style, churn_risk_level)
    combining deterministic features, AI v3 cues, and existing user_confirmed manual overrides (TR-08).
    """
    existing = existing or {}
    prov = existing.get("field_provenance") or {}

    # --- 1. Communication Preferences ---
    channel_by_topic: dict[str, str] = {}
    lang_mix_counts: dict[str, int] = {}
    emoji_total = 0
    word_counts: list[int] = []

    for m in clean_msgs:
        feats = m.get("features_json") or {}
        emoji_total += int(feats.get("emoji_count") or 0)
        wc = feats.get("word_count")
        if isinstance(wc, int) and wc > 0:
            word_counts.append(wc)
        e = m.get("enrichment_json") or {}
        cpc = e.get("channel_preference_cue")
        if isinstance(cpc, dict):
            for topic, ch in cpc.items():
                if topic and ch:
                    channel_by_topic[str(topic).strip()] = str(ch).strip().lower()
        lm = str(e.get("language_mix") or "").strip()
        if lm:
            lang_mix_counts[lm] = lang_mix_counts.get(lm, 0) + 1

    avg_words = (sum(word_counts) / len(word_counts)) if word_counts else 0
    preferred_length = "detailed" if avg_words >= 45 else ("short_bullets" if avg_words > 0 else "short_bullets")
    first_name = full_name.split()[0] if full_name else ""
    prefix_word = "Ibu" if salutation == "formal_ibu" else "Pak"
    addressing = f"{prefix_word} {first_name}".strip() if first_name else prefix_word

    ai_comm_prefs = {
        "channel_by_topic": channel_by_topic,
        "dnd_windows": [
            f"Fri 11:30-13:00 {tz_label}",
            f"17:00-08:00 {tz_label}",
            "Sat-Sun",
        ],
        "peak_responsive_hours_local": _compute_peak_hours(clean_msgs, tz_label),
        "language_register": {
            "addressing": addressing,
            "formality": dominant_formality,
            "language_mix": max(lang_mix_counts, key=lang_mix_counts.get) if lang_mix_counts else "id",
            "uses_emoji": emoji_total > 0,
        },
        "preferred_length": preferred_length,
        "typical_reply_hours": (
            round(existing["avg_response_delay_sec"] / 3600.0, 2)
            if existing.get("avg_response_delay_sec")
            else None
        ),
    }
    communication_prefs = _deep_merge_preserving_manual(
        ai_comm_prefs, existing.get("communication_prefs") or {}, prov, "communication_prefs"
    )

    # --- 2. Character Profile ---
    style_counts: dict[str, int] = {}
    complaint_topics: list[str] = []
    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        sc = str(e.get("style_cue") or "").strip().title()
        if sc in ("Driver", "Analytical", "Amiable", "Expressive"):
            style_counts[sc] = style_counts.get(sc, 0) + 1
        if e.get("complaints"):
            for t in (e.get("topics") or []):
                t_norm = str(t).strip().lower()
                if t_norm and t_norm not in complaint_topics:
                    complaint_topics.append(t_norm)

    # Guardrail: only assign non-unknown AI character_style once >= 3 clean messages exist
    ranked_styles = sorted(style_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    inferred_style = ranked_styles[0][0] if (len(clean_msgs) >= 3 and ranked_styles) else "unknown"
    secondary_style = ranked_styles[1][0] if (len(clean_msgs) >= 3 and len(ranked_styles) > 1) else ""
    prelim_note = (
        f"Preliminary signal ({ranked_styles[0][0]}) from {len(clean_msgs)} message(s); needs >=3 messages or manual confirmation."
        if (inferred_style == "unknown" and ranked_styles)
        else (f"Inferred from {len(clean_msgs)} messages." if inferred_style != "unknown" else "")
    )

    ai_character = {
        "style": inferred_style,
        "secondary_style": secondary_style,
        "style_evidence": prelim_note,
        "complaint_patterns": {
            "frequent_topics": complaint_topics[:8],
            "validity_rate": "",
            "proven_resolution_playbook": "",
        },
    }
    character_profile = _deep_merge_preserving_manual(
        ai_character, existing.get("character_profile") or {}, prov, "character_profile"
    )
    character_style = str(character_profile.get("style") or "unknown")
    if character_style not in VALID_CHARACTER_STYLES:
        character_style = "unknown"
        character_profile["style"] = "unknown"

    # --- 3. Motivation & Pain ---
    primary_jobs: list[str] = []
    value_drivers: list[str] = []
    reg_focus_counts: dict[str, int] = {}
    pain_quotes: list[dict] = []
    seen_quotes: set[str] = set()

    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        pk = m.get("message_pk")
        mdate = m.get("message_date").date().isoformat() if hasattr(m.get("message_date"), "date") else ""
        for j in (e.get("primary_jobs") or []):
            js = str(j).strip()
            if js and js not in primary_jobs:
                primary_jobs.append(js)
        for vd in (e.get("value_drivers") or []):
            vds = str(vd).strip().lower()
            if vds and vds not in value_drivers:
                value_drivers.append(vds)
        rf = str(e.get("regulatory_focus") or "").strip().lower()
        if rf in ("promotion", "prevention", "balanced"):
            reg_focus_counts[rf] = reg_focus_counts.get(rf, 0) + 1
        for pq in (e.get("pain_quotes") or []):
            q_text = str(pq.get("quote") if isinstance(pq, dict) else pq).strip()
            q_key = q_text.lower()
            if q_text and q_key not in seen_quotes:
                seen_quotes.add(q_key)
                pain_quotes.append({"quote": q_text[:300], "source_msg_pk": pk, "date": mdate})

    reg_focus = max(reg_focus_counts, key=reg_focus_counts.get) if reg_focus_counts else ""
    ai_motivation = {
        "primary_jobs": primary_jobs[:8],
        "value_drivers": value_drivers[:8],
        "regulatory_focus": reg_focus,
        "verbatim_pain_quotes": pain_quotes[-_MAX_PAIN_QUOTES:],
    }
    motivation_and_pain = _deep_merge_preserving_manual(
        ai_motivation, existing.get("motivation_and_pain") or {}, prov, "motivation_and_pain"
    )

    # --- 4. Persuasion Profile ---
    route_counts: dict[str, int] = {}
    ai_triggers: list[dict] = []
    seen_triggers: set[str] = set()
    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        pr = str(e.get("processing_route_cue") or "").strip().lower()
        if pr in ("central", "peripheral"):
            route_counts[pr] = route_counts.get(pr, 0) + 1
        pc = str(e.get("persuasion_cue") or "").strip().lower()
        if pc in ("social_proof", "authority", "scarcity", "reciprocity") and pc not in seen_triggers:
            seen_triggers.add(pc)
            ai_triggers.append({"trigger": pc, "detail": "Signal observed in messages", "source": "ai_chat"})

    ai_persuasion = {
        "proven_triggers": ai_triggers,
        "processing_route": max(route_counts, key=route_counts.get) if route_counts else "",
    }
    persuasion_profile = _deep_merge_preserving_manual(
        ai_persuasion, existing.get("persuasion_profile") or {}, prov, "persuasion_profile"
    )

    # --- 5. Relationship Health ---
    open_promises: list[dict] = []
    seen_promise_keys: set[str] = set()
    today_str = now.date().isoformat()

    # Keep any manually entered/confirmed promises from existing profile first
    existing_health = existing.get("relationship_health") or {}
    for ep in (existing_health.get("open_promises") or []):
        if isinstance(ep, dict) and ep.get("status") != "resolved":
            item_text = str(ep.get("item") or "").strip()
            if item_text:
                p_copy = dict(ep)
                due = str(p_copy.get("due_date") or "")
                if due and due < today_str and p_copy.get("status") == "open":
                    p_copy["status"] = "overdue"
                open_promises.append(p_copy)
                seen_promise_keys.add(item_text.lower())

    # Add structured v3 promises from messages
    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        pk = m.get("message_pk")
        for pr_item in (e.get("promises") or []):
            if not isinstance(pr_item, dict):
                continue
            item_text = str(pr_item.get("item") or "").strip()
            if not item_text or item_text.lower() in seen_promise_keys:
                continue
            owner_side = str(pr_item.get("owner") or "us").strip().lower()
            if owner_side not in ("us", "customer"):
                owner_side = "us"
            due = str(pr_item.get("due_date") or "").strip()
            status = "overdue" if (due and due < today_str) else "open"
            seen_promise_keys.add(item_text.lower())
            open_promises.append({
                "owner": owner_side,
                "item": item_text,
                "due_date": due,
                "status": status,
                "source_msg_pk": pk,
            })

    # Backfill from v2 open_commitments if not already represented
    for c in commitments:
        c_text = str(c.get("text") if isinstance(c, dict) else c).strip()
        if c_text and c_text.lower() not in seen_promise_keys:
            seen_promise_keys.add(c_text.lower())
            open_promises.append({
                "owner": "us",
                "item": c_text,
                "due_date": "",
                "status": "open",
                "source_msg_pk": c.get("source_message_pk") if isinstance(c, dict) else None,
            })

    # Key moments (merge manual + AI chat)
    key_moments: list[dict] = []
    seen_moments: set[str] = set()
    for em in (existing_health.get("key_moments") or []):
        if isinstance(em, dict) and em.get("summary"):
            s_key = str(em["summary"]).strip().lower()
            if s_key not in seen_moments:
                seen_moments.add(s_key)
                key_moments.append(dict(em))
    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        km = e.get("key_moment")
        if isinstance(km, dict) and km.get("summary"):
            s_key = str(km["summary"]).strip().lower()
            if s_key not in seen_moments:
                seen_moments.add(s_key)
                mdate = m.get("message_date").date().isoformat() if hasattr(m.get("message_date"), "date") else ""
                key_moments.append({
                    "type": str(km.get("type") or "incident").lower(),
                    "summary": str(km["summary"]).strip(),
                    "date": str(km.get("date") or mdate),
                    "source": "ai_chat",
                })

    sentiment_trend = _compute_sentiment_trend(clean_msgs)
    days_since_last = None
    if last_msg_date and hasattr(last_msg_date, "timestamp"):
        days_since_last = max(0, int((now.timestamp() - last_msg_date.timestamp()) // 86400))

    # Hybrid churn risk calculation
    overdue_us = sum(1 for p in open_promises if p.get("owner") == "us" and p.get("status") == "overdue")
    reasons = []
    score = 0
    if sentiment_trend["direction"] == "declining":
        score += 2
        reasons.append("sentimen menurun")
    if len(complaints) >= 2:
        score += 2
        reasons.append(f"{len(complaints)} komplain aktif")
    elif len(complaints) == 1:
        score += 1
        reasons.append("1 komplain aktif")
    if overdue_us > 0:
        score += 2
        reasons.append(f"{overdue_us} janji kita overdue")
    if days_since_last is not None and days_since_last >= 30:
        score += 1
        reasons.append(f"{days_since_last} hari tanpa kontak")

    churn_level = "high" if score >= 4 else ("medium" if score >= 2 else "low")
    ai_health = {
        "open_promises": open_promises[:_MAX_OPEN_PROMISES],
        "sentiment_trend": sentiment_trend,
        "key_moments": key_moments[-_MAX_KEY_MOMENTS:],
        "days_since_last_contact": days_since_last,
        "churn_risk": {
            "level": churn_level,
            "reason": ", ".join(reasons) if reasons else "Relasi stabil.",
        },
    }
    relationship_health = _deep_merge_preserving_manual(
        ai_health, existing_health, prov, "relationship_health"
    )
    churn_risk_level = str((relationship_health.get("churn_risk") or {}).get("level") or churn_level).lower()
    if churn_risk_level not in VALID_CHURN_LEVELS:
        churn_risk_level = churn_level

    return (
        communication_prefs,
        character_profile,
        motivation_and_pain,
        persuasion_profile,
        relationship_health,
        character_style,
        churn_risk_level,
    )


def compile_agent_brief(master_data: dict) -> str:
    """
    Compile a comprehensive, plain-language executive brief for Agent #2
    (Meeting & Ticket Agent) from ALL relevant master profile columns:
    identity/tier/city, fleet units, active complaints, channel & DND/timing
    preferences, character & resolution playbook, motivation/pain, persuasion
    triggers, two-way open promises, key moments, and verification warnings.
    Returns empty string for peer contacts (TR-10).
    """
    if master_data.get("category") == "peer":
        return ""

    name = master_data.get("full_name") or master_data.get("contact_id", "")
    role = master_data.get("role_title") or ""
    org = master_data.get("org_name") or ""
    tier = master_data.get("account_tier") or ""
    city = master_data.get("city") or ""
    tz_label = master_data.get("tz_label") or "WIB"
    comm = master_data.get("communication_prefs") or {}
    char = master_data.get("character_profile") or {}
    motiv = master_data.get("motivation_and_pain") or {}
    pers = master_data.get("persuasion_profile") or {}
    health = master_data.get("relationship_health") or {}

    header_parts = [p for p in (role, org, city, tz_label) if p]
    tier_tag = f" [{tier}]" if tier else ""
    lines = [f"Brief Customer — {name}{tier_tag}" + (f" ({', '.join(header_parts)})" if header_parts else "")]

    # Verification / review warning for Agent #2
    ver_status = master_data.get("verification_status") or "verified"
    if master_data.get("needs_review") or ver_status != "verified":
        conf = master_data.get("confidence")
        conf_str = f", confidence={conf:.2f}" if isinstance(conf, (int, float)) else ""
        lines.append(f"PERHATIAN: Profil berstatus '{ver_status}'{conf_str} — verifikasi fakta penting sebelum kirim pesan.")

    # Character, regulatory focus, sentiment & churn risk (plain-language explanations)
    style = char.get("style") or "unknown"
    reg_focus = motiv.get("regulatory_focus") or ""
    reg_explain = {
        "prevention": "prevention (tekankan mitigasi risiko/downtime)",
        "promotion": "promotion (tekankan peningkatan produktivitas/keuntungan)",
        "balanced": "balanced (seimbang antara mitigasi risiko & peluang)",
    }.get(reg_focus, reg_focus)
    trend = (health.get("sentiment_trend") or {}).get("direction") or "stable"
    churn = (health.get("churn_risk") or {}).get("level") or "low"
    churn_reason = (health.get("churn_risk") or {}).get("reason") or ""

    summary_bits = []
    if style != "unknown":
        sec = f"-{char['secondary_style']}" if char.get("secondary_style") else ""
        summary_bits.append(f"Karakter: {style}{sec}")
    if reg_explain:
        summary_bits.append(f"Fokus motivasi: {reg_explain}")
    summary_bits.append(f"Sentimen: {trend} | Risiko churn: {churn}" + (f" ({churn_reason})" if churn_reason else ""))
    lines.append(" · ".join(summary_bits) + ".")

    # Business context: fleet units, jobs, value drivers, activity
    fleet = master_data.get("fleet_units") or []
    jobs = motiv.get("primary_jobs") or []
    drivers = motiv.get("value_drivers") or []
    active_ch = master_data.get("active_channels") or []
    msg_30d = master_data.get("total_messages_30d") or 0
    days_last = health.get("days_since_last_contact")

    biz_bits = []
    if fleet:
        biz_bits.append(f"Armada: {', '.join(fleet)}")
    if jobs:
        biz_bits.append(f"Prioritas bisnis: {'; '.join(jobs[:3])}")
    if drivers:
        biz_bits.append(f"Value driver: {', '.join(drivers[:4])}")
    if active_ch or msg_30d:
        act_str = f"{msg_30d} pesan/30h via {', '.join(active_ch) or 'n/a'}"
        if days_last is not None:
            act_str += f" (kontak terakhir {days_last} hari lalu)"
        biz_bits.append(f"Aktivitas: {act_str}")
    if biz_bits:
        lines.append("Konteks Bisnis: " + " | ".join(biz_bits) + ".")

    # Communication guidance (channel, register, length, peak hours, DND)
    reg = comm.get("language_register") or {}
    addr = reg.get("addressing") or name
    formality = reg.get("formality") or master_data.get("dominant_formality") or "formal"
    lang_mix = reg.get("language_mix") or "id"
    length_pref = comm.get("preferred_length") or "short_bullets"
    emoji_txt = "boleh emoji" if reg.get("uses_emoji") else "tanpa emoji"
    peak = ", ".join(comm.get("peak_responsive_hours_local") or []) or master_data.get("best_contact_window", "")
    dnd = ", ".join(comm.get("dnd_windows") or [])
    ch_map = comm.get("channel_by_topic") or {}
    ch_txt = ", ".join(f"{k}->{v}" for k, v in ch_map.items()) if ch_map else (master_data.get("preferred_channel") or "whatsapp")
    reply_hrs = comm.get("typical_reply_hours")
    reply_txt = f"; pola balas ~{reply_hrs} jam" if reply_hrs else ""
    dnd_txt = f"; jam larangan kontak: {dnd}" if dnd else ""
    lines.append(
        f"Komunikasi: sapa '{addr}', gaya {formality} ({lang_mix}, {length_pref}, {emoji_txt}); "
        f"channel: {ch_txt}; waktu responsif: {peak}{dnd_txt}{reply_txt}."
    )

    # Active complaints + resolution playbook
    open_complaints = master_data.get("open_complaints") or []
    if open_complaints:
        comp_texts = [
            str(c.get("text") if isinstance(c, dict) else c).strip()
            for c in open_complaints[:3]
        ]
        comp_texts = [t for t in comp_texts if t]
        if comp_texts:
            lines.append("Komplain aktif: " + "; ".join(comp_texts) + ".")

    playbook = ((char.get("complaint_patterns") or {}).get("proven_resolution_playbook") or "").strip()
    if playbook:
        lines.append(f"Playbook penyelesaian terbukti: {playbook}")

    # Persuasion & pain quote
    route = pers.get("processing_route") or ""
    route_explain = {
        "central": "central (utamakan data, spek teknis, & angka detail)",
        "peripheral": "peripheral (utamakan kepercayaan, reputasi, & hubungan personal)",
    }.get(route, route)
    triggers = [t.get("trigger") for t in (pers.get("proven_triggers") or []) if isinstance(t, dict) and t.get("trigger")]
    if route_explain or triggers:
        lines.append(
            f"Persuasi: jalur {route_explain or 'mixed'}"
            + (f"; pemicu efektif: {', '.join(triggers)}." if triggers else ".")
        )

    pain_quotes = motiv.get("verbatim_pain_quotes") or []
    if pain_quotes:
        latest_q = pain_quotes[-1]
        q_txt = latest_q.get("quote", "") if isinstance(latest_q, dict) else str(latest_q)
        if q_txt:
            lines.append(f'Kutipan pain terbaru: "{q_txt[:180]}"')

    # Key moments (latest 2)
    moments = health.get("key_moments") or []
    if moments:
        m_items = [
            f"[{m.get('type', 'event')}] {m.get('summary', '')}"
            for m in moments[-2:]
            if isinstance(m, dict) and m.get("summary")
        ]
        if m_items:
            lines.append("Momen penting: " + "; ".join(m_items) + ".")

    # Open promises (two-way)
    promises = [p for p in (health.get("open_promises") or []) if isinstance(p, dict) and p.get("status") != "resolved"]
    if promises:
        p_lines = []
        for p in promises[:5]:
            tag = f"[{str(p.get('status', 'open')).upper()} — {'Kita' if p.get('owner') == 'us' else 'Customer'}]"
            due = f" (due {p['due_date']})" if p.get("due_date") else ""
            p_lines.append(f"- {tag} {p.get('item', '')}{due}")
        lines.append("Janji terbuka:\n" + "\n".join(p_lines))

    return "\n".join(lines)


def apply_manual_enrichment(
    existing: dict,
    updates: dict,
    owner: str = "owner_rifat",
) -> tuple[dict, dict, str]:
    """
    Pure TR-08 / BR-17 / TR-10 compliant manual enrichment helper.
    Merges manual updates into the 5 JSONB dimensions, marks each touched path as
    'user_confirmed' in field_provenance, validates UU PDP blocklist, and recompiles agent_brief.
    """
    # BR-17 PDP check on all string values inside updates
    flat_strings: list[str] = []

    def _collect_strings(obj):
        if isinstance(obj, str):
            flat_strings.append(obj)
        elif isinstance(obj, list):
            for x in obj:
                _collect_strings(x)
        elif isinstance(obj, dict):
            for v in obj.values():
                _collect_strings(v)

    _collect_strings(updates)
    blocked = check_pdp_blocklist("", flat_strings)
    if blocked:
        raise ValueError(f"BR-17 UU PDP violation: blocked sensitive attribute '{blocked}'")

    allowed_domains = (
        "communication_prefs",
        "character_profile",
        "motivation_and_pain",
        "persuasion_profile",
        "relationship_health",
    )
    merged_profile = dict(existing)
    prov = dict(existing.get("field_provenance") or {})

    def _merge_and_tag(base: dict, patch: dict, prefix: str) -> dict:
        out = dict(base or {})
        for k, v in (patch or {}).items():
            path = f"{prefix}.{k}"
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = _merge_and_tag(out[k], v, path)
            else:
                out[k] = v
                prov[path] = "user_confirmed"
        return out

    updated_cols: dict = {}
    for domain in allowed_domains:
        if domain in updates and isinstance(updates[domain], dict):
            new_val = _merge_and_tag(existing.get(domain) or {}, updates[domain], domain)
            merged_profile[domain] = new_val
            updated_cols[domain] = new_val

    # Sync scalar filter columns from JSONB or direct override
    char_style = str(
        updates.get("character_style")
        or (merged_profile.get("character_profile") or {}).get("style")
        or existing.get("character_style")
        or "unknown"
    )
    if char_style in VALID_CHARACTER_STYLES:
        merged_profile["character_style"] = char_style
        updated_cols["character_style"] = char_style
        if "character_style" in updates:
            prov["character_profile.style"] = "user_confirmed"
            cp = dict(merged_profile.get("character_profile") or {})
            cp["style"] = char_style
            merged_profile["character_profile"] = cp
            updated_cols["character_profile"] = cp

    churn_lvl = str(
        updates.get("churn_risk_level")
        or ((merged_profile.get("relationship_health") or {}).get("churn_risk") or {}).get("level")
        or existing.get("churn_risk_level")
        or "low"
    ).lower()
    if churn_lvl in VALID_CHURN_LEVELS:
        merged_profile["churn_risk_level"] = churn_lvl
        updated_cols["churn_risk_level"] = churn_lvl
        if "churn_risk_level" in updates:
            prov["relationship_health.churn_risk"] = "user_confirmed"
            rh = dict(merged_profile.get("relationship_health") or {})
            cr = dict(rh.get("churn_risk") or {})
            cr["level"] = churn_lvl
            rh["churn_risk"] = cr
            merged_profile["relationship_health"] = rh
            updated_cols["relationship_health"] = rh

    merged_profile = apply_peer_privacy(merged_profile)
    brief = compile_agent_brief(merged_profile)
    updated_cols["agent_brief"] = brief
    updated_cols["field_provenance"] = prov
    return updated_cols, prov, brief


def build_master_profile_data(
    contact_id: str,
    msgs: list[dict],
    existing: dict | None = None,
    now_utc: datetime | None = None,
) -> tuple[dict, list[dict]]:
    """
    Pure builder for a single contact's consolidated master profile + staging rows.
    Handles all 3 continuous-conversation edge cases:
      1. Sticky last-non-empty resolution for org_name, role_title, city, confidence
      2. Cross-channel aggregation across email/whatsapp/telegram
      3. Complaint & commitment deduplication + auto-resolution
    """
    clean_msgs = [m for m in msgs if not _is_poisoning_message(m)]
    latest = clean_msgs[-1] if clean_msgs else msgs[-1]

    # Identity: prefer most recent clean display name, fallback to existing
    full_name = _extract_display_name(latest) or (existing.get("full_name") if existing else "") or contact_id
    full_name_prov = f"scraped_msg_pk_{latest['message_pk']}"

    # Sticky last-non-empty for org_name, role_title, city (Edge Case 1)
    org_name, org_prov = _resolve_last_non_empty(msgs, "org_name", existing)
    role_title, role_prov = _resolve_last_non_empty(msgs, "role_title", existing)
    city, city_prov = _resolve_last_non_empty(msgs, "city", existing)

    master_id = (
        existing["master_id"]
        if existing and existing.get("master_id")
        else generate_master_id(contact_id, org_name)
    )

    # Resolve timezone from sticky city
    tz, tz_label = resolve_timezone(city)

    # Cross-channel contact extraction (Edge Case 2) + TR-08 poisoning detection
    phone_wa = ""
    phone_prov = ""
    email_addr = ""
    email_prov = ""
    telegram_handle = ""
    telegram_prov = ""

    # Track candidate values from every message (including poisoning ones, for staging)
    proposed_emails: list[tuple[str, dict]] = []
    proposed_phones: list[tuple[str, dict]] = []

    for m in msgs:
        src = str(m.get("source") or "").lower()
        ident = str(m.get("sender_identifier") or "").strip()
        body = m.get("clean_body") or ""
        is_poison = _is_poisoning_message(m)

        # Candidate email
        m_email = ""
        if src == "email" and "@" in ident:
            m_email = ident
        if not m_email:
            m_email = extract_email(body) or ""
        else:
            # Also check if body proposes a DIFFERENT email (e.g. poisoning in email body)
            body_email = extract_email(body) or ""
            if body_email and body_email.lower() != m_email.lower():
                proposed_emails.append((body_email, m))

        if m_email:
            if not is_poison and not email_addr:
                email_addr = m_email
                email_prov = f"scraped_msg_pk_{m['message_pk']}"
            elif m_email.lower() != (email_addr or "").lower():
                proposed_emails.append((m_email, m))

        # Candidate phone_wa (never accept landline)
        m_phone = ""
        if src == "whatsapp" and ident:
            m_phone = extract_phone_e164(ident) or ""
        if not m_phone:
            m_phone = extract_phone_e164(body) or ""
        else:
            body_phone = extract_phone_e164(body) or ""
            if body_phone and not is_landline(body_phone) and body_phone != m_phone:
                proposed_phones.append((body_phone, m))

        if m_phone and not is_landline(m_phone):
            if not is_poison and not phone_wa:
                phone_wa = m_phone
                phone_prov = f"scraped_msg_pk_{m['message_pk']}"
            elif m_phone != phone_wa:
                proposed_phones.append((m_phone, m))

        # Candidate telegram_handle
        if src == "telegram" and ident.startswith("@") and not is_poison and not telegram_handle:
            telegram_handle = ident
            telegram_prov = f"scraped_msg_pk_{m['message_pk']}"

    # Inherit verified channels from existing profile if not present in this batch
    if existing:
        if not email_addr and existing.get("email"):
            email_addr = existing["email"]
            email_prov = (existing.get("field_provenance") or {}).get("email", "existing_profile")
        if not phone_wa and existing.get("phone_wa"):
            phone_wa = existing["phone_wa"]
            phone_prov = (existing.get("field_provenance") or {}).get("phone_wa", "existing_profile")
        if not telegram_handle and existing.get("telegram_handle"):
            telegram_handle = existing["telegram_handle"]
            telegram_prov = (existing.get("field_provenance") or {}).get("telegram_handle", "existing_profile")

    # Collect TR-08 profile poisoning staging rows (never silently overwrite verified email/phone)
    pending_staging_rows: list[dict] = []
    seen_staging_hashes: set[str] = set()

    def _add_staging(row: dict) -> None:
        h = row["approval_hash"]
        if h not in seen_staging_hashes:
            seen_staging_hashes.add(h)
            pending_staging_rows.append(row)

    verified_email = (existing.get("email") if existing else "") or email_addr
    verified_phone = (existing.get("phone_wa") if existing else "") or phone_wa

    if existing and email_addr and existing.get("email") and email_addr.lower() != existing["email"].lower():
        proposed_emails.insert(0, (email_addr, latest))
        email_addr = existing["email"]
        email_prov = (existing.get("field_provenance") or {}).get("email", "existing_profile")

    if existing and phone_wa and existing.get("phone_wa") and phone_wa != existing["phone_wa"]:
        proposed_phones.insert(0, (phone_wa, latest))
        phone_wa = existing["phone_wa"]
        phone_prov = (existing.get("field_provenance") or {}).get("phone_wa", "existing_profile")

    for prop_email, prop_msg in proposed_emails:
        if verified_email and prop_email.lower() != verified_email.lower():
            prop_e = prop_msg.get("enrichment_json") or {}
            approval_hash = sha256_hash(f"poisoning:email:{contact_id}:{prop_email}:{verified_email}")
            _add_staging({
                "contact_id": contact_id,
                "master_id": master_id,
                "source": prop_msg.get("source", "email"),
                "source_message_pk": prop_msg["message_pk"],
                "reason_type": "profile_poisoning",
                "proposed_changes": {"email": prop_email},
                "existing_snapshot": {"email": verified_email},
                "candidate_matches": [],
                "source_quote": f"Scraped email: {prop_email}",
                "confidence": float(prop_e.get("confidence", 1.0)),
                "approval_hash": approval_hash,
            })

    for prop_phone, prop_msg in proposed_phones:
        if verified_phone and prop_phone != verified_phone:
            prop_e = prop_msg.get("enrichment_json") or {}
            approval_hash = sha256_hash(f"poisoning:phone_wa:{contact_id}:{prop_phone}:{verified_phone}")
            _add_staging({
                "contact_id": contact_id,
                "master_id": master_id,
                "source": prop_msg.get("source", "whatsapp"),
                "source_message_pk": prop_msg["message_pk"],
                "reason_type": "profile_poisoning",
                "proposed_changes": {"phone_wa": prop_phone},
                "existing_snapshot": {"phone_wa": verified_phone},
                "candidate_matches": [],
                "source_quote": f"Scraped phone: {prop_phone}",
                "confidence": float(prop_e.get("confidence", 1.0)),
                "approval_hash": approval_hash,
            })

    # Aggregate fleet units across all clean messages (regex union LLM)
    all_fleet: list[str] = []
    for m in clean_msgs:
        for u in extract_fleet_units(m.get("clean_body") or ""):
            if u not in all_fleet:
                all_fleet.append(u)
        e = m.get("enrichment_json") or {}
        for u in (e.get("fleet_units") or []):
            u_norm = str(u).strip().upper()
            if u_norm and u_norm not in all_fleet:
                all_fleet.append(u_norm)

    # Aggregate intents, sentiments, formality across all clean messages
    intents: dict[str, int] = {}
    sentiments: dict[str, int] = {}
    formality_counts: dict[str, int] = {}
    for m in clean_msgs:
        e = m.get("enrichment_json") or {}
        intent = e.get("intent", "")
        if intent:
            intents[intent] = intents.get(intent, 0) + 1
        s = e.get("sentiment", "")
        if s:
            sentiments[s] = sentiments.get(s, 0) + 1
        f = e.get("formality", "")
        if f:
            formality_counts[f] = formality_counts.get(f, 0) + 1

    dominant_formality = max(formality_counts, key=formality_counts.get) if formality_counts else "formal"

    # Edge Case 3: Deduplicated & auto-resolved complaints / commitments
    complaints, commitments = aggregate_complaints_and_commitments(msgs)

    # Message counts (rolling 30d + lifetime)
    now = now_utc or datetime.now(timezone.utc)
    thirty_days_ago = now.timestamp() - (30 * 24 * 3600)
    total_30d = 0
    for m in msgs:
        if m.get("message_date"):
            try:
                msg_time = m["message_date"].timestamp() if hasattr(m["message_date"], "timestamp") else 0
                if msg_time >= thirty_days_ago:
                    total_30d += 1
            except Exception:
                pass

    # Field provenance (exact source_message_pk per field)
    field_provenance: dict[str, str] = {}
    for field, value, prov in [
        ("full_name", full_name, full_name_prov),
        ("city", city, city_prov),
        ("org_name", org_name, org_prov),
        ("role_title", role_title, role_prov),
        ("phone_wa", phone_wa, phone_prov),
        ("email", email_addr, email_prov),
        ("telegram_handle", telegram_handle, telegram_prov),
    ]:
        if value and prov:
            field_provenance[field] = prov

    best_window = compute_best_contact_window(tz)
    salutation = infer_salutation(full_name)
    active_channels = sorted({m["source"] for m in msgs if m.get("source")})

    last_msg_date = None
    for m in reversed(msgs):
        if m.get("message_date"):
            last_msg_date = m["message_date"]
            break

    # Consolidated confidence (Edge Case 1)
    confidence = _resolve_profile_confidence(msgs, existing)
    if confidence < CONFIDENCE_THRESHOLD:
        _add_staging({
            "contact_id": contact_id,
            "master_id": master_id,
            "source": latest.get("source", "email"),
            "source_message_pk": latest["message_pk"],
            "reason_type": "low_confidence",
            "proposed_changes": {"confidence": confidence, "verification_status": "verified"},
            "existing_snapshot": {"confidence": existing["confidence"] if existing else None},
            "candidate_matches": [],
            "source_quote": "Enrichment confidence below threshold (< 0.6)",
            "confidence": confidence,
            "approval_hash": sha256_hash(f"low_confidence:{contact_id}:{latest['message_pk']}"),
        })

    category = (existing.get("category") if existing and existing.get("category") else "customer")
    personalization_level = (
        existing.get("personalization_level")
        if existing and existing.get("personalization_level")
        else ("timing_only" if category == "peer" else "full")
    )

    (
        communication_prefs,
        character_profile,
        motivation_and_pain,
        persuasion_profile,
        relationship_health,
        character_style,
        churn_risk_level,
    ) = build_intelligence_dimensions(
        clean_msgs=clean_msgs,
        existing=existing,
        full_name=full_name,
        salutation=salutation,
        tz_label=tz_label,
        dominant_formality=dominant_formality,
        complaints=complaints,
        commitments=commitments,
        last_msg_date=last_msg_date,
        now=now,
    )

    # Preserve existing user_confirmed provenance keys (TR-08)
    if existing and isinstance(existing.get("field_provenance"), dict):
        for p_key, p_val in existing["field_provenance"].items():
            if p_val == "user_confirmed":
                field_provenance[p_key] = "user_confirmed"

    master_data = {
        "master_id": master_id,
        "contact_id": contact_id,
        "full_name": full_name,
        "salutation": salutation,
        "role_title": role_title,
        "category": category,
        "personalization_level": personalization_level,
        "org_id": (existing.get("org_id") if existing and existing.get("org_id") else f"org_{contact_id}"),
        "org_name": org_name,
        "account_tier": (existing.get("account_tier") if existing and existing.get("account_tier") else "Standard Account"),
        "city": city or "Jakarta",
        "timezone": tz,
        "tz_label": tz_label,
        "work_hours_local": "08:00-17:00",
        "jumatan_block_local": "11:30-13:00 (WIB & Local)",
        "after_hours_policy": "defer_next_workday_0800_local",
        "best_contact_window": best_window,
        "email": email_addr,
        "phone_wa": phone_wa,
        "telegram_handle": telegram_handle,
        "preferred_channel": (existing.get("preferred_channel") if existing and existing.get("preferred_channel") else "whatsapp"),
        "active_channels": active_channels,
        "total_messages_30d": total_30d,
        "total_messages_lifetime": len(msgs),
        "avg_response_delay_sec": existing.get("avg_response_delay_sec") if existing else None,
        "dominant_formality": dominant_formality,
        "sentiment_mix": sentiments,
        "top_intents": intents,
        "fleet_units": all_fleet,
        "open_complaints": complaints,
        "open_commitments": commitments,
        "character_style": character_style,
        "churn_risk_level": churn_risk_level,
        "communication_prefs": communication_prefs,
        "character_profile": character_profile,
        "motivation_and_pain": motivation_and_pain,
        "persuasion_profile": persuasion_profile,
        "relationship_health": relationship_health,
        "agent_brief": "",
        "consent_status": "granted",
        "confidence": confidence,
        "needs_review": confidence < CONFIDENCE_THRESHOLD,
        "verification_status": (
            "staged_unverified"
            if len(pending_staging_rows) > 0 or confidence < CONFIDENCE_THRESHOLD
            else "verified"
        ),
        "field_provenance": field_provenance,
        "visible_to_roles": (
            existing.get("visible_to_roles")
            if existing and existing.get("visible_to_roles")
            else ["owner_rifat", "owner_andi"]
        ),
        "approval_hash": sha256_hash(f"master:{contact_id}:{full_name}"),
        "last_message_at": last_msg_date,
        "last_scraped_at": now,
        "updated_at": now,
    }

    master_data["agent_brief"] = compile_agent_brief(master_data)
    master_data = apply_peer_privacy(master_data)
    return master_data, pending_staging_rows


# ============================================================================
# Command: build-master
# ============================================================================

def cmd_build_master(args):
    """Aggregate enriched messages into customer_master_profiles."""
    conn = get_connection()

    # Get all enriched (done/review) messages ordered chronologically
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT message_pk, source, source_id, sender_raw, sender_name,
                      sender_identifier, subject, redacted_body, clean_body,
                      injection_flags, features_json, enrichment_json,
                      message_date, contact_id
               FROM public.scraped_messages
               WHERE enrichment_status IN ('done', 'review')
               ORDER BY message_date ASC NULLS LAST, message_pk ASC"""
        )
        messages = cur.fetchall()

    if not messages:
        print(json.dumps({"status": "no_data", "message": "No enriched messages to build master profiles from."}, indent=2))
        conn.close()
        return

    # Load existing identifier -> contact_id mapping for cross-channel grouping
    ident_to_contact: dict[str, str] = {}
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT contact_id, email, phone_wa, telegram_handle FROM public.customer_master_profiles"
        )
        for prof in cur.fetchall():
            cid = prof["contact_id"]
            for col in ("email", "phone_wa", "telegram_handle"):
                val = str(prof.get(col) or "").strip().lower()
                if val:
                    ident_to_contact[val] = cid

    # Group across channels by canonical contact_id (Edge Case 2)
    groups = group_messages_by_contact(messages, ident_to_contact=ident_to_contact)

    masters_built = 0
    staged = 0
    synced = 0

    for contact_id, msgs in groups.items():
        # Check for existing master profile
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM public.customer_master_profiles WHERE contact_id=%s",
                (contact_id,)
            )
            existing = cur.fetchone()

        master_data, pending_staging_rows = build_master_profile_data(
            contact_id=contact_id,
            msgs=msgs,
            existing=existing,
        )
        full_name = master_data["full_name"]
        master_id = master_data["master_id"]
        tz = master_data["timezone"]
        tz_label = master_data["tz_label"]
        latest = msgs[-1]

        # Check for ambiguous contacts (multiple "Pak Budi" in different cities)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT contact_id, master_id, full_name, city FROM public.customer_master_profiles
                   WHERE full_name ILIKE %s AND contact_id != %s""",
                (f"%{full_name.split()[0] if full_name else ''}%", contact_id)
            )
            ambiguous = cur.fetchall()

        if ambiguous and not existing:
            candidates = [
                {"contact_id": amb["contact_id"], "master_id": amb["master_id"],
                 "full_name": amb["full_name"], "city": amb["city"]}
                for amb in ambiguous
            ]
            approval_hash = sha256_hash(f"ambiguity:{contact_id}:{','.join(a['contact_id'] for a in ambiguous)}")
            pending_staging_rows.append({
                "contact_id": contact_id,
                "master_id": master_id,
                "source": latest["source"],
                "source_message_pk": latest["message_pk"],
                "reason_type": "contact_ambiguity",
                "proposed_changes": {"full_name": full_name, "city": master_data["city"]},
                "existing_snapshot": {},
                "candidate_matches": candidates,
                "source_quote": f"Name '{full_name}' may match existing contact(s): {', '.join(a['contact_id'] for a in ambiguous)}",
                "confidence": master_data["confidence"],
                "approval_hash": approval_hash,
            })
            master_data["verification_status"] = "staged_unverified"

        # Upsert into customer_master_profiles
        if existing:
            # Update existing
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.customer_master_profiles SET
                       full_name=%s, role_title=%s, org_name=%s,
                       city=%s, timezone=%s, tz_label=%s,
                       best_contact_window=%s,
                       email=%s, phone_wa=%s, telegram_handle=%s,
                       active_channels=%s,
                       total_messages_30d=%s, total_messages_lifetime=%s,
                       dominant_formality=%s, sentiment_mix=%s, top_intents=%s,
                       fleet_units=%s, open_complaints=%s, open_commitments=%s,
                       character_style=%s, churn_risk_level=%s,
                       communication_prefs=%s, character_profile=%s,
                       motivation_and_pain=%s, persuasion_profile=%s,
                       relationship_health=%s, agent_brief=%s,
                       confidence=%s, needs_review=%s, verification_status=%s,
                       field_provenance=%s,
                       last_message_at=%s, last_scraped_at=NOW(), updated_at=NOW()
                       WHERE contact_id=%s""",
                    (master_data["full_name"], master_data["role_title"], master_data["org_name"],
                     master_data["city"], master_data["timezone"], master_data["tz_label"],
                     master_data["best_contact_window"],
                     master_data["email"], master_data["phone_wa"], master_data["telegram_handle"],
                     Json(master_data["active_channels"]),
                     master_data["total_messages_30d"], master_data["total_messages_lifetime"],
                     master_data["dominant_formality"], Json(master_data["sentiment_mix"]),
                     Json(master_data["top_intents"]),
                     Json(master_data["fleet_units"]),
                     Json(master_data["open_complaints"]),
                     Json(master_data["open_commitments"]),
                     master_data["character_style"], master_data["churn_risk_level"],
                     Json(master_data["communication_prefs"]),
                     Json(master_data["character_profile"]),
                     Json(master_data["motivation_and_pain"]),
                     Json(master_data["persuasion_profile"]),
                     Json(master_data["relationship_health"]),
                     master_data["agent_brief"],
                     master_data["confidence"], master_data["needs_review"],
                     master_data["verification_status"],
                     Json(master_data["field_provenance"]),
                     master_data["last_message_at"],
                     contact_id)
                )
        else:
            # Insert new
            columns = list(master_data.keys())
            values = []
            for col in columns:
                val = master_data[col]
                if isinstance(val, (dict, list)):
                    val = Json(val)
                values.append(val)
            placeholders = ", ".join(["%s"] * len(columns))
            col_names = ", ".join(columns)
            with conn.cursor() as cur:
                cur.execute(
                    f"""INSERT INTO public.customer_master_profiles ({col_names})
                        VALUES ({placeholders})
                        ON CONFLICT (contact_id) DO NOTHING""",
                    values
                )

        masters_built += 1

        # Insert staged conflict/ambiguity/low-confidence rows now that master_id exists
        for s_row in pending_staging_rows:
            staging_id = f"stg_{s_row['approval_hash'][:12]}"
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO public.master_profile_staging
                       (staging_id, contact_id, master_id, source, source_message_pk,
                        reason_type, proposed_changes, existing_snapshot,
                        candidate_matches, source_quote, confidence,
                        approval_hash, status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending_approval')
                       ON CONFLICT (staging_id) DO NOTHING""",
                    (staging_id, s_row["contact_id"], s_row["master_id"], s_row["source"],
                     s_row["source_message_pk"], s_row["reason_type"],
                     Json(s_row["proposed_changes"]), Json(s_row["existing_snapshot"]),
                     Json(s_row["candidate_matches"]), s_row["source_quote"],
                     s_row["confidence"], s_row["approval_hash"])
                )
            staged += 1

        # Update scraped_messages.contact_id for this sender's messages
        msg_pks = [m["message_pk"] for m in msgs]
        if msg_pks:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE public.scraped_messages SET contact_id=%s WHERE message_pk = ANY(%s)",
                    (contact_id, msg_pks)
                )

        # Sync to live DBeaver organizations table (org_id, name, org_json TEXT, organization_news JSONB)
        if master_data["org_name"]:
            org_payload = {
                "account_tier": master_data["account_tier"],
                "city": master_data["city"],
                "timezone": tz,
                "tz_label": tz_label,
            }
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO public.organizations
                       (org_id, name, org_json, organization_news)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (org_id) DO UPDATE SET
                         name=EXCLUDED.name,
                         org_json=EXCLUDED.org_json""",
                    (master_data["org_id"], master_data["org_name"],
                     json.dumps(org_payload, ensure_ascii=False), Json([]))
                )
            synced += 1

    # Audit
    append_audit(conn, args.owner, "build_master", "customer_master_profiles", "", {
        "masters_built": masters_built,
        "staged": staged,
        "synced_organizations": synced,
        "total_messages": len(messages),
    })

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": "completed",
        "masters_built": masters_built,
        "staged_conflicts": staged,
        "synced_organizations": synced,
        "total_messages_processed": len(messages),
    }, indent=2))

# ============================================================================
# Command: approve-staging
# ============================================================================

def cmd_approve_staging(args):
    """Approve or reject a staged master profile change."""
    conn = get_connection()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM public.master_profile_staging WHERE staging_id=%s",
            (args.id,)
        )
        item = cur.fetchone()

    if not item:
        print(json.dumps({"error": f"Staging ID {args.id} not found"}, indent=2))
        conn.close()
        return

    if item["status"] not in ("pending_approval", "pending"):
        print(json.dumps({"error": f"Staging ID {args.id} is already {item['status']}"}, indent=2))
        conn.close()
        return

    # Verify approval_hash
    if args.hash and args.hash != item["approval_hash"]:
        print(json.dumps({"error": "approval_hash mismatch"}, indent=2))
        conn.close()
        return

    reason_type = item.get("reason_type", "")
    proposed_changes = item.get("proposed_changes") or {}
    allowed_fields = {"email", "phone_wa", "telegram_handle", "full_name", "role_title", "city", "org_name"}

    if args.decision == "approve":
        # Apply the staged change
        if reason_type == "profile_poisoning" and isinstance(proposed_changes, dict):
            for field_name, proposed_val in proposed_changes.items():
                if field_name in allowed_fields:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""UPDATE public.customer_master_profiles
                                SET {field_name}=%s, updated_at=NOW()
                                WHERE contact_id=%s""",
                            (proposed_val, item["contact_id"])
                        )
        elif reason_type == "contact_ambiguity":
            # Mark as resolved — user confirmed this is a distinct person
            pass
        elif reason_type == "low_confidence":
            # Mark the master profile as verified after human review
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.customer_master_profiles
                       SET verification_status='verified', needs_review=FALSE,
                       updated_at=NOW() WHERE contact_id=%s""",
                    (item["contact_id"],)
                )

        with conn.cursor() as cur:
            cur.execute(
                """UPDATE public.master_profile_staging
                   SET status='approved', reviewed_by=%s, reviewed_at=NOW()
                   WHERE staging_id=%s""",
                (args.owner, args.id)
            )

        append_audit(conn, args.owner, "staging_approved", "master_profile_staging", str(args.id), {
            "reason_type": reason_type,
            "proposed_changes": proposed_changes,
            "contact_id": item["contact_id"],
        })
    else:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE public.master_profile_staging
                   SET status='rejected', reviewed_by=%s, reviewed_at=NOW()
                   WHERE staging_id=%s""",
                (args.owner, args.id)
            )

        append_audit(conn, args.owner, "staging_rejected", "master_profile_staging", str(args.id), {
            "reason_type": reason_type,
            "contact_id": item["contact_id"],
        })

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": args.decision,
        "staging_id": args.id,
        "reviewed_by": args.owner,
    }, indent=2))

# ============================================================================
# Command: report
# ============================================================================

def cmd_report(args):
    """Print Markdown Master Customer Profile Table."""
    conn = get_connection()

    # Filter by timezone group if specified
    where_clause = ""
    params = []
    if args.tz_group:
        tz_map = {"WIB": "WIB", "WITA": "WITA", "WIT": "WIT"}
        tz_label = tz_map.get(args.tz_group.upper(), args.tz_group.upper())
        where_clause = "WHERE tz_label = %s"
        params = [tz_label]

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""SELECT * FROM public.customer_master_profiles
                {where_clause}
                ORDER BY tz_label, full_name""",
                params
        )
        profiles = cur.fetchall()

        # Staging queue
        cur.execute(
            "SELECT * FROM public.master_profile_staging WHERE status='pending_approval' ORDER BY created_at DESC"
        )
        staging = cur.fetchall()

        # Audit chain (live DBeaver audit_events columns)
        cur.execute(
            """SELECT id, timestamp, request_id, event_type, payload_json, prev_hash, curr_hash
               FROM public.audit_events ORDER BY id DESC LIMIT 20"""
        )
        audit_events = cur.fetchall()

        # Table counts
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM public.scraped_messages) as scraped_messages,
                (SELECT COUNT(*) FROM public.customer_master_profiles) as master_profiles,
                (SELECT COUNT(*) FROM public.master_profile_staging WHERE status='pending_approval') as staging_pending,
                (SELECT COUNT(*) FROM public.audit_events) as audit_events_total,
                (SELECT COUNT(*) FROM public.scraped_messages WHERE enrichment_status='pending') as enrichment_pending,
                (SELECT COUNT(*) FROM public.scraped_messages WHERE needs_review=TRUE) as needs_review
        """)
        counts = cur.fetchone()

    conn.close()

    # Build Markdown report
    lines = []
    lines.append("# Master Customer Profile Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| Scraped Messages | {counts['scraped_messages']} |")
    lines.append(f"| Master Profiles | {counts['master_profiles']} |")
    lines.append(f"| Staging Pending | {counts['staging_pending']} |")
    lines.append(f"| Enrichment Pending | {counts['enrichment_pending']} |")
    lines.append(f"| Needs Review | {counts['needs_review']} |")
    lines.append(f"| Audit Events | {counts['audit_events_total']} |")
    lines.append("")

    # Master profiles table
    if profiles:
        lines.append("## Master Customer Profiles")
        if args.tz_group:
            lines.append(f"(Filtered: {args.tz_group.upper()})")
        lines.append("")
        lines.append("| Master ID | Name | Org | City | TZ | Role | Phone | Email | Confidence | Status |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for p in profiles:
            lines.append(
                f"| {p['master_id']} | {p['full_name']} | {p['org_name']} | "
                f"{p['city']} | {p['tz_label']} | {p['role_title']} | "
                f"{p['phone_wa'] or '-'} | {p['email'] or '-'} | "
                f"{p['confidence']:.2f} | {p['verification_status']} |"
            )
        lines.append("")

        # Detailed profiles
        lines.append("## Detailed Profiles")
        lines.append("")
        for p in profiles:
            lines.append(f"### {p['full_name']} ({p['master_id']})")
            lines.append(f"- **Contact ID:** {p['contact_id']}")
            lines.append(f"- **Organization:** {p['org_name']}")
            lines.append(f"- **Role:** {p['role_title']}")
            lines.append(f"- **City/Timezone:** {p['city']} / {p['tz_label']} ({p['timezone']})")
            lines.append(f"- **Best Contact Window:** {p['best_contact_window']}")
            lines.append(f"- **Active Channels:** {', '.join(p['active_channels'])}")
            lines.append(f"- **Preferred Channel:** {p['preferred_channel']}")
            lines.append(f"- **Phone (WA):** {p['phone_wa'] or '-'}")
            lines.append(f"- **Email:** {p['email'] or '-'}")
            lines.append(f"- **Messages (30d/Lifetime):** {p['total_messages_30d']}/{p['total_messages_lifetime']}")
            lines.append(f"- **Dominant Formality:** {p['dominant_formality']}")
            if p['fleet_units']:
                lines.append(f"- **Fleet Units:** {', '.join(p['fleet_units'])}")
            if p['open_complaints']:
                lines.append(f"- **Open Complaints:** {len(p['open_complaints'])}")
                for c in p['open_complaints']:
                    lines.append(f"  - {c.get('text', '')}")
            if p['open_commitments']:
                lines.append(f"- **Open Commitments:** {len(p['open_commitments'])}")
                for c in p['open_commitments']:
                    lines.append(f"  - {c.get('text', '')}")
            lines.append(f"- **Confidence:** {p['confidence']:.2f}")
            lines.append(f"- **Verification Status:** {p['verification_status']}")
            if p['needs_review']:
                lines.append(f"- **⚠️ Needs Review**")
            lines.append(f"- **Field Provenance:** {json.dumps(p['field_provenance'], indent=2)}")
            lines.append("")
    else:
        lines.append("## Master Customer Profiles")
        lines.append("")
        lines.append("No master profiles found.")
        lines.append("")

    # Staging queue
    if staging:
        lines.append("## Staging Queue (Pending Approval)")
        lines.append("")
        lines.append("| ID | Reason | Contact | Existing | Proposed | Confidence |")
        lines.append("|---|---|---|---|---|---|")
        for s in staging:
            lines.append(
                f"| {s['staging_id']} | {s.get('reason_type', '-')} | {s['contact_id'] or '-'} | "
                f"{json.dumps(s.get('existing_snapshot') or {}, ensure_ascii=False)} | "
                f"{json.dumps(s.get('proposed_changes') or {}, ensure_ascii=False)} | "
                f"{s['confidence']:.2f} |"
            )
        lines.append("")
    else:
        lines.append("## Staging Queue")
        lines.append("")
        lines.append("No pending staging items.")
        lines.append("")

    # Audit chain
    lines.append("## Audit Chain (Last 20 Events)")
    lines.append("")
    if audit_events:
        lines.append("| ID | Actor | Event Type | Request ID | Timestamp | Hash (first 16) |")
        lines.append("|---|---|---|---|---|---|")
        for e in audit_events:
            raw_payload = e.get("payload_json") or {}
            if isinstance(raw_payload, str):
                try:
                    payload = json.loads(raw_payload)
                except Exception:
                    payload = {}
            else:
                payload = raw_payload
            actor = payload.get("actor", "-") if isinstance(payload, dict) else "-"
            ts_val = e["timestamp"].isoformat() if hasattr(e.get("timestamp"), "isoformat") else (e.get("timestamp") or "-")
            lines.append(
                f"| {e['id']} | {actor} | {e['event_type']} | "
                f"{e['request_id'] or '-'} | "
                f"{ts_val} | "
                f"{e['curr_hash'][:16]}... |"
            )
        lines.append("")
    else:
        lines.append("No audit events.")
        lines.append("")

    print("\n".join(lines))

# ============================================================================
# Ticket & Personalization Bridge (For Friend's WorkBuddy #2)
# ============================================================================

def build_ticket_records(
    item: dict,
    master_profile: dict | None = None,
    owner: str = "owner_rifat",
    now_utc: datetime | None = None,
) -> dict:
    """
    Pure 5-Pillar & WIB/WITA/WIT auto-mapper: converts 1 flat JSON from
    Friend's WorkBuddy agent into structured rows for:
      - public.tickets
      - public.ticket_actions
      - public.ticket_findings
    """
    ref_utc = now_utc or datetime.now(timezone.utc)
    profile = master_profile or {}

    source_message_pk = item.get("source_message_pk")
    contact_id = item.get("contact_id") or profile.get("contact_id") or ""
    request_id = (
        item.get("request_id")
        or f"req_{ref_utc.strftime('%Y%m%d%H%M%S')}_{source_message_pk or sha256_hash(json.dumps(item, default=str))[:6]}"
    )
    action_id = item.get("action_id") or f"act_{request_id}"

    raw_input = item.get("raw_input") or item.get("redacted_summary") or ""
    attachment_text = item.get("attachment_text") or ""
    redacted_summary = redact_pii(item.get("redacted_summary") or raw_input)
    owner_id = normalize_owner_id(
        raw_owner=str(item.get("owner_id") or owner or ""),
        meeting_text=f"{raw_input} {redacted_summary}",
        visible_to_roles=profile.get("visible_to_roles") if isinstance(profile.get("visible_to_roles"), list) else None,
    )
    source_channel = item.get("source_channel") or item.get("channel") or "whatsapp"

    # Personalization context from customer_master_profiles
    recipient_name = item.get("recipient_name") or profile.get("full_name") or ""
    recipient_email = item.get("recipient_email") or profile.get("email") or ""
    recipient_phone = item.get("recipient_phone") or profile.get("phone_wa") or ""
    recipient_org_id = item.get("recipient_org_id") or profile.get("org_id") or ""
    recipient_org_name = item.get("recipient_org_name") or profile.get("org_name") or ""
    recipient_city = item.get("recipient_city") or profile.get("city") or "Jakarta"
    recipient_tz = item.get("recipient_timezone") or profile.get("timezone") or ""
    tz_label = item.get("tz_label") or profile.get("tz_label") or ""
    if not recipient_tz or not tz_label:
        recipient_tz, tz_label = resolve_timezone(recipient_city)

    channel = item.get("channel") or profile.get("preferred_channel") or "whatsapp"
    channel_reason = item.get("channel_reason") or f"Preferred channel from customer_master_profiles ({channel})"
    action_type = item.get("action_type") or "reply_customer"
    subject = item.get("subject") or ""
    body_draft = item.get("body_draft") or ""
    source_quote = item.get("source_quote") or ""
    risk_tier = item.get("risk_tier") or "medium"
    confidence = float(item.get("confidence", profile.get("confidence", 1.0)))
    is_ramadan = bool(item.get("is_ramadan", False))

    # Timezone & Jumatan scheduling (BR-04, TR-09)
    scheduled_send_at, rule_applied = compute_scheduled_send_at(
        recipient_tz, now_utc=ref_utc, is_ramadan=is_ramadan
    )

    findings = []
    interrupt_reasons = []

    # Finding 1: Timezone / Jumatan / After-hours deferral
    if rule_applied != "IMMEDIATE_WITHIN_HOURS":
        findings.append({
            "finding_id": f"fnd_{request_id}_tz",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "timezone_deferral",
            "severity": "info",
            "message": f"Deferred send to {scheduled_send_at.isoformat()} ({tz_label}) per {rule_applied}",
            "recommended_fix": False,
        })

    # Finding 2: SOURCES pillar — verbatim source_quote check
    if not source_quote.strip():
        findings.append({
            "finding_id": f"fnd_{request_id}_src",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "source_provenance",
            "severity": "warning",
            "message": "Missing verbatim source_quote (SOURCES pillar)",
            "recommended_fix": True,
        })

    # Finding 3: PERMISSIONS pillar — Peer privacy TR-10
    if profile.get("category") == "peer":
        findings.append({
            "finding_id": f"fnd_{request_id}_peer",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "peer_privacy",
            "severity": "info",
            "message": "Recipient is an internal peer (TR-10): timing_only personalization enforced",
            "recommended_fix": False,
        })

    # Finding 4: PERMISSIONS pillar — UU PDP BR-17 blocklist on draft & summary
    blocked_term = check_pdp_blocklist(body_draft, [redacted_summary, subject])
    if blocked_term:
        findings.append({
            "finding_id": f"fnd_{request_id}_pdp",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "pdp_blocklist",
            "severity": "critical",
            "message": f"Draft contains UU PDP blocked attribute '{blocked_term}' (BR-17)",
            "recommended_fix": True,
        })
        interrupt_reasons.append("pdp_violation")

    # Finding 5: LIMITS pillar — Low confidence (< 0.6)
    if confidence < CONFIDENCE_THRESHOLD:
        findings.append({
            "finding_id": f"fnd_{request_id}_conf",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "confidence_limit",
            "severity": "warning",
            "message": f"Confidence {confidence:.2f} is below 0.60 threshold (LIMITS pillar)",
            "recommended_fix": True,
        })
        interrupt_reasons.append("low_confidence")

    # Finding 6: LIMITS pillar — Landline check for WhatsApp channel
    if channel == "whatsapp" and recipient_phone and is_landline(recipient_phone):
        findings.append({
            "finding_id": f"fnd_{request_id}_landline",
            "request_id": request_id,
            "action_id": action_id,
            "check_type": "landline_whatsapp",
            "severity": "warning",
            "message": f"Recipient phone '{recipient_phone}' is a landline; cannot send via WhatsApp",
            "recommended_fix": True,
        })
        recipient_phone = ""

    # Determine interrupt_type & approval_hash (APPROVAL pillar)
    if "pdp_violation" in interrupt_reasons:
        interrupt_type = "pdp_violation"
    elif "low_confidence" in interrupt_reasons:
        interrupt_type = "low_confidence"
    else:
        interrupt_type = "external_communication"

    approval_payload = {
        "request_id": request_id,
        "action_id": action_id,
        "contact_id": contact_id,
        "channel": channel,
        "body_draft": body_draft,
        "scheduled_send_at": scheduled_send_at.isoformat(),
    }
    approval_hash = canonical_hash(approval_payload)

    provenance_links = list(item.get("provenance_links") or [])
    if source_message_pk is not None:
        ref = f"scraped_msg_pk_{source_message_pk}"
        if ref not in provenance_links:
            provenance_links.append(ref)
    if profile.get("master_id"):
        mref = f"master_profile:{profile['master_id']}"
        if mref not in provenance_links:
            provenance_links.append(mref)

    customer_context = {
        "source_message_pk": source_message_pk,
        "master_id": profile.get("master_id", ""),
        "contact_id": contact_id,
        "full_name": recipient_name,
        "salutation": profile.get("salutation", "formal_bapak"),
        "category": profile.get("category", "customer"),
        "personalization_level": (
            "timing_only" if profile.get("category") == "peer"
            else profile.get("personalization_level", "full")
        ),
        "org_name": recipient_org_name,
        "city": recipient_city,
        "tz_label": tz_label,
        "best_contact_window": profile.get("best_contact_window", compute_best_contact_window(recipient_tz, is_ramadan)),
        "fleet_units": profile.get("fleet_units", []),
        "confidence": confidence,
    }

    wa_handoff_link = (
        item.get("wa_handoff_link")
        or (build_wa_handoff_link(recipient_phone, body_draft) if channel == "whatsapp" and recipient_phone else "")
    )

    ticket_row = {
        "request_id": request_id,
        "owner_id": owner_id,
        "source_channel": source_channel,
        "raw_input": raw_input,
        "attachment_text": attachment_text,
        "redacted_summary": redacted_summary,
        "status": "pending_approval",
        "interrupt_type": interrupt_type,
        "interrupt_payload": {
            "reasons": interrupt_reasons or ["external_communication"],
            "risk_tier": risk_tier,
            "rule_applied": rule_applied,
            "findings_count": len(findings),
        },
        "approval_hash": approval_hash,
        "customer_context": customer_context,
    }

    action_row = {
        "action_id": action_id,
        "request_id": request_id,
        "action_type": action_type,
        "channel": channel,
        "channel_reason": channel_reason,
        "recipient_contact_id": contact_id,
        "recipient_name": recipient_name,
        "recipient_email": recipient_email,
        "recipient_phone": recipient_phone,
        "recipient_org_id": recipient_org_id,
        "recipient_org_name": recipient_org_name,
        "recipient_city": recipient_city,
        "recipient_timezone": recipient_tz,
        "subject": subject,
        "body_draft": body_draft,
        "scheduled_send_at": scheduled_send_at,
        "tz_label": tz_label,
        "rule_applied": rule_applied,
        "risk_tier": risk_tier,
        "provenance_links": provenance_links,
        "status": "staged",
        "wa_handoff_link": wa_handoff_link,
        "source_quote": source_quote,
    }

    return {
        "ticket": ticket_row,
        "action": action_row,
        "findings": findings,
    }


def cmd_ticket_pending(args):
    """Fetch enriched scraped_messages + customer_master_profiles for Friend's WorkBuddy #2."""
    conn = get_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT m.message_pk, m.source, m.source_id, m.subject,
                      m.sender_name, m.sender_identifier, m.redacted_body,
                      m.enrichment_json, m.message_date, m.contact_id,
                      p.master_id, p.full_name, p.salutation, p.role_title,
                      p.category, p.personalization_level, p.org_id, p.org_name,
                      p.city, p.timezone, p.tz_label, p.best_contact_window,
                      p.email, p.phone_wa, p.telegram_handle, p.preferred_channel,
                      p.dominant_formality, p.fleet_units, p.open_complaints,
                      p.open_commitments, p.character_style, p.churn_risk_level,
                      p.communication_prefs, p.character_profile,
                      p.motivation_and_pain, p.persuasion_profile,
                      p.relationship_health, p.agent_brief,
                      p.verification_status, p.confidence
               FROM public.scraped_messages m
               LEFT JOIN public.customer_master_profiles p
                 ON p.contact_id = m.contact_id
               WHERE m.enrichment_status IN ('done', 'review')
                 AND NOT EXISTS (
                     SELECT 1 FROM public.tickets t
                     WHERE (t.customer_context->>'source_message_pk') = m.message_pk::text
                 )
               ORDER BY m.message_date DESC NULLS LAST, m.ingested_at DESC
               LIMIT %s""",
            (args.limit,)
        )
        rows = cur.fetchall()
    conn.close()

    items = []
    for row in rows:
        profile = None
        if row.get("master_id"):
            profile = {
                "master_id": row["master_id"],
                "contact_id": row["contact_id"],
                "full_name": row["full_name"],
                "salutation": row["salutation"],
                "role_title": row["role_title"],
                "category": row["category"],
                "personalization_level": row["personalization_level"],
                "org_id": row["org_id"],
                "org_name": row["org_name"],
                "city": row["city"],
                "timezone": row["timezone"],
                "tz_label": row["tz_label"],
                "best_contact_window": row["best_contact_window"],
                "email": row["email"],
                "phone_wa": row["phone_wa"],
                "telegram_handle": row["telegram_handle"],
                "preferred_channel": row["preferred_channel"],
                "dominant_formality": row["dominant_formality"],
                "fleet_units": row["fleet_units"] or [],
                "open_complaints": [] if row["category"] == "peer" else (row["open_complaints"] or []),
                "open_commitments": row["open_commitments"] or [],
                "character_style": "unknown" if row["category"] == "peer" else (row.get("character_style") or "unknown"),
                "churn_risk_level": "low" if row["category"] == "peer" else (row.get("churn_risk_level") or "low"),
                "communication_prefs": row.get("communication_prefs") or {},
                "character_profile": {} if row["category"] == "peer" else (row.get("character_profile") or {}),
                "motivation_and_pain": {} if row["category"] == "peer" else (row.get("motivation_and_pain") or {}),
                "persuasion_profile": {} if row["category"] == "peer" else (row.get("persuasion_profile") or {}),
                "relationship_health": {} if row["category"] == "peer" else (row.get("relationship_health") or {}),
                "agent_brief": "" if row["category"] == "peer" else (row.get("agent_brief") or ""),
                "verification_status": row["verification_status"],
                "confidence": row["confidence"],
            }
        items.append({
            "message": {
                "message_pk": row["message_pk"],
                "source": row["source"],
                "source_id": row["source_id"],
                "subject": row["subject"],
                "sender_name": row["sender_name"],
                "sender_identifier": row["sender_identifier"],
                "redacted_body": row["redacted_body"],
                "enrichment_json": row["enrichment_json"] or {},
                "message_date": row["message_date"].isoformat() if row["message_date"] else None,
            },
            "master_profile": profile,
        })

    print(json.dumps(items, indent=2, ensure_ascii=False))


def cmd_ticket_publish(args):
    """Auto-map 1 flat JSON (or list) into tickets, ticket_actions, ticket_findings & audit_events."""
    payloads = []
    if getattr(args, "payloads", None):
        payloads = args.payloads if isinstance(args.payloads, list) else [args.payloads]
    elif getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
            payloads = data if isinstance(data, list) else [data]

    if not payloads:
        print(json.dumps({"status": "error", "error": "No ticket payload provided"}, indent=2))
        return

    conn = get_connection()
    published = []

    for item in payloads:
        contact_id = item.get("contact_id", "")
        profile = None
        if contact_id:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM public.customer_master_profiles WHERE contact_id=%s",
                    (contact_id,)
                )
                profile = cur.fetchone()

        bundle = build_ticket_records(item, master_profile=dict(profile) if profile else None, owner=args.owner)
        t = bundle["ticket"]
        a = bundle["action"]
        findings = bundle["findings"]

        with conn.cursor() as cur:
            epoch_now = datetime.now(timezone.utc).timestamp()
            cur.execute(
                """INSERT INTO public.tickets
                   (request_id, owner_id, source_channel, raw_input, attachment_text,
                    minutes_summary, status, interrupt_type, interrupt_payload,
                    approval_hash, customer_context, updated_at, updated_at_iso)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                   ON CONFLICT (request_id) DO UPDATE SET
                     minutes_summary=EXCLUDED.minutes_summary,
                     status=EXCLUDED.status,
                     interrupt_type=EXCLUDED.interrupt_type,
                     interrupt_payload=EXCLUDED.interrupt_payload,
                     approval_hash=EXCLUDED.approval_hash,
                     customer_context=EXCLUDED.customer_context,
                     updated_at=EXCLUDED.updated_at,
                     updated_at_iso=NOW()""",
                (t["request_id"], t["owner_id"], t["source_channel"], t["raw_input"],
                 t["attachment_text"], t["redacted_summary"], t["status"],
                 t["interrupt_type"], Json(t["interrupt_payload"]),
                 t["approval_hash"], Json(t["customer_context"]), epoch_now)
            )

            sched_iso = a["scheduled_send_at"].isoformat() if hasattr(a["scheduled_send_at"], "isoformat") else str(a["scheduled_send_at"] or "")
            prov_trust = "trusted" if a["provenance_links"] else "unverified"
            cur.execute(
                """INSERT INTO public.ticket_actions
                   (action_id, request_id, action_type, channel, channel_reason,
                    recipient_contact_id, recipient_name, recipient_email, recipient_phone,
                    recipient_org_id, recipient_org_name, recipient_city, recipient_timezone,
                    subject, body_draft, scheduled_send_at, tz_label, rule_applied,
                    risk_tier, provenance_trust, status, wa_handoff_link, source_quote)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (request_id, action_id) DO UPDATE SET
                     body_draft=EXCLUDED.body_draft,
                     scheduled_send_at=EXCLUDED.scheduled_send_at,
                     rule_applied=EXCLUDED.rule_applied,
                     provenance_trust=EXCLUDED.provenance_trust,
                     wa_handoff_link=EXCLUDED.wa_handoff_link,
                     source_quote=EXCLUDED.source_quote""",
                (a["action_id"], a["request_id"], a["action_type"], a["channel"],
                 a["channel_reason"], a["recipient_contact_id"], a["recipient_name"],
                 a["recipient_email"], a["recipient_phone"], a["recipient_org_id"],
                 a["recipient_org_name"], a["recipient_city"], a["recipient_timezone"],
                 a["subject"], a["body_draft"], sched_iso, a["tz_label"],
                 a["rule_applied"], a["risk_tier"], prov_trust,
                 a["status"], a["wa_handoff_link"], a["source_quote"])
            )

            for f in findings:
                cur.execute(
                    """INSERT INTO public.ticket_findings
                       (finding_id, request_id, action_id, check_type, severity, message, requires_step_up)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (request_id, finding_id) DO UPDATE SET
                         severity=EXCLUDED.severity,
                         message=EXCLUDED.message,
                         requires_step_up=EXCLUDED.requires_step_up""",
                    (f["finding_id"], f["request_id"], f["action_id"], f["check_type"],
                     f["severity"], f["message"], f["recommended_fix"])
                )

        append_audit(conn, args.owner, "ticket_published", "tickets", t["request_id"], {
            "action_id": a["action_id"],
            "contact_id": a["recipient_contact_id"],
            "channel": a["channel"],
            "tz_label": a["tz_label"],
            "rule_applied": a["rule_applied"],
            "interrupt_type": t["interrupt_type"],
            "findings_count": len(findings),
            "approval_hash": t["approval_hash"],
        })

        published.append({
            "request_id": t["request_id"],
            "action_id": a["action_id"],
            "status": t["status"],
            "interrupt_type": t["interrupt_type"],
            "approval_hash": t["approval_hash"],
            "tz_label": a["tz_label"],
            "scheduled_send_at": a["scheduled_send_at"].isoformat(),
            "rule_applied": a["rule_applied"],
            "findings_count": len(findings),
        })

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": "completed",
        "published_count": len(published),
        "tickets": published,
    }, indent=2, ensure_ascii=False))


def cmd_ticket_approve(args):
    """Approve or reject a ticket; approved actions move to outbox_queue with 60s undo window."""
    conn = get_connection()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM public.tickets WHERE request_id=%s", (args.request_id,))
        ticket = cur.fetchone()

    if not ticket:
        print(json.dumps({"error": f"Ticket {args.request_id} not found"}, indent=2))
        conn.close()
        return

    # Enforce owner separation: only the ticket's assigned owner_id can approve/reject it
    ticket_owner = (ticket.get("owner_id") or "").strip()
    acting_owner = (args.owner or "").strip()
    if ticket_owner and acting_owner and ticket_owner != acting_owner:
        append_audit(conn, acting_owner, "rbac_access_denied", "tickets", args.request_id, {
            "reason": f"Ticket belongs to {ticket_owner}, attempted approval by {acting_owner}",
            "decision": args.decision,
        })
        conn.commit()
        conn.close()
        print(json.dumps({
            "error": f"Permission denied: ticket {args.request_id} belongs to {ticket_owner} (logged in as {acting_owner})",
            "forbidden": True,
        }, indent=2))
        return

    if args.hash and ticket.get("approval_hash") and args.hash != ticket["approval_hash"]:
        print(json.dumps({"error": "approval_hash mismatch"}, indent=2))
        conn.close()
        return

    enqueued_outbox = []
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    release_iso = (now_dt.timestamp() + 60)
    release_dt_iso = datetime.fromtimestamp(release_iso, tz=timezone.utc).isoformat()
    epoch_now = now_dt.timestamp()

    if args.decision == "approve":
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """UPDATE public.tickets
                   SET status='approved', approved_by=%s, approved_at=%s,
                       approval_decision='approve', updated_at=%s, updated_at_iso=NOW()
                   WHERE request_id=%s""",
                (args.owner, now_iso, epoch_now, args.request_id)
            )
            cur.execute(
                "SELECT * FROM public.ticket_actions WHERE request_id=%s",
                (args.request_id,)
            )
            actions = cur.fetchall()

            for act in actions:
                outbox_id = f"obx_{act['action_id']}"
                recipient_addr = (
                    act["recipient_phone"] if act["channel"] == "whatsapp"
                    else act["recipient_email"] or act["recipient_phone"]
                )
                action_snapshot = {
                    k: (v.isoformat() if hasattr(v, "isoformat") else v)
                    for k, v in dict(act).items()
                }
                cur.execute(
                    """INSERT INTO public.outbox_queue
                       (outbox_id, action_id, request_id, channel, recipient_name,
                        recipient_address, subject, body, scheduled_send_at,
                        enqueued_at, release_at, status, action_json)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                               %s, %s, 'queued', %s)
                       ON CONFLICT (outbox_id) DO NOTHING""",
                    (outbox_id, act["action_id"], args.request_id, act["channel"],
                     act["recipient_name"], recipient_addr, act["subject"],
                     act["body_draft"], str(act["scheduled_send_at"] or ""),
                     now_iso, release_dt_iso, json.dumps(action_snapshot, ensure_ascii=False))
                )
                cur.execute(
                    "UPDATE public.ticket_actions SET status='queued_outbox' WHERE action_id=%s",
                    (act["action_id"],)
                )
                enqueued_outbox.append(outbox_id)

        append_audit(conn, args.owner, "ticket_approved", "tickets", args.request_id, {
            "decision": "approve",
            "outbox_ids": enqueued_outbox,
        })
    else:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE public.tickets
                   SET status='rejected', approved_by=%s, approved_at=%s,
                       approval_decision='reject', updated_at=%s, updated_at_iso=NOW()
                   WHERE request_id=%s""",
                (args.owner, now_iso, epoch_now, args.request_id)
            )
            cur.execute(
                "UPDATE public.ticket_actions SET status='rejected' WHERE request_id=%s",
                (args.request_id,)
            )
        append_audit(conn, args.owner, "ticket_rejected", "tickets", args.request_id, {
            "decision": "reject",
        })

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": args.decision,
        "request_id": args.request_id,
        "approved_by": args.owner,
        "outbox_ids": enqueued_outbox,
    }, indent=2))

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="WorkBuddy Master Customer Profiler — Supabase PostgreSQL"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ingest-omni
    p = sub.add_parser("ingest-omni", help="Ingest omni-channel messages into Supabase")
    p.add_argument("--source", default="all", choices=["all", "email", "whatsapp", "telegram"])
    p.add_argument("--trigger", default="scheduled", choices=["scheduled", "manual"])
    p.add_argument("--stdin", action="store_true", help="Read JSON from stdin")
    p.add_argument("--feed-file", default=None, help="Path to JSON feed file")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    # pending
    p = sub.add_parser("pending", help="Fetch PII-redacted pending messages")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)

    # write
    p = sub.add_parser("write", help="Validate and write enrichment results")
    p.add_argument("--version", default="v2", help="Analyzer version")
    p.add_argument("--model", default="workbuddy-expert", help="Model name")
    p.add_argument("--file", required=True, help="Path to JSON results file")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    # build-master
    p = sub.add_parser("build-master", help="Build consolidated master customer profiles")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    # approve-staging
    p = sub.add_parser("approve-staging", help="Approve or reject staged changes")
    p.add_argument("--id", type=str, required=True, help="Staging ID")
    p.add_argument("--decision", required=True, choices=["approve", "reject"])
    p.add_argument("--hash", default=None, help="Approval hash for verification")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    # report
    p = sub.add_parser("report", help="Print Markdown master profile report")
    p.add_argument("--tz-group", default=None, choices=["WIB", "WITA", "WIT"], help="Filter by timezone group")

    # ticket-pending (For Friend's WorkBuddy #2)
    p = sub.add_parser("ticket-pending", help="Fetch enriched messages + master profiles for personalization")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)

    # ticket-publish (For Friend's WorkBuddy #2)
    p = sub.add_parser("ticket-publish", help="Auto-map 1 flat JSON into tickets/actions/findings/audit")
    p.add_argument("--file", default=None, help="Path to JSON ticket payload file")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    # ticket-approve (Website UI / MCP approval -> 60s outbox_queue)
    p = sub.add_parser("ticket-approve", help="Approve/reject ticket and enqueue to 60s outbox_queue")
    p.add_argument("--request-id", required=True, help="Ticket request_id")
    p.add_argument("--decision", required=True, choices=["approve", "reject"])
    p.add_argument("--hash", default=None, help="Canonical SHA-256 approval_hash")
    p.add_argument("--owner", default=os.environ.get("DEFAULT_OWNER", "owner_rifat"))

    args = parser.parse_args()

    if args.command == "ingest-omni":
        cmd_ingest_omni(args)
    elif args.command == "pending":
        cmd_pending(args)
    elif args.command == "write":
        cmd_write(args)
    elif args.command == "build-master":
        cmd_build_master(args)
    elif args.command == "approve-staging":
        cmd_approve_staging(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "ticket-pending":
        cmd_ticket_pending(args)
    elif args.command == "ticket-publish":
        cmd_ticket_publish(args)
    elif args.command == "ticket-approve":
        cmd_ticket_approve(args)


if __name__ == "__main__":
    main()
