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

        # Extract fields (safely flattens nested Zapier Gmail dict/list objects)
        raw_from = (
            payload.get("sender")
            if payload.get("sender") is not None
            else payload.get("from")
            if payload.get("from") is not None
            else payload.get("from_email") or payload.get("from_name") or ""
        )
        sender_raw, parsed_name, parsed_ident = _flatten_contact(raw_from)
        sender_name = _flatten_text(payload.get("sender_name") or payload.get("from_name")) or parsed_name
        sender_identifier = (
            _flatten_text(payload.get("sender_identifier") or payload.get("from_email"))
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
        subject = _flatten_text(payload.get("subject"))
        raw_body = _flatten_text(
            payload.get("body")
            or payload.get("body_plain")
            or payload.get("text")
            or payload.get("content")
            or payload.get("snippet")
        )
        message_date_str = _flatten_text(payload.get("date") or payload.get("message_date"))
        message_date = None
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

        # Check PDP blocklist
        blocked = check_pdp_blocklist(item.get("intent", ""), item.get("topics", []))
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

        # Extract additional enrichment fields
        enrichment = {
            "intent": item.get("intent", ""),
            "topics": item.get("topics", []),
            "sentiment": sentiment,
            "formality": formality,
            "open_questions": item.get("open_questions", []),
            "commitments": item.get("commitments", []),
            "complaints": item.get("complaints", []),
            "fleet_units": item.get("fleet_units", []),
            "org_name": item.get("org_name", ""),
            "role_title": item.get("role_title", ""),
            "city": item.get("city", ""),
            "confidence": confidence,
            "analyzer_version": args.version,
            "model": args.model,
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
# Command: build-master
# ============================================================================

def cmd_build_master(args):
    """Aggregate enriched messages into customer_master_profiles."""
    conn = get_connection()

    # Get all enriched (done) messages grouped by sender_identifier
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT message_pk, source, source_id, sender_raw, sender_name,
                      sender_identifier, subject, redacted_body, clean_body,
                      features_json, enrichment_json, message_date, contact_id
               FROM public.scraped_messages
               WHERE enrichment_status IN ('done', 'review')
               ORDER BY message_date ASC"""
        )
        messages = cur.fetchall()

    if not messages:
        print(json.dumps({"status": "no_data", "message": "No enriched messages to build master profiles from."}, indent=2))
        conn.close()
        return

    # Group by sender_identifier
    groups = {}
    for msg in messages:
        key = msg["sender_identifier"] or msg["sender_name"]
        if key not in groups:
            groups[key] = []
        groups[key].append(msg)

    masters_built = 0
    staged = 0
    synced = 0

    for sender_key, msgs in groups.items():
        # Use the most recent enrichment as primary
        latest = msgs[-1]
        enrichment = latest["enrichment_json"] or {}

        # Extract identity
        full_name = latest["sender_name"] or sender_key
        # Try to parse a cleaner name from sender_raw
        if "<" in latest["sender_raw"]:
            full_name = latest["sender_raw"].split("<")[0].strip().strip('"')

        # Generate IDs
        contact_id = generate_contact_id(full_name)
        master_id = generate_master_id(contact_id, enrichment.get("org_name", ""))

        # Resolve timezone from enrichment city
        city = enrichment.get("city", "")
        tz, tz_label = resolve_timezone(city)

        # Extract phone/email from clean_body of messages
        phone_wa = ""
        email_addr = ""
        for m in msgs:
            if not phone_wa:
                phone_wa = extract_phone_e164(m["clean_body"] or "") or ""
            if not email_addr:
                email_addr = extract_email(m["clean_body"] or "") or ""

        # Check for landline (LIMITS pillar — never assign landline to phone_wa)
        if phone_wa and is_landline(phone_wa):
            phone_wa = ""

        # Aggregate fleet units across all messages
        all_fleet = []
        for m in msgs:
            units = extract_fleet_units(m["clean_body"] or "")
            for u in units:
                if u not in all_fleet:
                    all_fleet.append(u)

        # Also check enrichment for fleet_units
        if enrichment.get("fleet_units"):
            for u in enrichment["fleet_units"]:
                if u not in all_fleet:
                    all_fleet.append(u)

        # Aggregate intents
        intents = {}
        sentiments = {}
        formality_counts = {}
        for m in msgs:
            e = m["enrichment_json"] or {}
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

        # Collect commitments and complaints
        commitments = []
        complaints = []
        for m in msgs:
            e = m["enrichment_json"] or {}
            for c in e.get("commitments", []):
                commitments.append({"text": c, "source_message_pk": m["message_pk"]})
            for c in e.get("complaints", []):
                complaints.append({"text": c, "source_message_pk": m["message_pk"]})

        # Compute counts
        now = datetime.now(timezone.utc)
        thirty_days_ago = now.timestamp() - (30 * 24 * 3600)
        total_30d = 0
        for m in msgs:
            if m["message_date"]:
                try:
                    msg_time = m["message_date"].timestamp() if hasattr(m["message_date"], "timestamp") else 0
                    if msg_time >= thirty_days_ago:
                        total_30d += 1
                except Exception:
                    pass

        # Build field_provenance
        field_provenance = {}
        for field, value in [("full_name", full_name), ("city", city),
                             ("org_name", enrichment.get("org_name", "")),
                             ("role_title", enrichment.get("role_title", ""))]:
            if value:
                field_provenance[field] = f"scraped_msg_pk_{latest['message_pk']}"

        if phone_wa:
            field_provenance["phone_wa"] = f"scraped_msg_pk_{latest['message_pk']}"
        if email_addr:
            field_provenance["email"] = f"scraped_msg_pk_{latest['message_pk']}"

        # Compute best contact window
        best_window = compute_best_contact_window(tz)

        # Salutation
        salutation = infer_salutation(full_name)

        # Active channels
        active_channels = list(set(m["source"] for m in msgs))

        # Last message date
        last_msg_date = None
        for m in reversed(msgs):
            if m["message_date"]:
                last_msg_date = m["message_date"]
                break

        # Check for existing master profile
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM public.customer_master_profiles WHERE contact_id=%s",
                (contact_id,)
            )
            existing = cur.fetchone()

        # Collect staging rows to insert AFTER customer_master_profiles upsert (respects master_id FK)
        pending_staging_rows = []
        if existing:
            # Check if scraped email/phone conflicts with verified ones (TR-08)
            if email_addr and existing["email"] and email_addr != existing["email"]:
                approval_hash = sha256_hash(f"poisoning:email:{contact_id}:{email_addr}:{existing['email']}")
                pending_staging_rows.append({
                    "contact_id": contact_id,
                    "master_id": existing["master_id"],
                    "source": latest["source"],
                    "source_message_pk": latest["message_pk"],
                    "reason_type": "profile_poisoning",
                    "proposed_changes": {"email": email_addr},
                    "existing_snapshot": {"email": existing["email"]},
                    "candidate_matches": [],
                    "source_quote": f"Scraped email: {email_addr}",
                    "confidence": enrichment.get("confidence", 1.0),
                    "approval_hash": approval_hash,
                })
                email_addr = existing["email"]  # Keep verified value

            if phone_wa and existing["phone_wa"] and phone_wa != existing["phone_wa"]:
                approval_hash = sha256_hash(f"poisoning:phone_wa:{contact_id}:{phone_wa}:{existing['phone_wa']}")
                pending_staging_rows.append({
                    "contact_id": contact_id,
                    "master_id": existing["master_id"],
                    "source": latest["source"],
                    "source_message_pk": latest["message_pk"],
                    "reason_type": "profile_poisoning",
                    "proposed_changes": {"phone_wa": phone_wa},
                    "existing_snapshot": {"phone_wa": existing["phone_wa"]},
                    "candidate_matches": [],
                    "source_quote": f"Scraped phone: {phone_wa}",
                    "confidence": enrichment.get("confidence", 1.0),
                    "approval_hash": approval_hash,
                })
                phone_wa = existing["phone_wa"]

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
                "proposed_changes": {"full_name": full_name, "city": city or "Jakarta"},
                "existing_snapshot": {},
                "candidate_matches": candidates,
                "source_quote": f"Name '{full_name}' may match existing contact(s): {', '.join(a['contact_id'] for a in ambiguous)}",
                "confidence": enrichment.get("confidence", 0.5),
                "approval_hash": approval_hash,
            })

        # Low confidence check
        confidence = enrichment.get("confidence", 1.0)
        if confidence < CONFIDENCE_THRESHOLD:
            pending_staging_rows.append({
                "contact_id": contact_id,
                "master_id": existing["master_id"] if existing else master_id,
                "source": latest["source"],
                "source_message_pk": latest["message_pk"],
                "reason_type": "low_confidence",
                "proposed_changes": {"confidence": confidence, "verification_status": "verified"},
                "existing_snapshot": {"confidence": existing["confidence"] if existing else None},
                "candidate_matches": [],
                "source_quote": "Enrichment confidence below threshold (< 0.6)",
                "confidence": confidence,
                "approval_hash": sha256_hash(f"low_confidence:{contact_id}:{latest['message_pk']}"),
            })

        staged_for_contact = len(pending_staging_rows)

        # Build master profile data
        master_data = {
            "master_id": master_id,
            "contact_id": contact_id,
            "full_name": full_name,
            "salutation": salutation,
            "role_title": enrichment.get("role_title", ""),
            "category": "customer",  # Default
            "personalization_level": "full",
            "org_id": f"org_{contact_id}",
            "org_name": enrichment.get("org_name", ""),
            "account_tier": "Standard Account",
            "city": city or "Jakarta",
            "timezone": tz,
            "tz_label": tz_label,
            "work_hours_local": "08:00-17:00",
            "jumatan_block_local": "11:30-13:00 (WIB & Local)",
            "after_hours_policy": "defer_next_workday_0800_local",
            "best_contact_window": best_window,
            "email": email_addr,
            "phone_wa": phone_wa,
            "telegram_handle": "",
            "preferred_channel": "whatsapp",
            "active_channels": active_channels,
            "total_messages_30d": total_30d,
            "total_messages_lifetime": len(msgs),
            "avg_response_delay_sec": None,
            "dominant_formality": dominant_formality,
            "sentiment_mix": sentiments,
            "top_intents": intents,
            "fleet_units": all_fleet,
            "open_complaints": complaints,
            "open_commitments": commitments,
            "consent_status": "granted",
            "confidence": confidence,
            "needs_review": confidence < CONFIDENCE_THRESHOLD,
            "verification_status": "staged_unverified" if staged_for_contact > 0 or confidence < CONFIDENCE_THRESHOLD else "verified",
            "field_provenance": field_provenance,
            "visible_to_roles": ["owner_rifat", "owner_andi"],
            "approval_hash": sha256_hash(f"master:{contact_id}:{full_name}"),
            "last_message_at": last_msg_date,
            "last_scraped_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        # Apply peer privacy if needed
        master_data = apply_peer_privacy(master_data)

        # Upsert into customer_master_profiles
        if existing:
            # Update existing
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.customer_master_profiles SET
                       full_name=%s, role_title=%s, org_name=%s,
                       city=%s, timezone=%s, tz_label=%s,
                       best_contact_window=%s,
                       email=%s, phone_wa=%s,
                       active_channels=%s,
                       total_messages_30d=%s, total_messages_lifetime=%s,
                       dominant_formality=%s, sentiment_mix=%s, top_intents=%s,
                       fleet_units=%s, open_complaints=%s, open_commitments=%s,
                       confidence=%s, needs_review=%s, verification_status=%s,
                       field_provenance=%s,
                       last_message_at=%s, last_scraped_at=NOW(), updated_at=NOW()
                       WHERE contact_id=%s""",
                    (master_data["full_name"], master_data["role_title"], master_data["org_name"],
                     master_data["city"], master_data["timezone"], master_data["tz_label"],
                     master_data["best_contact_window"],
                     master_data["email"], master_data["phone_wa"],
                     Json(master_data["active_channels"]),
                     master_data["total_messages_30d"], master_data["total_messages_lifetime"],
                     master_data["dominant_formality"], Json(master_data["sentiment_mix"]),
                     Json(master_data["top_intents"]),
                     Json(master_data["fleet_units"]),
                     Json(master_data["open_complaints"]),
                     Json(master_data["open_commitments"]),
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
                      p.open_commitments, p.verification_status, p.confidence
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
