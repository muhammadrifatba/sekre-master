"""
sekre_adapter.py — Approval Gate Adapter bridging Supabase `sekre_*` tables
(sekre_results, sekre_actions, sekre_audit, v_crm_complaint_draft_review)
with `customer_master_profiles` (v3) & `organizations` for the Hackathon Frontend.

Zero database schema changes required.
All endpoints are server-side JWT-scoped by `owner_key`.
"""
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BACKEND_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import master_profiler as profiler  # noqa: E402
from app.core.rules_engine import (  # noqa: E402
    build_wa_handoff_link,
    compute_scheduled_send_at,
    TZ_WIB,
)


# ============================================================================
# Canonical Hashing & Normalization Helpers
# ============================================================================

def canonical_sha256(data: Any) -> str:
    """Canonical JSON SHA-256 compatible with sekre.pilot.serializer.sha256_hex."""
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def normalize_channel(channel: str | None) -> str:
    ch = str(channel or "").strip().lower()
    if ch in ("wa", "whatsapp"):
        return "whatsapp"
    if ch == "email":
        return "email"
    return ch or "whatsapp"


def resolve_sekre_owner_key(current_owner: dict[str, Any] | None = None, explicit_owner_key: str = "") -> str:
    """Map authenticated JWT owner to the sekre_* `owner_key`."""
    if explicit_owner_key:
        return explicit_owner_key.strip()
    if current_owner and current_owner.get("sekre_owner_key"):
        return str(current_owner["sekre_owner_key"]).strip()
    return os.environ.get("DEFAULT_SEKRE_OWNER_KEY", "owner_demo").strip() or "owner_demo"


def _compute_proposed_friday_slots(tz_label: str = "WIB", now_utc: datetime | None = None) -> list[str]:
    """Generate 2 safe Friday contact slots outside Jumatan (11:30-13:00 local)."""
    ref = now_utc or datetime.now(timezone.utc)
    days_until_friday = (4 - ref.weekday()) % 7
    target_friday = (ref + timedelta(days=days_until_friday)).date().isoformat()
    return [
        f"{target_friday} 09:00 {tz_label}",
        f"{target_friday} 13:30 {tz_label}",
    ]


# ============================================================================
# Pure Transformation Builders (Unit-Testable Without DB)
# ============================================================================

def build_customer_context_snapshot(
    profile: dict[str, Any] | None,
    org_news: list[dict[str, Any]] | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """
    Build the `CustomerContextPanel.tsx` snapshot from `customer_master_profiles` (v3)
    + `organizations.organization_news`. Strictly enforces TR-10 peer privacy.
    """
    if not profile:
        return {}

    now_iso = (now_utc or datetime.now(timezone.utc)).isoformat()
    category = str(profile.get("category") or "customer").lower()
    tz_label = profile.get("tz_label") or "WIB"
    work_hours = profile.get("work_hours_local") or "08:00-17:00"

    if category == "peer":
        return {
            "contact_id": profile.get("contact_id", ""),
            "master_id": profile.get("master_id", ""),
            "snapshot_at": now_iso,
            "category": "peer",
            "personalization_level": "timing_only",
            "org_name": profile.get("org_name", ""),
            "city": profile.get("city", ""),
            "tz_label": tz_label,
            "work_hours": work_hours,
            "relationship_signals": [],
            "commitments": [],
            "company_news": [],
            "agent_brief": "",
        }

    # Map open_complaints -> relationship_signals
    signals = []
    for idx, comp in enumerate(profile.get("open_complaints") or [], start=1):
        summary = comp.get("text") if isinstance(comp, dict) else str(comp)
        if summary:
            signals.append({"signal_id": f"sig-{idx}", "summary": summary})

    # Map relationship_health.open_promises (fallback open_commitments) -> commitments
    rel_health = profile.get("relationship_health") or {}
    promises = rel_health.get("open_promises") or []
    commitments = []
    if promises:
        for idx, p in enumerate(promises, start=1):
            if isinstance(p, dict) and p.get("status") != "resolved" and p.get("item"):
                commitments.append({
                    "commitment_id": f"com-{idx}",
                    "description": p["item"],
                    "due_date": p.get("due_date") or "",
                    "owner": p.get("owner") or "us",
                    "status": p.get("status") or "open",
                })
    else:
        for idx, c in enumerate(profile.get("open_commitments") or [], start=1):
            desc = c.get("text") if isinstance(c, dict) else str(c)
            if desc:
                commitments.append({
                    "commitment_id": f"com-{idx}",
                    "description": desc,
                    "due_date": "",
                    "owner": "us",
                    "status": "open",
                })

    # Map organizations.organization_news -> company_news
    news_items = []
    for idx, n in enumerate(org_news or [], start=1):
        if isinstance(n, dict) and n.get("headline"):
            news_items.append({
                "news_id": f"news-{idx}",
                "headline": n["headline"],
                "summary": n.get("summary") or n.get("date") or "",
            })

    return {
        "contact_id": profile.get("contact_id", ""),
        "master_id": profile.get("master_id", ""),
        "snapshot_at": now_iso,
        "category": "customer",
        "personalization_level": profile.get("personalization_level") or "full",
        "org_name": profile.get("org_name", ""),
        "city": profile.get("city", ""),
        "tz_label": tz_label,
        "work_hours": work_hours,
        "character_style": profile.get("character_style") or "unknown",
        "churn_risk_level": profile.get("churn_risk_level") or "low",
        "agent_brief": profile.get("agent_brief") or "",
        "relationship_signals": signals,
        "commitments": commitments,
        "company_news": news_items,
    }


def _match_candidate_profiles(query_text: str, all_profiles: list[dict[str, Any]], now_utc: datetime | None = None) -> list[dict[str, Any]]:
    """Find candidate contacts from customer_master_profiles for a recipient ambiguity."""
    q = (query_text or "").lower()
    if not q or not all_profiles:
        return []
    matches = []
    for prof in all_profiles:
        full_name = str(prof.get("full_name") or "").strip()
        first_token = full_name.lower().split()[0] if full_name else ""
        if full_name and (full_name.lower() in q or (len(first_token) >= 3 and first_token in q)):
            tz_label = prof.get("tz_label") or "WIB"
            matches.append({
                "contact_id": prof.get("contact_id", ""),
                "name": full_name,
                "unit": prof.get("role_title") or prof.get("account_tier") or "",
                "org_name": prof.get("org_name") or "",
                "city": prof.get("city") or "",
                "tz_label": tz_label,
                "phone": prof.get("phone_wa") or "",
                "email": prof.get("email") or "",
                "proposed_friday_slots": _compute_proposed_friday_slots(tz_label, now_utc),
            })
    return matches[:5]


def build_request_card(
    result_row: dict[str, Any],
    actions_rows: list[dict[str, Any]],
    profiles_by_cid: dict[str, dict[str, Any]],
    org_news_by_org: dict[str, list[dict[str, Any]]] | None = None,
    all_profiles: list[dict[str, Any]] | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """
    Transform 1 `sekre_results` row + its `sekre_actions` rows (with §5.3 UNION
    fallback to `payload.message_drafts`) + `customer_master_profiles` v3 into
    the exact JSON shape consumed by the Hackathon Frontend (`page.tsx`).
    """
    org_news_by_org = org_news_by_org or {}
    payload = result_row.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}

    request_id = result_row["request_id"]
    status = str(result_row.get("status") or "needs_clarify")
    source_summary = str(result_row.get("source_summary") or payload.get("source_summary") or "")
    source_refs = list(result_row.get("source_refs") or payload.get("source_refs") or [])
    payload_hash = str(result_row.get("payload_hash") or "")

    # Merge sekre_actions (for send_email / wa_handoff / flag_crm_complaint) + §5.3 payload.message_drafts
    plan_actions: list[dict[str, Any]] = []
    customer_context_map: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    seen_draft_ids: set[str] = set()

    def _build_action_obj(
        action_id: str,
        action_type: str,
        channel_raw: str,
        target_id: str,
        recipient_name: str,
        subject: str,
        body_draft: str,
        action_status: str,
        risk_tier: str,
        idempotency_key: str,
        draft_id: str,
        approval_hash: str,
        act_payload_hash: str,
    ) -> dict[str, Any]:
        channel = normalize_channel(channel_raw)
        prof = profiles_by_cid.get(target_id)
        tz_iana = (prof.get("timezone") if prof else None) or TZ_WIB
        tz_label = (prof.get("tz_label") if prof else None) or "WIB"
        phone = (prof.get("phone_wa") if prof else "") or ""
        email = (prof.get("email") if prof else "") or ""
        org_name = (prof.get("org_name") if prof else "") or ""
        city = (prof.get("city") if prof else "") or ""
        display_name = recipient_name or (prof.get("full_name") if prof else "") or target_id or "Penerima"

        sched_dt, rule_applied = compute_scheduled_send_at(tz_iana, now_utc=now_utc)
        wa_link = build_wa_handoff_link(phone, body_draft) if (channel == "whatsapp" and phone) else ""

        if rule_applied != "IMMEDIATE_WITHIN_HOURS":
            findings.append({
                "finding_id": f"fnd_{action_id}_tz",
                "action_id": action_id,
                "check_type": "timezone_deferral",
                "severity": "info",
                "message": f"Jadwal pengiriman disesuaikan ({tz_label}, {rule_applied}).",
            })

        if prof:
            org_news = org_news_by_org.get(prof.get("org_id", ""), [])
            customer_context_map[action_id] = build_customer_context_snapshot(prof, org_news=org_news, now_utc=now_utc)

        return {
            "action_id": action_id,
            "draft_id": draft_id,
            "action_type": action_type,
            "channel": channel,
            "risk_tier": risk_tier or "medium",
            "status": action_status,
            "idempotency_key": idempotency_key,
            "approval_hash": approval_hash,
            "payload_hash": act_payload_hash,
            "who": {
                "contact_id": target_id,
                "name": display_name,
                "category": (prof.get("category") if prof else None) or "customer",
                "org_name": org_name,
                "city": city,
                "tz_label": tz_label,
                "phone": phone,
                "email": email,
            },
            "what": {
                "subject": subject,
                "body": body_draft,
                "body_draft": body_draft,
            },
            "when": {
                "scheduled_send_at": sched_dt.isoformat(),
                "rule_applied": rule_applied,
            },
            "wa_handoff_link": wa_link,
        }

    # 1) Include sekre_actions rows (send_email, wa_handoff, flag_crm_complaint)
    for act in actions_rows:
        act_type = str(act.get("action_type") or "")
        if act_type not in ("send_email", "wa_handoff", "flag_crm_complaint"):
            continue
        ap = act.get("payload") or {}
        if isinstance(ap, str):
            try:
                ap = json.loads(ap)
            except Exception:
                ap = {}
        draft_id = str(ap.get("draft_id") or act["action_id"])
        seen_draft_ids.add(draft_id)
        ch = "crm" if act_type == "flag_crm_complaint" else (ap.get("channel") or ("whatsapp" if act_type == "wa_handoff" else "email"))
        plan_actions.append(
            _build_action_obj(
                action_id=act["action_id"],
                action_type=act_type,
                channel_raw=ch,
                target_id=str(act.get("target_id") or ""),
                recipient_name=str(ap.get("recipient_name") or ""),
                subject=str(ap.get("subject") or ""),
                body_draft=str(ap.get("body_draft") or ap.get("body") or ""),
                action_status=str(act.get("status") or "awaiting_approval"),
                risk_tier=str(act.get("risk_tier") or "medium"),
                idempotency_key=str(act.get("idempotency_key") or ""),
                draft_id=draft_id,
                approval_hash=str(act.get("approval_hash") or ""),
                act_payload_hash=str(act.get("payload_hash") or ""),
            )
        )

    # 2) UNION §5.3: include any payload.message_drafts not yet attached to sekre_actions (read-only preview)
    raw_drafts = payload.get("message_drafts")
    if isinstance(raw_drafts, list):
        for idx, d in enumerate(raw_drafts, start=1):
            if not isinstance(d, dict):
                continue
            draft_id = str(d.get("draft_id") or f"draft_{request_id}_{idx}")
            if draft_id in seen_draft_ids:
                continue
            seen_draft_ids.add(draft_id)
            ch = normalize_channel(d.get("channel"))
            plan_actions.append(
                _build_action_obj(
                    action_id=f"preview_{draft_id}",
                    action_type="wa_handoff" if ch == "whatsapp" else "send_email",
                    channel_raw=ch,
                    target_id=str(d.get("target_id") or ""),
                    recipient_name=str(d.get("recipient_name") or ""),
                    subject=str(d.get("subject") or ""),
                    body_draft=str(d.get("body_draft") or d.get("body") or ""),
                    action_status="held_needs_clarify" if status == "needs_clarify" else "awaiting_approval",
                    risk_tier=str(d.get("risk_tier") or "medium"),
                    idempotency_key="",
                    draft_id=draft_id,
                    approval_hash="",
                    act_payload_hash=canonical_sha256(d),
                )
            )

    # Map injection_findings -> injection_flags
    injection_flags = []
    for idx, flg in enumerate(payload.get("injection_findings") or [], start=1):
        if isinstance(flg, dict):
            injection_flags.append({
                "flag_id": str(flg.get("flag_id") or flg.get("id") or f"inj-{idx}"),
                "offending_excerpt": str(flg.get("offending_excerpt") or flg.get("match") or flg.get("excerpt") or flg.get("description") or flg),
            })
        else:
            injection_flags.append({"flag_id": f"inj-{idx}", "offending_excerpt": str(flg)})

    # Build ambiguities with candidate lookup for CLARIFY modal
    enriched_ambiguities = []
    for amb in (payload.get("ambiguities") or []):
        if not isinstance(amb, dict):
            continue
        amb_copy = dict(amb)
        if not amb_copy.get("candidates") and amb_copy.get("field") == "recipient" and all_profiles:
            query_str = f"{amb_copy.get('description', '')} {amb_copy.get('clarification_question', '')}"
            amb_copy["candidates"] = _match_candidate_profiles(query_str, all_profiles, now_utc=now_utc)
        enriched_ambiguities.append(amb_copy)

    # Determine interrupt object for FE Hackathon
    interrupt: dict[str, Any] | None = None
    if status == "needs_clarify":
        interrupt = {
            "type": "CLARIFY",
            "approval_hash": payload_hash,
            "ambiguities": enriched_ambiguities,
            "plan": {"actions": plan_actions},
        }
    elif status in ("awaiting_approval", "revalidation_failed"):
        interrupt = {
            "type": "APPROVAL",
            "approval_hash": payload_hash,
            "plan": {"actions": plan_actions},
        }

    created_at = result_row.get("created_at")
    updated_at = result_row.get("updated_at")
    return {
        "request_id": request_id,
        "owner_key": result_row.get("owner_key", ""),
        "run_id": result_row.get("run_id"),
        "status": status,
        "source_refs": source_refs,
        "payload_hash": payload_hash,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or ""),
        "updated_at": updated_at.isoformat() if hasattr(updated_at, "isoformat") else str(updated_at or ""),
        "interrupt": interrupt,
        "state": {
            "raw_input": source_summary,
            "plan": {"actions": plan_actions},
            "findings": findings,
            "injection_flags": injection_flags,
            "customer_context": customer_context_map,
            "todo_items": payload.get("todo_items") or [],
            "commitments": payload.get("commitments") or [],
            "follow_up_items": payload.get("follow_up_items") or [],
            "ambiguities": enriched_ambiguities,
        },
    }


def verify_sekre_audit_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify prev_hash -> curr_hash continuity across chronological `sekre_audit` rows."""
    breaks: list[str] = []
    # Re-order tied timestamps by following prev_hash -> curr_hash links so same-ms inserts
    # don't produce false-positive chain breaks.
    ordered = list(events)
    if len(ordered) > 1:
        by_prev: dict[str, list[dict[str, Any]]] = {}
        for ev in ordered:
            by_prev.setdefault(str(ev.get("prev_hash") or ""), []).append(ev)
        # Walk from genesis ("0"*64) or first event if a clean chain exists
        genesis_key = "0" * 64
        start_prev = genesis_key if genesis_key in by_prev else str(ordered[0].get("prev_hash") or "")
        walked: list[dict[str, Any]] = []
        visited_ids: set[int] = set()
        curr_prev = start_prev
        while curr_prev in by_prev:
            nxt = None
            for cand in by_prev[curr_prev]:
                if id(cand) not in visited_ids:
                    nxt = cand
                    break
            if nxt is None:
                break
            visited_ids.add(id(nxt))
            walked.append(nxt)
            curr_prev = str(nxt.get("curr_hash") or "")
        if len(walked) == len(ordered):
            ordered = walked

    prev_curr: str | None = None
    for idx, ev in enumerate(ordered):
        p_hash = str(ev.get("prev_hash") or "")
        c_hash = str(ev.get("curr_hash") or "")
        if idx > 0 and prev_curr is not None and p_hash != prev_curr:
            breaks.append(
                f"Chain break at event {ev.get('event_id', idx)}: prev_hash={p_hash[:12]} != expected {prev_curr[:12]}"
            )
        if not c_hash:
            breaks.append(f"Empty curr_hash at event {ev.get('event_id', idx)}")
        prev_curr = c_hash
    is_valid = len(breaks) == 0
    reason_text = "" if is_valid else "; ".join(breaks)
    return {
        "valid": is_valid,
        "total_events": len(ordered),
        "head_hash": prev_curr or ("0" * 64),
        "breaks": breaks,
        "reason": reason_text,
        "message": "Rantai hash audit terverifikasi utuh." if is_valid else reason_text,
    }


# ============================================================================
# Database-Backed Adapter Service Functions
# ============================================================================

def _tz_label_from_iana(tz_iana: str | None) -> str:
    tz = str(tz_iana or "").strip()
    if tz == "Asia/Makassar":
        return "WITA"
    if tz == "Asia/Jayapura":
        return "WIT"
    return "WIB"


def _load_merged_profiles(cur, owner_key: str) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """
    Load `customer_master_profiles` and merge with `sekre_profiles` + `sekre_contact_channels`
    so contacts defined in the Sekre pilot tables (e.g. `c_andi`) resolve email, phone, and category.
    """
    cur.execute("SELECT * FROM public.customer_master_profiles")
    all_profiles = [dict(r) for r in cur.fetchall()]
    profiles_by_cid: dict[str, dict[str, Any]] = {
        p["contact_id"]: p for p in all_profiles if p.get("contact_id")
    }

    # Merge public.sekre_profiles (guarded by SAVEPOINT so missing table never aborts tx)
    try:
        cur.execute("SAVEPOINT sp_sekre_profiles")
        cur.execute(
            """SELECT contact_id, org_id, display_name, category, personalization_level,
                      role_title, city, timezone, tz_label, work_hours_local
               FROM public.sekre_profiles
               WHERE owner_key = %s""",
            (owner_key,),
        )
        for sp in cur.fetchall():
            cid = sp.get("contact_id")
            if not cid:
                continue
            tz_iana = sp.get("timezone") or TZ_WIB
            tz_lbl = sp.get("tz_label") or _tz_label_from_iana(tz_iana)
            if cid not in profiles_by_cid:
                merged = {
                    "contact_id": cid,
                    "master_id": f"sekre_{cid}",
                    "full_name": sp.get("display_name") or cid,
                    "category": sp.get("category") or "customer",
                    "personalization_level": sp.get("personalization_level") or "full",
                    "org_id": sp.get("org_id") or "",
                    "org_name": "",
                    "role_title": sp.get("role_title") or "",
                    "city": sp.get("city") or "",
                    "timezone": tz_iana,
                    "tz_label": tz_lbl,
                    "work_hours_local": sp.get("work_hours_local") or "08:00-17:00",
                    "email": "",
                    "phone_wa": "",
                }
                profiles_by_cid[cid] = merged
                all_profiles.append(merged)
            else:
                existing = profiles_by_cid[cid]
                if not existing.get("category") and sp.get("category"):
                    existing["category"] = sp["category"]
                if not existing.get("full_name") and sp.get("display_name"):
                    existing["full_name"] = sp["display_name"]
        cur.execute("RELEASE SAVEPOINT sp_sekre_profiles")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_sekre_profiles")

    # Merge public.sekre_contact_channels (email / whatsapp addresses)
    try:
        cur.execute("SAVEPOINT sp_sekre_channels")
        cur.execute(
            """SELECT contact_id, channel, address_normalized
               FROM public.sekre_contact_channels
               WHERE owner_key = %s""",
            (owner_key,),
        )
        for ch_row in cur.fetchall():
            cid = ch_row.get("contact_id")
            addr = str(ch_row.get("address_normalized") or "").strip()
            ch = normalize_channel(ch_row.get("channel"))
            if not cid or not addr:
                continue
            if cid not in profiles_by_cid:
                stub = {
                    "contact_id": cid,
                    "master_id": f"sekre_{cid}",
                    "full_name": cid,
                    "category": "customer",
                    "personalization_level": "full",
                    "org_id": "",
                    "org_name": "",
                    "role_title": "",
                    "city": "",
                    "timezone": TZ_WIB,
                    "tz_label": "WIB",
                    "work_hours_local": "08:00-17:00",
                    "email": "",
                    "phone_wa": "",
                }
                profiles_by_cid[cid] = stub
                all_profiles.append(stub)
            prof = profiles_by_cid[cid]
            if ch == "email" and not prof.get("email"):
                prof["email"] = addr
            elif ch == "whatsapp" and not prof.get("phone_wa"):
                prof["phone_wa"] = addr
        cur.execute("RELEASE SAVEPOINT sp_sekre_channels")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_sekre_channels")

    return all_profiles, profiles_by_cid


def list_approval_requests(owner_key: str, limit: int = 50) -> dict[str, Any]:
    """Fetch `sekre_results` + `sekre_actions` enriched with `customer_master_profiles` & `sekre_profiles`."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT request_id, owner_key, run_id, status, source_summary,
                          source_refs, payload, payload_hash, created_at, updated_at
                   FROM public.sekre_results
                   WHERE owner_key = %s
                   ORDER BY created_at DESC
                   LIMIT %s""",
                (owner_key, limit),
            )
            result_rows = cur.fetchall()

            request_ids = [r["request_id"] for r in result_rows]
            actions_by_req: dict[str, list[dict[str, Any]]] = {}
            if request_ids:
                cur.execute(
                    """SELECT action_id, owner_key, request_id, run_id, action_type,
                              target_type, target_id, status, idempotency_key,
                              approval_hash, risk_tier, payload, payload_hash,
                              created_at, updated_at
                       FROM public.sekre_actions
                       WHERE owner_key = %s AND request_id = ANY(%s)
                       ORDER BY created_at ASC""",
                    (owner_key, request_ids),
                )
                for act in cur.fetchall():
                    actions_by_req.setdefault(act["request_id"], []).append(dict(act))

            all_profiles, profiles_by_cid = _load_merged_profiles(cur, owner_key)

            cur.execute("SELECT org_id, organization_news FROM public.organizations")
            org_news_by_org = {
                r["org_id"]: (r["organization_news"] or [])
                for r in cur.fetchall()
            }
        conn.close()

        cards = [
            build_request_card(
                result_row=dict(r),
                actions_rows=actions_by_req.get(r["request_id"], []),
                profiles_by_cid=profiles_by_cid,
                org_news_by_org=org_news_by_org,
                all_profiles=all_profiles,
            )
            for r in result_rows
        ]
        return {
            "success": True,
            "owner_key": owner_key,
            "count": len(cards),
            "requests": cards,
        }
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "requests": []}


def get_approval_request_by_id(owner_key: str, request_id: str) -> dict[str, Any] | None:
    """Fetch a single enriched `sekre_results` card by request_id."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT request_id, owner_key, run_id, status, source_summary,
                          source_refs, payload, payload_hash, created_at, updated_at
                   FROM public.sekre_results
                   WHERE owner_key = %s AND request_id = %s
                   LIMIT 1""",
                (owner_key, request_id),
            )
            row = cur.fetchone()
            if not row:
                conn.close()
                return None

            cur.execute(
                """SELECT action_id, owner_key, request_id, run_id, action_type,
                          target_type, target_id, status, idempotency_key,
                          approval_hash, risk_tier, payload, payload_hash,
                          created_at, updated_at
                   FROM public.sekre_actions
                   WHERE owner_key = %s AND request_id = %s
                   ORDER BY created_at ASC""",
                (owner_key, request_id),
            )
            actions_rows = [dict(a) for a in cur.fetchall()]
            all_profiles, profiles_by_cid = _load_merged_profiles(cur, owner_key)

            cur.execute("SELECT org_id, organization_news FROM public.organizations")
            org_news_by_org = {
                r["org_id"]: (r["organization_news"] or [])
                for r in cur.fetchall()
            }
        conn.close()
        return build_request_card(
            result_row=dict(row),
            actions_rows=actions_rows,
            profiles_by_cid=profiles_by_cid,
            org_news_by_org=org_news_by_org,
            all_profiles=all_profiles,
        )
    except (Exception, SystemExit):  # noqa: BLE001
        return None


def list_contacts(owner_key: str) -> dict[str, Any]:
    """List merged contacts from `customer_master_profiles` and `sekre_profiles`/`sekre_contact_channels`."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            all_profiles, _ = _load_merged_profiles(cur, owner_key)
        conn.close()

        contacts = [
            {
                "contact_id": p.get("contact_id", ""),
                "name": p.get("full_name") or p.get("contact_id", ""),
                "category": p.get("category") or "customer",
                "org_name": p.get("org_name") or "",
                "unit": p.get("role_title") or "",
                "city": p.get("city") or "",
                "tz_label": p.get("tz_label") or _tz_label_from_iana(p.get("timezone")),
                "email": p.get("email") or "",
                "phone": p.get("phone_wa") or "",
            }
            for p in all_profiles
        ]
        return {"success": True, "count": len(contacts), "contacts": contacts}
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "contacts": []}


def get_latest_approval_request(owner_key: str) -> dict[str, Any]:
    res = list_approval_requests(owner_key=owner_key, limit=1)
    if not res.get("success") or not res.get("requests"):
        return {"status": "unknown", "request_id": None}
    return res["requests"][0]


def _append_sekre_audit(
    cur,
    owner_key: str,
    request_id: str,
    run_id: str,
    event_type: str,
    payload_json: dict[str, Any],
) -> str:
    """Append a hash-chained event to public.sekre_audit (append-only §7)."""
    cur.execute(
        """SELECT curr_hash FROM public.sekre_audit
           WHERE owner_key = %s
           ORDER BY created_at DESC LIMIT 1""",
        (owner_key,),
    )
    row = cur.fetchone()
    prev_hash = (row["curr_hash"] if row and row.get("curr_hash") else ("0" * 64))
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    event_body = {
        "event_id": event_id,
        "owner_key": owner_key,
        "request_id": request_id,
        "run_id": run_id or "",
        "event_type": event_type,
        "payload_json": payload_json,
    }
    curr_hash = canonical_sha256([prev_hash, event_body])
    from psycopg2.extras import Json

    cur.execute(
        """INSERT INTO public.sekre_audit
           (event_id, owner_key, request_id, run_id, event_type, payload_json, prev_hash, curr_hash)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (event_id, owner_key, request_id, run_id or "", event_type, Json(payload_json), prev_hash, curr_hash),
    )
    return event_id


OUTBOX_UNDO_WINDOW_SECONDS = 60


def _as_utc(dt: Any) -> datetime:
    if isinstance(dt, datetime):
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    if isinstance(dt, str) and dt:
        try:
            parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _resolve_recipient_contact(
    cur,
    target_id: str,
    payload: dict[str, Any],
    owner_key: str = "",
) -> tuple[str, str]:
    """Resolve recipient (email, phone) from payload, customer_master_profiles, or sekre_contact_channels."""
    email = str(payload.get("recipient_email") or payload.get("email") or "").strip()
    phone = str(payload.get("recipient_phone") or payload.get("phone") or "").strip()
    if (not email or not phone) and target_id:
        cur.execute(
            """SELECT email, phone_wa
               FROM public.customer_master_profiles
               WHERE contact_id = %s
               LIMIT 1""",
            (target_id,),
        )
        prof = cur.fetchone()
        if prof:
            if not email:
                email = str(prof.get("email") or "").strip()
            if not phone:
                phone = str(prof.get("phone_wa") or "").strip()

    if (not email or not phone) and target_id:
        try:
            cur.execute("SAVEPOINT sp_resolve_sekre_ch")
            if owner_key:
                cur.execute(
                    """SELECT channel, address_normalized
                       FROM public.sekre_contact_channels
                       WHERE owner_key = %s AND contact_id = %s""",
                    (owner_key, target_id),
                )
            else:
                cur.execute(
                    """SELECT channel, address_normalized
                       FROM public.sekre_contact_channels
                       WHERE contact_id = %s""",
                    (target_id,),
                )
            for row in cur.fetchall():
                ch = normalize_channel(row.get("channel"))
                addr = str(row.get("address_normalized") or "").strip()
                if ch == "email" and not email and addr:
                    email = addr
                elif ch == "whatsapp" and not phone and addr:
                    phone = addr
            cur.execute("RELEASE SAVEPOINT sp_resolve_sekre_ch")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT sp_resolve_sekre_ch")
    return email, phone


def approve_or_reject_action(
    owner_key: str,
    request_id: str,
    action_id: str,
    idempotency_key: str,
    decision: str,
    actor_owner_id: str,
    cognitive_confirmation: str = "",
    edited_subject: str | None = None,
    edited_body_draft: str | None = None,
) -> dict[str, Any]:
    """
    Atomically edit + approve/reject a `sekre_actions` row, validate recipient contact info,
    recompute canonical payload_hash & approval_hash, enforce revalidation_failed guard,
    queue `send_email` with a 60s safety undo window, sync `sekre_results.status`,
    and append to `sekre_audit`.
    """
    from psycopg2.extras import Json, RealDictCursor

    if decision not in ("approve", "reject"):
        return {"success": False, "status_code": 400, "error": "decision must be 'approve' or 'reject'"}

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM public.sekre_actions
                   WHERE owner_key = %s AND request_id = %s AND action_id = %s
                   FOR UPDATE""",
                (owner_key, request_id, action_id),
            )
            act = cur.fetchone()
            if not act:
                conn.close()
                return {"success": False, "status_code": 404, "error": f"Action '{action_id}' not found"}

            if idempotency_key and act["idempotency_key"] != idempotency_key:
                conn.close()
                return {"success": False, "status_code": 400, "error": "idempotency_key mismatch"}

            if decision == "approve" and act.get("risk_tier") == "high" and not (cognitive_confirmation or "").strip():
                conn.close()
                return {
                    "success": False,
                    "status_code": 400,
                    "error": "High-risk action requires cognitive_confirmation phrase",
                }

            payload = dict(act.get("payload") or {})
            old_hash = str(act.get("payload_hash") or canonical_sha256(payload))
            edited = False
            if edited_subject is not None and edited_subject != payload.get("subject"):
                payload["subject"] = edited_subject
                edited = True
            if edited_body_draft is not None and edited_body_draft != payload.get("body_draft"):
                payload["body_draft"] = edited_body_draft
                edited = True

            new_payload_hash = canonical_sha256(payload)

            # Revalidation guard (§5.2 & §10): editing an already-approved/queued action triggers revalidation_failed
            if act["status"] in ("approved", "queued") and new_payload_hash != old_hash:
                cur.execute(
                    """UPDATE public.sekre_actions
                       SET status = 'revalidation_failed', payload = %s, payload_hash = %s, updated_at = NOW()
                       WHERE owner_key = %s AND action_id = %s""",
                    (Json(payload), new_payload_hash, owner_key, action_id),
                )
                cur.execute(
                    """UPDATE public.sekre_results
                       SET status = 'revalidation_failed', updated_at = NOW()
                       WHERE owner_key = %s AND request_id = %s""",
                    (owner_key, request_id),
                )
                _append_sekre_audit(
                    cur, owner_key, request_id, str(act.get("run_id") or ""),
                    "action_revalidation_failed",
                    {"action_id": action_id, "actor": actor_owner_id, "old_hash": old_hash, "new_hash": new_payload_hash},
                )
                conn.commit()
                conn.close()
                return {
                    "success": False,
                    "status_code": 409,
                    "revalidation_failed": True,
                    "error": "Material changed after prior approval — marked revalidation_failed; new approval required.",
                }

            # Idempotent retry guard: prevent duplicate approval writes/audit spam on double-click
            if decision == "approve" and act["status"] in ("queued", "approved", "executed", "handed_off"):
                now_utc = datetime.now(timezone.utc)
                updated_dt = _as_utc(act.get("updated_at"))
                send_after_dt = updated_dt + timedelta(seconds=OUTBOX_UNDO_WINDOW_SECONDS)
                remaining = max(0, int((send_after_dt - now_utc).total_seconds())) if act["status"] == "queued" else 0
                conn.close()
                return {
                    "success": True,
                    "already_processed": True,
                    "request_id": request_id,
                    "action_id": action_id,
                    "status": act["status"],
                    "approval_hash": str(act.get("approval_hash") or ""),
                    "payload_hash": old_hash,
                    "send_after": send_after_dt.isoformat() if act["status"] == "queued" else None,
                    "cancel_until": send_after_dt.isoformat() if act["status"] == "queued" else None,
                    "remaining_seconds": remaining,
                    "can_cancel": act["status"] == "queued" and remaining > 0,
                }

            # Recipient destination validation before allowing approval
            act_type = str(act.get("action_type") or "")
            if decision == "approve":
                rec_email, rec_phone = _resolve_recipient_contact(
                    cur, str(act.get("target_id") or ""), payload, owner_key=owner_key
                )
                if act_type == "send_email" and not rec_email:
                    conn.close()
                    return {
                        "success": False,
                        "status_code": 400,
                        "error": "Alamat email penerima belum tersedia. Lengkapi alamat email tujuan sebelum menyetujui pengiriman.",
                    }
                if act_type == "wa_handoff" and not rec_phone:
                    conn.close()
                    return {
                        "success": False,
                        "status_code": 400,
                        "error": "Nomor WhatsApp penerima belum tersedia. Lengkapi nomor WA tujuan sebelum menyetujui pengiriman.",
                    }

            now_utc = datetime.now(timezone.utc)
            if decision == "approve":
                # Email actions enter the 60-second safety undo queue (`queued`) before finalization
                new_status = "queued" if act_type == "send_email" else "approved"
            else:
                new_status = "rejected"

            approval_hash = (
                canonical_sha256({"action_id": action_id, "payload_hash": new_payload_hash, "owner_key": owner_key, "actor": actor_owner_id})
                if decision == "approve"
                else ""
            )

            cur.execute(
                """UPDATE public.sekre_actions
                   SET status = %s, payload = %s, payload_hash = %s, approval_hash = %s, updated_at = NOW()
                   WHERE owner_key = %s AND action_id = %s""",
                (new_status, Json(payload), new_payload_hash, approval_hash, owner_key, action_id),
            )

            # Sync parent sekre_results status if no awaiting_approval actions remain
            cur.execute(
                """SELECT status FROM public.sekre_actions
                   WHERE owner_key = %s AND request_id = %s""",
                (owner_key, request_id),
            )
            statuses = [r["status"] for r in cur.fetchall()]
            if statuses and "awaiting_approval" not in statuses:
                if "queued" in statuses:
                    parent_status = "queued"
                elif any(s in ("approved", "executed", "handed_off") for s in statuses):
                    parent_status = "approved"
                else:
                    parent_status = "rejected"
                cur.execute(
                    """UPDATE public.sekre_results
                       SET status = %s, updated_at = NOW()
                       WHERE owner_key = %s AND request_id = %s""",
                    (parent_status, owner_key, request_id),
                )

            event_id = _append_sekre_audit(
                cur, owner_key, request_id, str(act.get("run_id") or ""),
                f"action_{new_status}",
                {
                    "action_id": action_id,
                    "idempotency_key": act["idempotency_key"],
                    "actor": actor_owner_id,
                    "edited": edited,
                    "approval_hash": approval_hash,
                    "payload_hash": new_payload_hash,
                },
            )
        conn.commit()
        conn.close()

        send_after_iso = (now_utc + timedelta(seconds=OUTBOX_UNDO_WINDOW_SECONDS)).isoformat() if new_status == "queued" else None
        return {
            "success": True,
            "request_id": request_id,
            "action_id": action_id,
            "status": new_status,
            "approval_hash": approval_hash,
            "payload_hash": new_payload_hash,
            "audit_event_id": event_id,
            "send_after": send_after_iso,
            "cancel_until": send_after_iso,
            "remaining_seconds": OUTBOX_UNDO_WINDOW_SECONDS if new_status == "queued" else 0,
            "can_cancel": new_status == "queued",
        }
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "status_code": 500, "error": str(exc)}


def resolve_clarify(
    owner_key: str,
    request_id: str,
    contact_id: str,
    selected_slot: str,
    actor_owner_id: str,
) -> dict[str, Any]:
    """Record user clarification on a `needs_clarify` sekre_results row and append audit."""
    from psycopg2.extras import Json, RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM public.sekre_results
                   WHERE owner_key = %s AND request_id = %s
                   FOR UPDATE""",
                (owner_key, request_id),
            )
            row = cur.fetchone()
            if not row:
                conn.close()
                return {"success": False, "status_code": 404, "error": f"Request '{request_id}' not found"}

            payload = dict(row.get("payload") or {})
            payload["clarification_resolution"] = {
                "contact_id": contact_id,
                "selected_slot": selected_slot,
                "resolved_by": actor_owner_id,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            }
            new_hash = canonical_sha256(payload)
            cur.execute(
                """UPDATE public.sekre_results
                   SET status = 'awaiting_approval', payload = %s, payload_hash = %s, updated_at = NOW()
                   WHERE owner_key = %s AND request_id = %s""",
                (Json(payload), new_hash, owner_key, request_id),
            )
            event_id = _append_sekre_audit(
                cur, owner_key, request_id, str(row.get("run_id") or ""),
                "clarification_resolved",
                {"contact_id": contact_id, "selected_slot": selected_slot, "actor": actor_owner_id},
            )
        conn.commit()
        conn.close()
        return {
            "success": True,
            "request_id": request_id,
            "status": "awaiting_approval",
            "contact_id": contact_id,
            "selected_slot": selected_slot,
            "audit_event_id": event_id,
        }
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "status_code": 500, "error": str(exc)}


def list_outbox(owner_key: str, request_id: str = "") -> dict[str, Any]:
    """List approved/queued/handed_off actions from `sekre_actions` with 60s countdown metadata."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        conditions = ["owner_key = %s", "status IN ('approved', 'queued', 'handed_off')"]
        params: list[Any] = [owner_key]
        if request_id:
            conditions.append("request_id = %s")
            params.append(request_id)

        now_utc = datetime.now(timezone.utc)
        expired_action_ids: list[tuple[str, str]] = []

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""SELECT action_id, request_id, action_type, target_id, status,
                           risk_tier, payload, approval_hash, created_at, updated_at
                    FROM public.sekre_actions
                    WHERE {' AND '.join(conditions)}
                    ORDER BY updated_at DESC LIMIT 50""",
                params,
            )
            rows = cur.fetchall()

            items = []
            for r in rows:
                ap = r.get("payload") or {}
                updated_dt = _as_utc(r.get("updated_at"))
                send_after_dt = updated_dt + timedelta(seconds=OUTBOX_UNDO_WINDOW_SECONDS)
                db_status = str(r["status"])
                remaining = 0
                if db_status == "queued":
                    remaining = max(0, int((send_after_dt - now_utc).total_seconds()))
                    if remaining == 0:
                        db_status = "approved"
                        expired_action_ids.append((r["action_id"], r["request_id"]))

                # Map DB status to OutboxCountdown.tsx contract ('queued_outbox' | 'sent')
                ui_status = "queued_outbox" if (db_status == "queued" and remaining > 0) else "sent"
                rec_email, rec_phone = _resolve_recipient_contact(
                    cur, str(r.get("target_id") or ""), ap, owner_key=owner_key
                )
                channel = normalize_channel(ap.get("channel") or ("whatsapp" if r["action_type"] == "wa_handoff" else "email"))
                recipient_address = (
                    (rec_phone if channel == "whatsapp" else rec_email)
                    or rec_email
                    or rec_phone
                    or ap.get("recipient_name")
                    or r["target_id"]
                )
                items.append({
                    "outbox_id": f"obx_{r['action_id']}",
                    "action_id": r["action_id"],
                    "request_id": r["request_id"],
                    "channel": channel,
                    "recipient_name": ap.get("recipient_name") or r["target_id"],
                    "recipient_address": recipient_address,
                    "recipient_email": rec_email,
                    "subject": ap.get("subject") or "",
                    "body": ap.get("body_draft") or "",
                    "status": ui_status,
                    "db_status": db_status,
                    "approval_hash": r["approval_hash"],
                    "enqueued_at": updated_dt.isoformat(),
                    "queued_at": updated_dt.isoformat(),
                    "release_at": send_after_dt.isoformat(),
                    "send_after": send_after_dt.isoformat(),
                    "scheduled_send_at": send_after_dt.isoformat(),
                    "cancel_until": send_after_dt.isoformat(),
                    "remaining_seconds": remaining,
                    "countdown_seconds": remaining,
                    "can_cancel": ui_status == "queued_outbox",
                    "updated_at": updated_dt.isoformat(),
                })

            if expired_action_ids:
                for act_id, req_id in expired_action_ids:
                    cur.execute(
                        """UPDATE public.sekre_actions
                           SET status = 'approved'
                           WHERE owner_key = %s AND action_id = %s AND status = 'queued'""",
                        (owner_key, act_id),
                    )
                    cur.execute(
                        """UPDATE public.sekre_results
                           SET status = 'approved'
                           WHERE owner_key = %s AND request_id = %s AND status = 'queued'""",
                        (owner_key, req_id),
                    )
                conn.commit()
        conn.close()
        return {"success": True, "count": len(items), "items": items}
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "items": []}


def cancel_outbox_action(
    owner_key: str,
    action_id: str,
    actor_owner_id: str,
) -> dict[str, Any]:
    """Cancel a queued action during its 60-second safety window and revert to awaiting_approval."""
    from psycopg2.extras import RealDictCursor

    clean_action_id = str(action_id or "").strip()
    if clean_action_id.startswith("obx_"):
        clean_action_id = clean_action_id[4:]
    if not clean_action_id:
        return {"success": False, "status_code": 400, "error": "action_id is required"}

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM public.sekre_actions
                   WHERE owner_key = %s AND action_id = %s
                   FOR UPDATE""",
                (owner_key, clean_action_id),
            )
            act = cur.fetchone()
            if not act:
                conn.close()
                return {"success": False, "status_code": 404, "error": f"Outbox action '{clean_action_id}' not found"}

            if act["status"] != "queued":
                conn.close()
                return {
                    "success": False,
                    "status_code": 409,
                    "error": f"Pengiriman tidak dapat dibatalkan karena status saat ini '{act['status']}'.",
                }

            now_utc = datetime.now(timezone.utc)
            updated_dt = _as_utc(act.get("updated_at"))
            if (now_utc - updated_dt).total_seconds() >= OUTBOX_UNDO_WINDOW_SECONDS:
                cur.execute(
                    """UPDATE public.sekre_actions
                       SET status = 'approved'
                       WHERE owner_key = %s AND action_id = %s AND status = 'queued'""",
                    (owner_key, clean_action_id),
                )
                cur.execute(
                    """UPDATE public.sekre_results
                       SET status = 'approved'
                       WHERE owner_key = %s AND request_id = %s AND status = 'queued'""",
                    (owner_key, act["request_id"]),
                )
                conn.commit()
                conn.close()
                return {
                    "success": False,
                    "status_code": 409,
                    "error": "Waktu tunda pengaman 60 detik sudah habis; pengiriman tidak dapat dibatalkan.",
                }

            cur.execute(
                """UPDATE public.sekre_actions
                   SET status = 'awaiting_approval', approval_hash = '', updated_at = NOW()
                   WHERE owner_key = %s AND action_id = %s""",
                (owner_key, clean_action_id),
            )
            cur.execute(
                """UPDATE public.sekre_results
                   SET status = 'awaiting_approval', updated_at = NOW()
                   WHERE owner_key = %s AND request_id = %s""",
                (owner_key, act["request_id"]),
            )
            event_id = _append_sekre_audit(
                cur,
                owner_key,
                act["request_id"],
                str(act.get("run_id") or ""),
                "action_cancelled",
                {
                    "action_id": clean_action_id,
                    "actor": actor_owner_id,
                    "previous_status": "queued",
                },
            )
        conn.commit()
        conn.close()
        return {
            "success": True,
            "cancelled": True,
            "outbox_id": f"obx_{clean_action_id}",
            "action_id": clean_action_id,
            "request_id": act["request_id"],
            "status": "undone",
            "action_status": "awaiting_approval",
            "audit_event_id": event_id,
        }
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "status_code": 500, "error": str(exc)}


def verify_audit(owner_key: str, request_id: str = "") -> dict[str, Any]:
    """Verify hash-chain integrity on `public.sekre_audit` and return sanitized events."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT event_id, owner_key, request_id, run_id, event_type,
                          payload_json, prev_hash, curr_hash, created_at
                   FROM public.sekre_audit
                   WHERE owner_key = %s
                   ORDER BY created_at ASC""",
                (owner_key,),
            )
            all_events = [dict(r) for r in cur.fetchall()]
        conn.close()

        verification = verify_sekre_audit_chain(all_events)
        filtered = [e for e in all_events if not request_id or e.get("request_id") == request_id]
        serialized = [
            {
                "id": e["event_id"],
                "event_id": e["event_id"],
                "request_id": e.get("request_id", ""),
                "run_id": e.get("run_id", ""),
                "event_type": e["event_type"],
                "payload_json": e.get("payload_json") or {},
                "prev_hash": e.get("prev_hash", ""),
                "curr_hash": e.get("curr_hash", ""),
                "timestamp": e["created_at"].isoformat() if hasattr(e.get("created_at"), "isoformat") else str(e.get("created_at", "")),
            }
            for e in reversed(filtered[-100:])
        ]
        return {"success": True, "verification": verification, "events": serialized}
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": str(exc),
            "verification": {"valid": False, "total_events": 0, "breaks": [str(exc)], "reason": str(exc), "message": str(exc)},
            "events": [],
        }


def list_crm_complaints(owner_key: str, status: str = "") -> dict[str, Any]:
    """Fetch CRM complaint drafts from `public.v_crm_complaint_draft_review`."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        conditions = ["owner_key = %s"]
        params: list[Any] = [owner_key]
        if status:
            conditions.append("status = %s")
            params.append(status)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""SELECT owner_key, request_id, action_id, complaint_draft_id,
                           status, approval_hash, complaint_payload, payload_hash, created_at
                    FROM public.v_crm_complaint_draft_review
                    WHERE {' AND '.join(conditions)}
                    ORDER BY created_at DESC LIMIT 50""",
                params,
            )
            rows = cur.fetchall()
        conn.close()

        items = [
            {
                **{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in dict(r).items()}
            }
            for r in rows
        ]
        return {"success": True, "count": len(items), "items": items}
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "items": []}


def list_order_followups(owner_key: str, run_id: str = "") -> dict[str, Any]:
    """
    Fetch order follow-up items extracted from `sekre_results.payload->'order_drafts'`
    for the latest `run_id` (or a specific `run_id` if provided).
    """
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        if run_id:
            sql = """
                WITH rows_with_drafts AS (
                  SELECT r.request_id, r.run_id, r.payload->'order_drafts' AS order_drafts
                  FROM public.sekre_results r
                  WHERE r.owner_key = %s
                    AND r.run_id = %s
                    AND jsonb_typeof(r.payload->'order_drafts') = 'array'
                    AND COALESCE(jsonb_array_length(r.payload->'order_drafts'), 0) > 0
                ),
                one_draft AS (
                  SELECT DISTINCT ON (d.value->>'order_draft_id')
                         r.request_id,
                         r.run_id,
                         d.value->>'order_draft_id' AS order_draft_id,
                         d.value AS draft
                  FROM rows_with_drafts r
                  CROSS JOIN LATERAL jsonb_array_elements(r.order_drafts) d(value)
                  ORDER BY d.value->>'order_draft_id', r.request_id
                )
                SELECT o.request_id,
                       o.run_id,
                       o.order_draft_id,
                       o.draft->>'full_name'       AS nama_pemesan,
                       o.draft->>'org_name'        AS nama_customer,
                       o.draft->>'po_reference'    AS po_reference,
                       o.draft->>'due_date'        AS due_date,
                       so.value->>'so_id'          AS so_id,
                       so.value->>'status'         AS so_status,
                       so.value->>'billing_status' AS billing_status,
                       jsonb_agg(jsonb_build_object(
                         'item', li.value->>'item_name',
                         'qty',  li.value->>'quantity',
                         'unit', li.value->>'unit'
                       ) ORDER BY li.value->>'item_name') AS items
                FROM one_draft o
                CROSS JOIN LATERAL jsonb_array_elements(COALESCE(o.draft->'sales_orders', '[]'::jsonb)) so(value)
                CROSS JOIN LATERAL jsonb_array_elements(COALESCE(so.value->'line_items', '[]'::jsonb)) li(value)
                GROUP BY o.request_id, o.run_id, o.order_draft_id, o.draft, nama_pemesan, nama_customer,
                         po_reference, due_date, so_id, so_status, billing_status
                ORDER BY o.order_draft_id, so_id
            """
            params: tuple[Any, ...] = (owner_key, run_id)
        else:
            sql = """
                WITH latest AS (
                  SELECT run_id
                  FROM public.sekre_results
                  WHERE owner_key = %s
                  GROUP BY run_id
                  ORDER BY MAX(created_at) DESC
                  LIMIT 1
                ),
                rows_with_drafts AS (
                  SELECT r.request_id, r.run_id, r.payload->'order_drafts' AS order_drafts
                  FROM public.sekre_results r
                  JOIN latest l ON l.run_id = r.run_id
                  WHERE r.owner_key = %s
                    AND jsonb_typeof(r.payload->'order_drafts') = 'array'
                    AND COALESCE(jsonb_array_length(r.payload->'order_drafts'), 0) > 0
                ),
                one_draft AS (
                  SELECT DISTINCT ON (d.value->>'order_draft_id')
                         r.request_id,
                         r.run_id,
                         d.value->>'order_draft_id' AS order_draft_id,
                         d.value AS draft
                  FROM rows_with_drafts r
                  CROSS JOIN LATERAL jsonb_array_elements(r.order_drafts) d(value)
                  ORDER BY d.value->>'order_draft_id', r.request_id
                )
                SELECT o.request_id,
                       o.run_id,
                       o.order_draft_id,
                       o.draft->>'full_name'       AS nama_pemesan,
                       o.draft->>'org_name'        AS nama_customer,
                       o.draft->>'po_reference'    AS po_reference,
                       o.draft->>'due_date'        AS due_date,
                       so.value->>'so_id'          AS so_id,
                       so.value->>'status'         AS so_status,
                       so.value->>'billing_status' AS billing_status,
                       jsonb_agg(jsonb_build_object(
                         'item', li.value->>'item_name',
                         'qty',  li.value->>'quantity',
                         'unit', li.value->>'unit'
                       ) ORDER BY li.value->>'item_name') AS items
                FROM one_draft o
                CROSS JOIN LATERAL jsonb_array_elements(COALESCE(o.draft->'sales_orders', '[]'::jsonb)) so(value)
                CROSS JOIN LATERAL jsonb_array_elements(COALESCE(so.value->'line_items', '[]'::jsonb)) li(value)
                GROUP BY o.request_id, o.run_id, o.order_draft_id, o.draft, nama_pemesan, nama_customer,
                         po_reference, due_date, so_id, so_status, billing_status
                ORDER BY o.order_draft_id, so_id
            """
            params = (owner_key, owner_key)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        conn.close()

        items = [dict(r) for r in rows]
        resolved_run_id = items[0].get("run_id") if items else (run_id or None)
        return {
            "success": True,
            "owner_key": owner_key,
            "run_id": resolved_run_id,
            "count": len(items),
            "items": items,
        }
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "count": 0, "items": []}
