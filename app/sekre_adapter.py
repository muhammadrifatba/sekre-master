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
                "org_name": org_name,
                "city": city,
                "tz_label": tz_label,
                "phone": phone,
                "email": email,
            },
            "what": {
                "subject": subject,
                "body": body_draft,
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
    prev_curr: str | None = None
    for idx, ev in enumerate(events):
        p_hash = str(ev.get("prev_hash") or "")
        c_hash = str(ev.get("curr_hash") or "")
        if idx > 0 and prev_curr is not None and p_hash != prev_curr:
            breaks.append(
                f"Chain break at event {ev.get('event_id', idx)}: prev_hash={p_hash[:12]} != expected {prev_curr[:12]}"
            )
        if not c_hash:
            breaks.append(f"Empty curr_hash at event {ev.get('event_id', idx)}")
        prev_curr = c_hash
    return {
        "valid": len(breaks) == 0,
        "total_events": len(events),
        "breaks": breaks,
    }


# ============================================================================
# Database-Backed Adapter Service Functions
# ============================================================================

def list_approval_requests(owner_key: str, limit: int = 50) -> dict[str, Any]:
    """Fetch `sekre_results` + `sekre_actions` enriched with `customer_master_profiles` v3."""
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

            # Load master profiles + organizations for lookup & clarify candidate matching
            cur.execute("SELECT * FROM public.customer_master_profiles")
            all_profiles = [dict(r) for r in cur.fetchall()]
            profiles_by_cid = {p["contact_id"]: p for p in all_profiles if p.get("contact_id")}

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
    Atomically edit + approve/reject a `sekre_actions` row, recompute canonical
    payload_hash & approval_hash, enforce revalidation_failed guard, sync
    `sekre_results.status`, and append to `sekre_audit`.
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

            # Revalidation guard (§5.2 & §10): editing an already-approved action triggers revalidation_failed
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

            new_status = "approved" if decision == "approve" else "rejected"
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
                parent_status = "approved" if any(s in ("approved", "queued", "executed", "handed_off") for s in statuses) else "rejected"
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

        return {
            "success": True,
            "request_id": request_id,
            "action_id": action_id,
            "status": new_status,
            "approval_hash": approval_hash,
            "payload_hash": new_payload_hash,
            "audit_event_id": event_id,
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
    """List approved/queued/handed_off actions from `sekre_actions` for `OutboxCountdown.tsx`."""
    from psycopg2.extras import RealDictCursor

    try:
        conn = profiler.get_connection()
        conditions = ["owner_key = %s", "status IN ('approved', 'queued', 'handed_off')"]
        params: list[Any] = [owner_key]
        if request_id:
            conditions.append("request_id = %s")
            params.append(request_id)

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
        conn.close()

        items = []
        for r in rows:
            ap = r.get("payload") or {}
            items.append({
                "outbox_id": f"obx_{r['action_id']}",
                "action_id": r["action_id"],
                "request_id": r["request_id"],
                "channel": normalize_channel(ap.get("channel") or ("whatsapp" if r["action_type"] == "wa_handoff" else "email")),
                "recipient_name": ap.get("recipient_name") or r["target_id"],
                "subject": ap.get("subject") or "",
                "body": ap.get("body_draft") or "",
                "status": r["status"],
                "approval_hash": r["approval_hash"],
                "updated_at": r["updated_at"].isoformat() if hasattr(r["updated_at"], "isoformat") else str(r["updated_at"]),
            })
        return {"success": True, "count": len(items), "items": items}
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "items": []}


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
        return {"success": False, "error": str(exc), "verification": {"valid": False, "breaks": [str(exc)]}, "events": []}


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
