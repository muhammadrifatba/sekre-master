"""
main.py — FastAPI HTTP service for the Master Customer Profiler.

Run:
    uvicorn app.main:app --host 127.0.0.1 --port 8000
    (or: python backend/app/main.py)

Endpoints wrap app.services so the HTTP API and the WorkBuddy MCP server
share exactly the same pipeline logic.
"""
import os
import sys
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import mcp_server, sekre_adapter, services  # noqa: E402
from app.core.security import decode_access_token  # noqa: E402

app = FastAPI(
    title="WorkBuddy Master Customer Profiler API",
    description="Supabase-backed omni-channel customer master profiling pipeline for PT Nusantara Alat Berat",
    version="2.0.0",
)

# Allow localhost:3000, production sekre-v3.web.id, custom CORS_ORIGINS env var, and any *.vercel.app deployment
_extra_origins = [
    o.strip().rstrip("/") for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://sekre-v3.web.id",
        "https://www.sekre-v3.web.id",
        *_extra_origins,
    ],
    allow_origin_regex=r"https://.*\.vercel\.app|https://(www\.)?sekre-v3\.web\.id|http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Request models
# ============================================================================

class IngestRequest(BaseModel):
    source: str = Field(default="all", pattern="^(all|email|whatsapp|telegram)$")
    trigger: str = Field(default="scheduled", pattern="^(scheduled|manual)$")
    payloads: list[dict[str, Any]] | None = None
    feed_file: str | None = None
    owner: str = "owner_rifat"


class EnrichmentRequest(BaseModel):
    results: list[dict[str, Any]]
    version: str = "v2"
    model: str = "workbuddy-expert"
    owner: str = "owner_rifat"


class ApprovalRequest(BaseModel):
    staging_id: str | int
    decision: str = Field(default="approve", pattern="^(approve|reject)$")
    owner: str = "owner_rifat"
    approval_hash: str | None = None


class TicketPublishRequest(BaseModel):
    request_id: str | None = None
    owner_id: str = "owner_rifat"
    source_message_pk: int | None = None
    contact_id: str = ""
    source_channel: str = "whatsapp"
    raw_input: str = ""
    attachment_text: str = ""
    redacted_summary: str = ""
    action_type: str = "reply_customer"
    channel: str = Field(default="whatsapp", pattern="^(whatsapp|email|telegram|crm)$")
    channel_reason: str = ""
    subject: str = ""
    body_draft: str
    source_quote: str = ""
    risk_tier: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    is_ramadan: bool = False


class TicketApproveRequest(BaseModel):
    request_id: str
    decision: str = Field(default="approve", pattern="^(approve|reject)$")
    owner: str = "owner_rifat"
    approval_hash: str | None = None


class LoginRequest(BaseModel):
    identifier: str = Field(..., description="owner_id ('owner_rifat', 'owner_andi') or email")
    password: str = Field(..., min_length=1)


class ManualEnrichRequest(BaseModel):
    communication_prefs: dict[str, Any] | None = None
    character_profile: dict[str, Any] | None = None
    motivation_and_pain: dict[str, Any] | None = None
    persuasion_profile: dict[str, Any] | None = None
    relationship_health: dict[str, Any] | None = None
    character_style: str | None = Field(default=None, pattern="^(Driver|Analytical|Amiable|Expressive|unknown)$")
    churn_risk_level: str | None = Field(default=None, pattern="^(low|medium|high)$")
    owner: str = "owner_rifat"


class SekreApproveActionRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    idempotency_key: str = ""
    decision: str = Field(default="approve", pattern="^(approve|reject)$")
    cognitive_confirmation: str = ""
    edited_subject: str | None = None
    edited_body_draft: str | None = None


class SekreClarifyRequest(BaseModel):
    contact_id: str = Field(..., min_length=1)
    selected_slot: str = ""


class SekreApproveOrderRequest(BaseModel):
    order_draft_id: str = Field(..., min_length=1)
    decision: str = Field(default="approve", pattern="^(approve|reject)$")
    request_id: str = ""
    run_id: str = ""
    so_id: str = ""
    nama_pemesan: str = ""
    nama_customer: str = ""
    po_reference: str = ""
    due_date: str = ""
    so_status: str = "processing"
    billing_status: str = "pending_invoice"
    items: list[dict[str, Any]] = Field(default_factory=list)
    notes: str = ""


class SekreCancelOutboxRequest(BaseModel):
    action_id: str = ""
    outbox_id: str = ""


# ============================================================================
# JWT Authentication Helpers
# ============================================================================

def get_optional_current_owner(
    authorization: str | None = Header(default=None),
) -> dict[str, Any] | None:
    """Decode Bearer JWT if present; returns None for unauthenticated local/MCP calls."""
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise HTTPException(status_code=401, detail="Invalid Authorization header format (expected 'Bearer <token>')")
    try:
        return decode_access_token(parts[1].strip())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {exc}") from exc


def get_required_current_owner(
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
) -> dict[str, Any]:
    """Require a valid Bearer JWT token."""
    if not current_owner:
        raise HTTPException(status_code=401, detail="Authentication required (missing Bearer token)")
    return current_owner


# ============================================================================
# Website Login & Auth endpoints
# ============================================================================

@app.post("/auth/login", tags=["Auth"])
def auth_login(request: LoginRequest):
    """Authenticate an owner ('owner_rifat' or 'owner_andi') and return a signed JWT."""
    result = services.authenticate_owner(
        identifier=request.identifier,
        password=request.password,
    )
    if not result.get("success"):
        raise HTTPException(status_code=401, detail=result.get("error", "Authentication failed"))
    return result


@app.get("/auth/me", tags=["Auth"])
def auth_me(current_owner: dict[str, Any] = Depends(get_required_current_owner)):
    """Return the currently logged-in owner's profile & permissions from their JWT."""
    return {
        "success": True,
        "owner": {
            "owner_id": current_owner["owner_id"],
            "name": current_owner.get("name", ""),
            "role": current_owner.get("role", "Owner / Admin"),
            "permissions": current_owner.get("permissions", []),
            "visible_categories": current_owner.get("visible_categories", ["customer", "peer"]),
        },
    }


@app.post("/auth/logout", tags=["Auth"])
def auth_logout(current_owner: dict[str, Any] = Depends(get_required_current_owner)):
    """Record an authenticated logout event in audit_events."""
    return services.record_logout(owner_id=current_owner["owner_id"])


# ============================================================================
# Health
# ============================================================================

@app.get("/health", tags=["System"])
def health():
    """Configuration and database connectivity status."""
    return services.check_health()


@app.get("/", tags=["System"])
def root():
    return {
        "service": "customer-master-profiler",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
    }


# ============================================================================
# Pipeline endpoints
# ============================================================================

@app.post("/profiler/ingest", tags=["Pipeline"])
def ingest(request: IngestRequest):
    """Ingest Email/WhatsApp/Telegram messages into Supabase."""
    return services.run_ingest(
        source=request.source,
        trigger=request.trigger,
        payloads=request.payloads,
        feed_file=request.feed_file,
        owner=request.owner,
    )


@app.get("/profiler/pending", tags=["Pipeline"])
def pending(limit: int = Query(default=20, ge=1, le=200)):
    """Fetch PII-redacted pending messages for Expert analysis."""
    return services.get_pending(limit=limit)


@app.post("/profiler/write", tags=["Pipeline"])
def write_enrichment(request: EnrichmentRequest):
    """Validate and write Expert enrichment results."""
    return services.write_enrichment(
        results=request.results,
        version=request.version,
        model=request.model,
        owner=request.owner,
    )


@app.post("/profiler/build-master", tags=["Pipeline"])
def build_master(owner: str = "owner_rifat"):
    """Build consolidated master customer profiles."""
    return services.build_master_profiles(owner=owner)


@app.post("/profiler/approve-staging", tags=["Pipeline"])
def approve_staging(
    request: ApprovalRequest,
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
):
    """Approve or reject a staged profile change (locks reviewer to JWT owner_id when logged in)."""
    effective_owner = current_owner["owner_id"] if current_owner else request.owner
    if current_owner and "approve_staging" not in current_owner.get("permissions", []):
        raise HTTPException(status_code=403, detail="Permission denied: missing 'approve_staging' permission")
    result = services.approve_staging(
        staging_id=request.staging_id,
        decision=request.decision,
        owner=effective_owner,
        approval_hash=request.approval_hash,
    )
    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/profiler/report", tags=["Pipeline"])
def report(tz_group: str | None = Query(default=None, pattern="^(WIB|WITA|WIT)$")):
    """Markdown master profile report, optionally filtered by timezone."""
    return {"markdown": services.get_report(tz_group=tz_group)}


# ============================================================================
# Query endpoints
# ============================================================================

@app.get("/profiles", tags=["Profiles"])
def profiles(
    contact_id: str = "",
    full_name: str = "",
    org_name: str = "",
    city: str = "",
    tz_label: str | None = Query(default=None, pattern="^(WIB|WITA|WIT)$"),
    category: str | None = Query(default=None, pattern="^(customer|peer)$"),
    verification_status: str = "",
    character_style: str | None = Query(default=None, pattern="^(Driver|Analytical|Amiable|Expressive|unknown)$"),
    churn_risk_level: str | None = Query(default=None, pattern="^(low|medium|high)$"),
    needs_review_only: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
):
    """Query customer master profiles with filters (auto-scoped by visible_to_roles when logged in)."""
    return services.query_profiles(
        contact_id=contact_id,
        full_name=full_name,
        org_name=org_name,
        city=city,
        tz_label=tz_label or "",
        category=category or "",
        verification_status=verification_status,
        character_style=character_style or "",
        churn_risk_level=churn_risk_level or "",
        needs_review_only=needs_review_only,
        viewer_owner_id=current_owner["owner_id"] if current_owner else "",
        limit=limit,
    )


@app.patch("/profiles/{contact_id}/manual-enrich", tags=["Profiles"])
def manual_enrich(
    contact_id: str,
    request: ManualEnrichRequest,
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
):
    """Manually enrich a customer master profile (marks fields user_confirmed under TR-08 & recompiles agent_brief)."""
    effective_owner = current_owner["owner_id"] if current_owner else request.owner
    if current_owner:
        perms = current_owner.get("permissions", [])
        if "enrich" not in perms and "approve_staging" not in perms:
            raise HTTPException(status_code=403, detail="Permission denied: missing 'enrich' permission")
    updates = {
        k: v
        for k, v in request.model_dump(exclude={"owner"}).items()
        if v is not None
    }
    result = services.manual_enrich_profile(
        contact_id=contact_id,
        updates=updates,
        owner=effective_owner,
    )
    if not result.get("success"):
        status_code = 404 if "not found" in str(result.get("error", "")).lower() else 400
        raise HTTPException(status_code=status_code, detail=result.get("error", "Manual enrich failed"))
    return result


# ============================================================================
# Ticket & Personalization Bridge endpoints (For Friend's WorkBuddy #2 & Website)
# ============================================================================

@app.get("/tickets/pending", tags=["Tickets"])
def tickets_pending(limit: int = Query(default=20, ge=1, le=200)):
    """Fetch enriched messages joined with customer_master_profiles for personalization."""
    return services.get_pending_tickets(limit=limit)


@app.post("/tickets/publish", tags=["Tickets"])
def tickets_publish(request: TicketPublishRequest):
    """Auto-map 1 flat JSON from WorkBuddy into tickets, ticket_actions, ticket_findings & audit_events."""
    return services.publish_personalized_ticket(
        payload=request.model_dump(),
        owner=request.owner_id,
    )


@app.post("/tickets/approve", tags=["Tickets"])
def tickets_approve(
    request: TicketApproveRequest,
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
):
    """Approve or reject a ticket; enforces owner separation (Rifat vs Andi) and 60s outbox_queue."""
    effective_owner = current_owner["owner_id"] if current_owner else request.owner
    if current_owner and "send_external" not in current_owner.get("permissions", []):
        raise HTTPException(status_code=403, detail="Permission denied: missing 'send_external' permission")
    result = services.approve_ticket_to_outbox(
        request_id=request.request_id,
        decision=request.decision,
        owner=effective_owner,
        approval_hash=request.approval_hash,
    )
    if isinstance(result, dict) and result.get("error"):
        status_code = 403 if result.get("forbidden") else 400
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result


@app.get("/tickets", tags=["Tickets"])
def list_tickets(
    status: str = "",
    owner_id: str = "",
    limit: int = Query(default=50, ge=1, le=200),
    current_owner: dict[str, Any] | None = Depends(get_optional_current_owner),
):
    """Query tickets grouped/scoped to the logged-in owner_id (pass owner_id='all' to view all)."""
    viewer_id = current_owner["owner_id"] if current_owner else ""
    return services.query_tickets(
        status=status,
        owner_id=owner_id,
        viewer_owner_id=viewer_id,
        limit=limit,
    )


# ============================================================================
# Approval Gate Adapter Endpoints (sekre_* + customer_master_profiles v3, JWT)
# ============================================================================

@app.get("/api/v1/health", tags=["ApprovalGate"])
def api_v1_health():
    """Hackathon v1 health alias."""
    return {"status": "ok", **services.check_health()}


@app.get("/api/v1/requests", tags=["ApprovalGate"])
def api_v1_list_requests(
    limit: int = Query(default=50, ge=1, le=200),
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List sekre_results cards enriched with sekre_actions & customer_master_profiles v3."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_approval_requests(owner_key=owner_key, limit=limit)


@app.get("/api/v1/requests/latest", tags=["ApprovalGate"])
def api_v1_latest_request(
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Fetch the most recent sekre_results card for the authenticated owner."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.get_latest_approval_request(owner_key=owner_key)


@app.get("/api/v1/requests/{request_id}", tags=["ApprovalGate"])
def api_v1_get_request(
    request_id: str,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Fetch a single sekre_results card by request_id."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    card = sekre_adapter.get_approval_request_by_id(owner_key=owner_key, request_id=request_id)
    if not card:
        raise HTTPException(status_code=404, detail=f"Request '{request_id}' not found")
    return card


@app.post("/api/v1/requests/{request_id}/approve", tags=["ApprovalGate"])
def api_v1_approve_action(
    request_id: str,
    request: SekreApproveActionRequest,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Edit + approve/reject a sekre_actions row, recompute hashes, and append sekre_audit."""
    if "send_external" not in current_owner.get("permissions", []):
        raise HTTPException(status_code=403, detail="Permission denied: missing 'send_external' permission")
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    result = sekre_adapter.approve_or_reject_action(
        owner_key=owner_key,
        request_id=request_id,
        action_id=request.action_id,
        idempotency_key=request.idempotency_key,
        decision=request.decision,
        actor_owner_id=current_owner["owner_id"],
        cognitive_confirmation=request.cognitive_confirmation,
        edited_subject=request.edited_subject,
        edited_body_draft=request.edited_body_draft,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=int(result.get("status_code") or 400),
            detail=result.get("error", "Approval failed"),
        )
    return result


@app.post("/api/v1/requests/{request_id}/clarify", tags=["ApprovalGate"])
def api_v1_resolve_clarify(
    request_id: str,
    request: SekreClarifyRequest,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Resolve a needs_clarify sekre_results card with chosen contact_id & schedule slot."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    result = sekre_adapter.resolve_clarify(
        owner_key=owner_key,
        request_id=request_id,
        contact_id=request.contact_id,
        selected_slot=request.selected_slot,
        actor_owner_id=current_owner["owner_id"],
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=int(result.get("status_code") or 400),
            detail=result.get("error", "Clarify resolution failed"),
        )
    return result


@app.get("/api/v1/outbox", tags=["ApprovalGate"])
def api_v1_outbox(
    request_id: str = "",
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List approved/queued/handed_off sekre_actions with 60s countdown metadata for OutboxCountdown."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_outbox(owner_key=owner_key, request_id=request_id)


@app.post("/api/v1/outbox/{action_id}/undo", tags=["ApprovalGate"])
@app.post("/api/v1/outbox/{action_id}/cancel", tags=["ApprovalGate"])
def api_v1_outbox_cancel(
    action_id: str,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Undo/cancel a queued outbox action during the 60-second safety undo window."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    result = sekre_adapter.cancel_outbox_action(
        owner_key=owner_key,
        action_id=action_id,
        actor_owner_id=current_owner["owner_id"],
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=int(result.get("status_code") or 400),
            detail=result.get("error", "Cancel failed"),
        )
    return result


@app.post("/api/v1/outbox/cancel", tags=["ApprovalGate"])
def api_v1_outbox_cancel_body(
    request: SekreCancelOutboxRequest,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Cancel a queued outbox action via JSON body (`action_id` or `outbox_id`)."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    target_id = request.action_id or request.outbox_id
    result = sekre_adapter.cancel_outbox_action(
        owner_key=owner_key,
        action_id=target_id,
        actor_owner_id=current_owner["owner_id"],
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=int(result.get("status_code") or 400),
            detail=result.get("error", "Cancel failed"),
        )
    return result


@app.get("/api/v1/contacts", tags=["ApprovalGate"])
def api_v1_contacts(
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List merged contacts (customer_master_profiles + sekre_profiles/sekre_contact_channels)."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_contacts(owner_key=owner_key)


@app.get("/api/v1/audit/verify", tags=["ApprovalGate"])
def api_v1_audit_verify(
    request_id: str = "",
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Verify sekre_audit hash chain and return sanitized events."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.verify_audit(owner_key=owner_key, request_id=request_id)


@app.get("/api/v1/crm-complaints", tags=["ApprovalGate"])
def api_v1_crm_complaints(
    status: str = "",
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List CRM complaint drafts from v_crm_complaint_draft_review."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_crm_complaints(owner_key=owner_key, status=status)


@app.get("/api/v1/order-followups", tags=["ApprovalGate"])
def api_v1_order_followups(
    run_id: str = "",
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List order follow-up items extracted from sekre_results.payload->'order_drafts' (latest run by default)."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_order_followups(owner_key=owner_key, run_id=run_id)


@app.post("/api/v1/order-followups/approve", tags=["ApprovalGate"])
def api_v1_approve_order_followup(
    request: SekreApproveOrderRequest,
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """Edit & approve/reject an order follow-up into public.sekre_approved_orders + append sekre_audit."""
    perms = current_owner.get("permissions", [])
    if "send_external" not in perms and "approve_staging" not in perms:
        raise HTTPException(status_code=403, detail="Permission denied: missing approval permission")
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    result = sekre_adapter.approve_order_followup(
        owner_key=owner_key,
        order_draft_id=request.order_draft_id,
        actor_owner_id=current_owner["owner_id"],
        decision=request.decision,
        request_id=request.request_id,
        run_id=request.run_id,
        so_id=request.so_id,
        nama_pemesan=request.nama_pemesan,
        nama_customer=request.nama_customer,
        po_reference=request.po_reference,
        due_date=request.due_date,
        so_status=request.so_status,
        billing_status=request.billing_status,
        items=request.items,
        notes=request.notes,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=int(result.get("status_code") or 400),
            detail=result.get("error", "Order approval failed"),
        )
    return result


@app.get("/api/v1/approved-orders", tags=["ApprovalGate"])
def api_v1_list_approved_orders(
    limit: int = Query(default=50, ge=1, le=200),
    current_owner: dict[str, Any] = Depends(get_required_current_owner),
):
    """List all approved/processed orders from public.sekre_approved_orders."""
    owner_key = sekre_adapter.resolve_sekre_owner_key(current_owner)
    return sekre_adapter.list_approved_orders(owner_key=owner_key, limit=limit)


# ============================================================================
# Serverless-Ready Remote MCP Endpoints (Stateless JSON-RPC 2.0 for Vercel)
# ============================================================================

@app.get("/mcp/{role}", tags=["MCP"])
def mcp_info(role: str):
    """Discovery endpoint for role-scoped remote MCP on Vercel ('profiler', 'ticket_agent', 'all')."""
    if role not in ("profiler", "ticket_agent", "all"):
        raise HTTPException(status_code=404, detail="Unknown MCP role (use 'profiler', 'ticket_agent', or 'all')")
    server = mcp_server.build_mcp_server(role)
    tools = [
        {"name": t.name, "description": t.description, "inputSchema": t.parameters}
        for t in server._tool_manager.list_tools()
    ]
    return {
        "protocol": "mcp-jsonrpc-2.0-stateless",
        "server": server.name,
        "role": role,
        "tools_count": len(tools),
        "tools": tools,
    }


@app.post("/mcp/{role}", tags=["MCP"])
async def mcp_jsonrpc(role: str, request: Request):
    """
    Stateless MCP JSON-RPC 2.0 endpoint for Vercel Serverless Functions.
    Supports 'initialize', 'ping', 'tools/list', and 'tools/call' in a single HTTP request.
    """
    if role not in ("profiler", "ticket_agent", "all"):
        raise HTTPException(status_code=404, detail="Unknown MCP role")

    expected_key = os.environ.get("MCP_API_KEY", "").strip()
    if expected_key:
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {expected_key}":
            raise HTTPException(status_code=401, detail="Invalid or missing MCP_API_KEY")

    body = await request.json()
    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}
    server = mcp_server.build_mcp_server(role)

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": server.name, "version": "2.0.0"},
            },
        }
    if method in ("notifications/initialized", "ping"):
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if method == "tools/list":
        tools = [
            {"name": t.name, "description": t.description or "", "inputSchema": t.parameters}
            for t in server._tool_manager.list_tools()
        ]
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}}

    if method == "tools/call":
        import json as _json

        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        allowed = {t.name: t for t in server._tool_manager.list_tools()}
        if tool_name not in allowed:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Tool '{tool_name}' is not available for role '{role}'"},
            }
        fn = getattr(mcp_server, tool_name)
        result = fn(**tool_args)
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "content": [{"type": "text", "text": _json.dumps(result, ensure_ascii=False, default=str)}],
                "isError": False,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Unsupported MCP method: {method}"},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
