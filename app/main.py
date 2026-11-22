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

from app import mcp_server, services  # noqa: E402
from app.core.security import decode_access_token  # noqa: E402

app = FastAPI(
    title="WorkBuddy Master Customer Profiler API",
    description="Supabase-backed omni-channel customer master profiling pipeline for PT Nusantara Alat Berat",
    version="2.0.0",
)

# Allow localhost:3000, custom CORS_ORIGINS env var, and any *.vercel.app deployment
_extra_origins = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", *_extra_origins],
    allow_origin_regex=r"https://.*\.vercel\.app|http://(localhost|127\.0\.0\.1)(:\d+)?",
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
        needs_review_only=needs_review_only,
        viewer_owner_id=current_owner["owner_id"] if current_owner else "",
        limit=limit,
    )


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
