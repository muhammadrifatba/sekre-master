"""
mcp_server.py — Role-Scoped WorkBuddy MCP Server for the Customer Master Profiler
and Friend's Meeting & Ticket Agent.

Runs over stdio (spawned by WorkBuddy via ~/.workbuddy-ai/mcp.json) and exposes
tools backed by app.services — the same service layer the FastAPI app uses.

Role isolation via MCP_AGENT_ROLE env var:
  - MCP_AGENT_ROLE=profiler     (Your WorkBuddy #1):
      3 tools ONLY: sekre_run_master_profiler, sekre_query_master_profiles,
      sekre_approve_master_profile_staging. (ZERO ticket tools.)
  - MCP_AGENT_ROLE=ticket_agent (Friend's WorkBuddy #2):
      4 tools ONLY: sekre_query_master_profiles, sekre_fetch_pending_tickets,
      sekre_publish_personalized_ticket, sekre_approve_ticket_to_outbox.
  - MCP_AGENT_ROLE=all          (default — admin / tests):
      All 6 tools.

Run directly:
    python -m app.mcp_server
"""
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import services  # noqa: E402


# ============================================================================
# Tool Implementations (plain functions — registered per MCP_AGENT_ROLE below)
# ============================================================================

def sekre_run_master_profiler(
    subcommand: str = "ingest-omni",
    source: str = "all",
    trigger: str = "scheduled",
    limit: int = 20,
    version: str = "v2",
    model: str = "workbuddy-expert",
    payloads: list[dict] | None = None,
    owner: str = "owner_rifat",
    tz_group: str = "",
    staging_id: str = "",
    decision: str = "",
    approval_hash: str = "",
) -> dict:
    """Run a Master Profiler pipeline command against Supabase.

    Args:
        subcommand: One of 'ingest-omni', 'pending', 'write', 'build-master',
                    'approve-staging', 'report'.
        source: Message source for ingest-omni ('all', 'email', 'whatsapp', 'telegram').
        trigger: 'scheduled' or 'manual'.
        limit: Max pending messages to return.
        version: Analyzer version for write.
        model: Model name for write.
        payloads: Optional list of message dicts for ingest-omni (e.g. Zapier results).
        owner: Owner ID for RBAC (default 'owner_rifat').
        tz_group: Timezone filter for report ('WIB', 'WITA', 'WIT').
        staging_id: Staging ID for approve-staging.
        decision: 'approve' or 'reject' for approve-staging.
        approval_hash: Optional SHA-256 hash for verification.

    Returns:
        Structured result of the command.
    """
    if subcommand == "ingest-omni":
        return services.run_ingest(
            source=source, trigger=trigger, payloads=payloads, owner=owner
        )
    if subcommand == "pending":
        return {"messages": services.get_pending(limit=limit)}
    if subcommand == "write":
        if not payloads:
            return {"error": "pass enrichment results in the 'payloads' parameter"}
        return services.write_enrichment(
            results=payloads, version=version, model=model, owner=owner
        )
    if subcommand == "build-master":
        return services.build_master_profiles(owner=owner)
    if subcommand == "approve-staging":
        if not staging_id or not decision:
            return {"error": "staging_id and decision are required"}
        return services.approve_staging(
            staging_id=staging_id, decision=decision, owner=owner,
            approval_hash=approval_hash or None
        )
    if subcommand == "report":
        return {"markdown": services.get_report(tz_group=tz_group or None)}
    return {"error": f"Unknown subcommand: {subcommand}"}


def sekre_query_master_profiles(
    contact_id: str = "",
    full_name: str = "",
    org_name: str = "",
    city: str = "",
    tz_label: str = "",
    category: str = "",
    verification_status: str = "",
    needs_review_only: bool = False,
    limit: int = 50,
) -> dict:
    """Query customer master profiles in Supabase with optional filters.

    Args:
        contact_id: Exact contact_id match.
        full_name: Partial customer name match (e.g. 'Budi' from a meeting transcript).
        org_name: Partial organization name.
        city: Partial city name.
        tz_label: 'WIB', 'WITA', or 'WIT'.
        category: 'customer' or 'peer'.
        verification_status: e.g. 'verified', 'staged_unverified'.
        needs_review_only: Only return profiles flagged for review.
        limit: Maximum results (default 50).

    Returns:
        Matching master profiles with ambiguous_match flag and pending-staging count.
    """
    return services.query_profiles(
        contact_id=contact_id,
        full_name=full_name,
        org_name=org_name,
        city=city,
        tz_label=tz_label,
        category=category,
        verification_status=verification_status,
        needs_review_only=needs_review_only,
        limit=limit,
    )


def sekre_approve_master_profile_staging(
    staging_id: str,
    decision: str = "approve",
    owner: str = "owner_rifat",
    approval_hash: str = "",
) -> dict:
    """Approve or reject a staged master profile change.

    Use this for profile poisoning (TR-08), contact ambiguity, or
    low-confidence extraction (<0.6) items awaiting human approval.
    """
    return services.approve_staging(
        staging_id=staging_id,
        decision=decision,
        owner=owner,
        approval_hash=approval_hash or None,
    )


def sekre_fetch_pending_tickets(limit: int = 20) -> dict:
    """Fetch newly enriched messages joined with customer_master_profiles.

    Used by Friend's WorkBuddy #2 (Meeting & Ticket Agent) when checking
    unprocessed scraped messages alongside their personalization profile.
    """
    return {"items": services.get_pending_tickets(limit=limit)}


def sekre_publish_personalized_ticket(
    body_draft: str,
    contact_id: str = "",
    source_message_pk: int | None = None,
    request_id: str = "",
    redacted_summary: str = "",
    subject: str = "",
    channel: str = "whatsapp",
    channel_reason: str = "",
    action_type: str = "reply_customer",
    source_quote: str = "",
    risk_tier: str = "medium",
    confidence: float = 1.0,
    is_ramadan: bool = False,
    owner: str = "owner_rifat",
) -> dict:
    """Publish 1 flat personalized ticket JSON into Supabase (WorkBuddy #2 ONLY).

    Automatically enforces the 5 Accountability Pillars & WIB/WITA/WIT rules
    and populates tickets, ticket_actions, ticket_findings, and audit_events.
    """
    payload = {
        "request_id": request_id or None,
        "owner_id": owner,
        "source_message_pk": source_message_pk,
        "contact_id": contact_id,
        "redacted_summary": redacted_summary,
        "action_type": action_type,
        "channel": channel,
        "channel_reason": channel_reason,
        "subject": subject,
        "body_draft": body_draft,
        "source_quote": source_quote,
        "risk_tier": risk_tier,
        "confidence": confidence,
        "is_ramadan": is_ramadan,
    }
    return services.publish_personalized_ticket(payload=payload, owner=owner)


def sekre_approve_ticket_to_outbox(
    request_id: str,
    decision: str = "approve",
    owner: str = "owner_rifat",
    approval_hash: str = "",
) -> dict:
    """Approve or reject a staged ticket; approved actions enter outbox_queue (60s undo)."""
    return services.approve_ticket_to_outbox(
        request_id=request_id,
        decision=decision,
        owner=owner,
        approval_hash=approval_hash or None,
    )


# ============================================================================
# Role-Scoped Server Builder
# ============================================================================

def build_mcp_server(role: str | None = None) -> FastMCP:
    """Build a FastMCP server registering ONLY the tools allowed for `role`."""
    resolved_role = (role or os.environ.get("MCP_AGENT_ROLE", "all")).strip().lower()
    server_name = (
        "customer-master-profiler"
        if resolved_role in ("profiler", "all")
        else "sekre-ticket-agent"
    )
    server = FastMCP(server_name)

    # Read-only profile lookup is shared by both agents
    server.tool()(sekre_query_master_profiles)

    # Profiler tools: ONLY Your WorkBuddy #1 ('profiler') or admin ('all')
    if resolved_role in ("profiler", "all"):
        server.tool()(sekre_run_master_profiler)
        server.tool()(sekre_approve_master_profile_staging)

    # Ticket tools: ONLY Friend's WorkBuddy #2 ('ticket_agent') or admin ('all')
    if resolved_role in ("ticket_agent", "all"):
        server.tool()(sekre_fetch_pending_tickets)
        server.tool()(sekre_publish_personalized_ticket)
        server.tool()(sekre_approve_ticket_to_outbox)

    return server


mcp = build_mcp_server()

if __name__ == "__main__":
    mcp.run()
