-- ============================================================================
-- SEKRE v3 + WorkBuddy Master Profiler — Live Supabase PostgreSQL Schema
-- 10 active tables in public schema (100% aligned with live DBeaver schema)
-- ============================================================================

-- ============================================================================
-- 1. SHARED CORE & GOVERNANCE TABLES
-- ============================================================================

-- 1. owner_profiles — Authorized owners/admins (RBAC)
CREATE TABLE IF NOT EXISTS public.owner_profiles (
    owner_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    profile_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 2. organizations — Customer/peer companies
CREATE TABLE IF NOT EXISTS public.organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    org_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    organization_news JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- 3. audit_events — HMAC-SHA256 hash-chained audit trail (RECORD pillar)
CREATE TABLE IF NOT EXISTS public.audit_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash TEXT,
    curr_hash TEXT NOT NULL
);

-- ============================================================================
-- 2. CUSTOMER MASTER PROFILER TABLES (WorkBuddy #1)
-- ============================================================================

-- 4. scraped_messages — Raw + clean + PII-redacted omni-channel messages
CREATE TABLE IF NOT EXISTS public.scraped_messages (
    message_pk BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,                              -- 'email' | 'whatsapp' | 'telegram'
    source_id TEXT NOT NULL,                           -- Unique message ID per source
    payload_hash TEXT NOT NULL,                        -- SHA-256 of raw payload (SOURCES pillar)
    sender_raw TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    sender_identifier TEXT NOT NULL,
    recipient TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    raw_payload JSONB NOT NULL,                        -- Immutable raw message envelope
    clean_body TEXT NOT NULL,                          -- Stripped of signatures, quotes, disclaimers
    redacted_body TEXT NOT NULL,                       -- PII-redacted — only this goes to Expert
    pii_redacted BOOLEAN NOT NULL DEFAULT FALSE,
    injection_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    contact_id TEXT,                                   -- Resolved link to customer_master_profiles
    consent_status TEXT NOT NULL DEFAULT 'granted',    -- PERMISSIONS pillar
    features_json JSONB NOT NULL DEFAULT '{}'::jsonb,  -- Deterministic features
    enrichment_status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'done' | 'review' | 'dead_letter'
    enrichment_json JSONB,                             -- WorkBuddy Expert output
    needs_review BOOLEAN NOT NULL DEFAULT FALSE,       -- TRUE when confidence < 0.6 (LIMITS pillar)
    message_date TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source, source_id)
);

-- 5. customer_master_profiles — Single Source of Truth for Personalization
CREATE TABLE IF NOT EXISTS public.customer_master_profiles (
    master_id TEXT PRIMARY KEY,
    contact_id TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    salutation TEXT NOT NULL DEFAULT 'formal_bapak',
    role_title TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'customer',
    personalization_level TEXT NOT NULL DEFAULT 'full',
    org_id TEXT NOT NULL,
    org_name TEXT NOT NULL,
    account_tier TEXT NOT NULL DEFAULT 'Standard Account',

    -- Indonesian Cultural & Temporal Rules (WIB/WITA/WIT, Jumatan, Ramadan)
    city TEXT NOT NULL DEFAULT 'Jakarta',
    timezone TEXT NOT NULL DEFAULT 'Asia/Jakarta',
    tz_label TEXT NOT NULL DEFAULT 'WIB',
    work_hours_local TEXT NOT NULL DEFAULT '08:00-17:00',
    jumatan_block_local TEXT NOT NULL DEFAULT '11:30-13:00 (WIB & Local)',
    after_hours_policy TEXT NOT NULL DEFAULT 'defer_next_workday_0800_local',
    best_contact_window TEXT NOT NULL DEFAULT '',

    -- Unified Omni-Channel Contact Identities
    email TEXT NOT NULL DEFAULT '',
    phone_wa TEXT NOT NULL DEFAULT '',
    telegram_handle TEXT NOT NULL DEFAULT '',
    preferred_channel TEXT NOT NULL DEFAULT 'whatsapp',
    active_channels JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Aggregated Behavioral & Heavy Machinery Domain Context
    total_messages_30d INTEGER NOT NULL DEFAULT 0,
    total_messages_lifetime INTEGER NOT NULL DEFAULT 0,
    avg_response_delay_sec DOUBLE PRECISION,
    dominant_formality TEXT NOT NULL DEFAULT 'formal',
    sentiment_mix JSONB NOT NULL DEFAULT '{}'::jsonb,
    top_intents JSONB NOT NULL DEFAULT '{}'::jsonb,
    fleet_units JSONB NOT NULL DEFAULT '[]'::jsonb,
    open_complaints JSONB NOT NULL DEFAULT '[]'::jsonb,
    open_commitments JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- 5 Accountability Pillars Metadata
    consent_status TEXT NOT NULL DEFAULT 'granted',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    needs_review BOOLEAN NOT NULL DEFAULT FALSE,
    verification_status TEXT NOT NULL DEFAULT 'verified',
    field_provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
    visible_to_roles JSONB NOT NULL DEFAULT '["owner_rifat", "owner_andi"]'::jsonb,
    approval_hash TEXT,
    last_message_at TIMESTAMPTZ,
    last_scraped_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. master_profile_staging — Approval gate for conflicts & ambiguities
CREATE TABLE IF NOT EXISTS public.master_profile_staging (
    staging_id TEXT PRIMARY KEY,
    contact_id TEXT,
    master_id TEXT REFERENCES public.customer_master_profiles(master_id) ON DELETE SET NULL,
    source TEXT NOT NULL DEFAULT 'scraped_msg',
    source_message_pk BIGINT REFERENCES public.scraped_messages(message_pk) ON DELETE SET NULL,
    reason_type TEXT NOT NULL,                         -- 'profile_poisoning' | 'contact_ambiguity' | 'low_confidence'
    proposed_changes JSONB NOT NULL DEFAULT '{}'::jsonb,
    existing_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    candidate_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_quote TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    approval_hash TEXT NOT NULL,                       -- Canonical SHA-256
    status TEXT NOT NULL DEFAULT 'pending',            -- 'pending' | 'approved' | 'rejected' | 'auto_resolved'
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 3. TICKET, PERSONALIZATION & WEBSITE TABLES (For Friend's WorkBuddy #2 & UI)
-- ============================================================================

-- 7. tickets — Incoming requests, customer context & human approval state
CREATE TABLE IF NOT EXISTS public.tickets (
    request_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL DEFAULT 'owner_rifat',
    source_channel TEXT NOT NULL DEFAULT 'email',
    raw_input TEXT NOT NULL DEFAULT '',
    attachment_text TEXT NOT NULL DEFAULT '',
    redacted_summary TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending_approval',   -- 'pending_approval' | 'approved' | 'rejected' | 'completed'
    interrupt_type TEXT,                               -- 'external_communication' | 'low_confidence' | 'pdp_violation'
    interrupt_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    approval_hash TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    approval_decision TEXT,
    customer_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. ticket_actions — Personalized message drafts per ticket
CREATE TABLE IF NOT EXISTS public.ticket_actions (
    action_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES public.tickets(request_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL DEFAULT 'reply_customer',
    channel TEXT NOT NULL DEFAULT 'whatsapp',
    channel_reason TEXT NOT NULL DEFAULT '',
    recipient_contact_id TEXT NOT NULL DEFAULT '',
    recipient_name TEXT NOT NULL DEFAULT '',
    recipient_email TEXT NOT NULL DEFAULT '',
    recipient_phone TEXT NOT NULL DEFAULT '',
    recipient_org_id TEXT NOT NULL DEFAULT '',
    recipient_org_name TEXT NOT NULL DEFAULT '',
    recipient_city TEXT NOT NULL DEFAULT 'Jakarta',
    recipient_timezone TEXT NOT NULL DEFAULT 'Asia/Jakarta',
    subject TEXT NOT NULL DEFAULT '',
    body_draft TEXT NOT NULL DEFAULT '',
    scheduled_send_at TIMESTAMPTZ,
    tz_label TEXT NOT NULL DEFAULT 'WIB',
    rule_applied TEXT NOT NULL DEFAULT '',
    risk_tier TEXT NOT NULL DEFAULT 'medium',
    provenance_links JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'staged',             -- 'staged' | 'queued_outbox' | 'sent' | 'rejected'
    wa_handoff_link TEXT NOT NULL DEFAULT '',
    source_quote TEXT NOT NULL DEFAULT ''
);

-- 9. ticket_findings — 5-Pillar & Indonesian temporal rule check results
CREATE TABLE IF NOT EXISTS public.ticket_findings (
    finding_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES public.tickets(request_id) ON DELETE CASCADE,
    action_id TEXT,
    check_type TEXT NOT NULL,                          -- 'timezone_deferral' | 'peer_privacy' | 'pdp_blocklist' | 'confidence_limit' | 'source_provenance'
    severity TEXT NOT NULL DEFAULT 'info',             -- 'info' | 'warning' | 'critical'
    message TEXT NOT NULL,
    recommended_fix BOOLEAN NOT NULL DEFAULT FALSE
);

-- 10. outbox_queue — 60-second undo countdown queue for approved actions
CREATE TABLE IF NOT EXISTS public.outbox_queue (
    outbox_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'whatsapp',
    recipient_name TEXT NOT NULL DEFAULT '',
    recipient_address TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    scheduled_send_at TIMESTAMPTZ,
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    release_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '60 seconds'),
    status TEXT NOT NULL DEFAULT 'queued',             -- 'queued' | 'released' | 'cancelled'
    action_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_scraped_messages_source ON public.scraped_messages (source);
CREATE INDEX IF NOT EXISTS idx_scraped_messages_source_id ON public.scraped_messages (source_id);
CREATE INDEX IF NOT EXISTS idx_scraped_messages_payload_hash ON public.scraped_messages (payload_hash);
CREATE INDEX IF NOT EXISTS idx_scraped_messages_contact_id ON public.scraped_messages (contact_id);
CREATE INDEX IF NOT EXISTS idx_scraped_messages_enrichment_status ON public.scraped_messages (enrichment_status);
CREATE INDEX IF NOT EXISTS idx_scraped_messages_message_date ON public.scraped_messages (message_date DESC);

CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_org_id ON public.customer_master_profiles (org_id);
CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_city ON public.customer_master_profiles (city);
CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_tz_label ON public.customer_master_profiles (tz_label);
CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_category ON public.customer_master_profiles (category);
CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_verification_status ON public.customer_master_profiles (verification_status);

CREATE INDEX IF NOT EXISTS idx_master_profile_staging_status ON public.master_profile_staging (status);
CREATE INDEX IF NOT EXISTS idx_master_profile_staging_master_id ON public.master_profile_staging (master_id);
CREATE INDEX IF NOT EXISTS idx_master_profile_staging_approval_hash ON public.master_profile_staging (approval_hash);

CREATE INDEX IF NOT EXISTS idx_tickets_status ON public.tickets (status);
CREATE INDEX IF NOT EXISTS idx_tickets_owner_id ON public.tickets (owner_id);
CREATE INDEX IF NOT EXISTS idx_ticket_actions_request_id ON public.ticket_actions (request_id);
CREATE INDEX IF NOT EXISTS idx_ticket_findings_request_id ON public.ticket_findings (request_id);
CREATE INDEX IF NOT EXISTS idx_outbox_queue_status ON public.outbox_queue (status);

CREATE INDEX IF NOT EXISTS idx_audit_events_request_id ON public.audit_events (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON public.audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON public.audit_events (timestamp DESC);

-- ============================================================================
-- UPDATED_AT TRIGGER FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION public.trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_customer_master_profiles_updated_at ON public.customer_master_profiles;
CREATE TRIGGER trg_customer_master_profiles_updated_at
    BEFORE UPDATE ON public.customer_master_profiles
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();

DROP TRIGGER IF EXISTS trg_tickets_updated_at ON public.tickets;
CREATE TRIGGER trg_tickets_updated_at
    BEFORE UPDATE ON public.tickets
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();
