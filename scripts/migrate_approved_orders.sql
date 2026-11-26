-- ============================================================================
-- Migration: Create public.sekre_approved_orders
-- Stores human-edited & approved order follow-ups without mutating sekre_results.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.sekre_approved_orders (
    approved_order_id TEXT PRIMARY KEY,
    owner_key         TEXT NOT NULL,
    request_id        TEXT NOT NULL DEFAULT '',
    run_id            TEXT NOT NULL DEFAULT '',
    order_draft_id    TEXT NOT NULL,
    so_id             TEXT NOT NULL DEFAULT '',
    nama_pemesan      TEXT NOT NULL DEFAULT '',
    nama_customer     TEXT NOT NULL DEFAULT '',
    po_reference      TEXT NOT NULL DEFAULT '',
    due_date          TEXT NOT NULL DEFAULT '',
    so_status         TEXT NOT NULL DEFAULT 'processing',
    billing_status    TEXT NOT NULL DEFAULT 'pending_invoice',
    items_json        JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes             TEXT NOT NULL DEFAULT '',
    decision          TEXT NOT NULL DEFAULT 'approved',
    approval_hash     TEXT NOT NULL DEFAULT '',
    approved_by       TEXT NOT NULL DEFAULT '',
    approved_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner_key, order_draft_id, so_id)
);

CREATE INDEX IF NOT EXISTS idx_sekre_approved_orders_owner_approved
    ON public.sekre_approved_orders (owner_key, approved_at DESC);

CREATE INDEX IF NOT EXISTS idx_sekre_approved_orders_owner_decision
    ON public.sekre_approved_orders (owner_key, decision);
