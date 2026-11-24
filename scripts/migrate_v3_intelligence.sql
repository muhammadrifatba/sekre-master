-- ============================================================================
-- Migration v3: Deep Customer Intelligence (5 JSONB + 2 Scalar + agent_brief)
-- Safe & idempotent — run directly in Supabase SQL Editor or psql.
-- ============================================================================

ALTER TABLE public.customer_master_profiles
    ADD COLUMN IF NOT EXISTS character_style TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS churn_risk_level TEXT NOT NULL DEFAULT 'low',
    ADD COLUMN IF NOT EXISTS communication_prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS character_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS motivation_and_pain JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS persuasion_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS relationship_health JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS agent_brief TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_character_style
    ON public.customer_master_profiles (character_style);

CREATE INDEX IF NOT EXISTS idx_customer_master_profiles_churn_risk_level
    ON public.customer_master_profiles (churn_risk_level);

-- Self-documenting column comments for SQL consumers, DBeaver, and Agent #2
COMMENT ON COLUMN public.customer_master_profiles.character_style IS
    'Primary communication style: Driver | Analytical | Amiable | Expressive | unknown (requires >=3 messages or manual confirm).';
COMMENT ON COLUMN public.customer_master_profiles.churn_risk_level IS
    'Customer churn risk filter: low | medium | high.';
COMMENT ON COLUMN public.customer_master_profiles.communication_prefs IS
    'JSONB: channel_by_topic, dnd_windows (do-not-disturb hours), peak_responsive_hours_local, language_register, preferred_length, typical_reply_hours.';
COMMENT ON COLUMN public.customer_master_profiles.character_profile IS
    'JSONB: style, secondary_style, style_evidence, complaint_patterns (frequent_topics, validity_rate, proven_resolution_playbook).';
COMMENT ON COLUMN public.customer_master_profiles.motivation_and_pain IS
    'JSONB: primary_jobs, value_drivers, regulatory_focus (promotion=gain/growth vs prevention=avoid downtime/risk), verbatim_pain_quotes.';
COMMENT ON COLUMN public.customer_master_profiles.persuasion_profile IS
    'JSONB: proven_triggers (social_proof/authority/scarcity/reciprocity), processing_route (central=data/specs vs peripheral=trust/brand).';
COMMENT ON COLUMN public.customer_master_profiles.relationship_health IS
    'JSONB: open_promises (two-way us/customer with due_date & status), sentiment_trend, key_moments, days_since_last_contact, churn_risk.';
COMMENT ON COLUMN public.customer_master_profiles.agent_brief IS
    'Auto-compiled plain-language narrative brief summarizing ALL relevant master profile columns for direct consumption by Agent #2.';
