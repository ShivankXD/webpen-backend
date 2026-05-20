-- ─────────────────────────────────────────────────────────────────
-- WebPen — Supabase migration 001
-- Creates the `users` table used by the Express backend.
--
-- Run this in:
--   Supabase Dashboard → SQL Editor → New Query → Paste & Run
-- OR via the Supabase CLI:
--   supabase db push
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.users (
  -- Primary key: the user's ID from your extension
  -- (e.g. a Google OAuth sub, a Chrome identity token, or an anon UUID)
  id                TEXT        PRIMARY KEY,

  -- User email — populated when PayPal returns subscriber.email_address
  email             TEXT,

  -- Premium flag — the one column the webhook flips to TRUE
  is_premium        BOOLEAN     NOT NULL DEFAULT FALSE,

  -- PayPal subscription ID — used to look up the row on cancellation
  paypal_sub_id     TEXT,

  -- Timestamps
  premium_since     TIMESTAMPTZ,
  premium_revoked_at TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Keep updated_at current automatically
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_set_updated_at ON public.users;
CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Index for fast lookups by PayPal subscription ID (used in revoke logic)
CREATE INDEX IF NOT EXISTS idx_users_paypal_sub_id
  ON public.users (paypal_sub_id);

-- ── Row Level Security ───────────────────────────────────────────
-- The backend uses the service-role key which bypasses RLS.
-- Enable RLS anyway so that anon/authenticated keys can't read raw data.
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Deny all access to anonymous users
CREATE POLICY "No anon access"
  ON public.users
  FOR ALL
  TO anon
  USING (false);

-- ── Notes ────────────────────────────────────────────────────────
-- After running this migration, grab your credentials from:
--   Supabase Dashboard → Settings → API
--     • Project URL  → SUPABASE_URL
--     • service_role → SUPABASE_SERVICE_KEY  (keep secret!)
