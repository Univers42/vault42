-- 071_vault42_secrets.sql — the vault42 zero-knowledge blob substrate.
-- Apply to the grobase Postgres (copy into grobase scripts/migrations/postgresql/).
-- Additive + idempotent (mirrors grobase's 070 shape). ZERO plaintext columns: the
-- `envelope` is an OPAQUE serialized vault42-core Envelope the server cannot decrypt.
-- Owner-scoped via RLS; `vault42_grants` carries the time-bound RBAC leases.
BEGIN;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.schema_migrations WHERE version = 71) THEN
    RAISE NOTICE 'Migration 071 already applied - skipping';
    RETURN;
  END IF;

  CREATE TABLE IF NOT EXISTS public.vault42_secrets (
    owner_id    uuid        NOT NULL,
    secret_id   uuid        NOT NULL,
    path        text        NOT NULL,
    version     integer     NOT NULL,
    envelope    bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, secret_id, version)
  );
  CREATE INDEX IF NOT EXISTS vault42_secrets_owner_path
    ON public.vault42_secrets (owner_id, path);
  ALTER TABLE public.vault42_secrets ENABLE ROW LEVEL SECURITY;

  CREATE TABLE IF NOT EXISTS public.vault42_grants (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant         text        NOT NULL,
    grantee        text        NOT NULL,
    role           text        NOT NULL CHECK (role IN ('read','write','update','admin')),
    resource_scope text        NOT NULL DEFAULT '*',
    granted_by     text        NOT NULL,
    granted_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz NULL,
    PRIMARY KEY (id)
  );
  CREATE INDEX IF NOT EXISTS vault42_grants_lookup
    ON public.vault42_grants (tenant, grantee, role) WHERE revoked_at IS NULL;

  INSERT INTO public.schema_migrations (version, name)
  VALUES (71, '071_vault42_secrets') ON CONFLICT (version) DO NOTHING;
END $$;
COMMIT;
