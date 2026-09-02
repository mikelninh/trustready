-- TrustReady Legal — pilot metadata schema
-- Production design artifact. Apply only to a dedicated protected PostgreSQL instance.
-- Raw mandate document bodies belong in private object storage, not these tables.

create extension if not exists pgcrypto;

create table if not exists firms (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  display_name text not null,
  created_at timestamptz not null default now()
);

create table if not exists principals (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  external_ref_hash char(64) not null,
  role text not null check (role in ('client','intake_staff','lawyer','firm_admin')),
  status text not null default 'active' check (status in ('active','disabled')),
  created_at timestamptz not null default now(),
  unique (firm_id, external_ref_hash, role)
);

create table if not exists matters (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  public_ref text not null,
  state text not null default 'OPEN' check (state in ('OPEN','INCOMPLETE','COMPLETE','READY_FOR_LAWYER','LAWYER_APPROVED_SHADOW_ONLY','CLOSED')),
  source_language text not null default 'vi' check (source_language in ('vi','de')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (firm_id, public_ref)
);

create table if not exists matter_access (
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  principal_id uuid not null references principals(id),
  access_role text not null check (access_role in ('client','intake_staff','lawyer')),
  created_at timestamptz not null default now(),
  primary key (matter_id, principal_id)
);

create table if not exists client_invites (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  principal_id uuid not null references principals(id),
  token_hash char(64) not null unique,
  second_factor_target_hash char(64) not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists portal_sessions (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid,
  principal_id uuid not null references principals(id),
  session_hash char(64) not null unique,
  authenticated_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists requirements (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  slot text not null,
  label_vi text not null,
  label_de text not null,
  status text not null check (status in ('MISSING','RECEIVED_QUARANTINE','SCAN_PENDING','REJECTED','RECEIVED_CLEAN','REVIEW_REQUIRED','COMPLETE')),
  reason_code text,
  updated_at timestamptz not null default now(),
  unique (matter_id, slot)
);

create table if not exists upload_capabilities (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  principal_id uuid not null references principals(id),
  requirement_id uuid not null references requirements(id),
  capability_hash char(64) not null unique,
  expected_mime text not null,
  expected_size_bytes bigint not null check (expected_size_bytes > 0),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists documents (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  requirement_id uuid not null references requirements(id),
  object_ref text not null,
  content_sha256 char(64),
  mime_type text not null,
  size_bytes bigint not null,
  storage_state text not null check (storage_state in ('QUARANTINE','REJECTED','PROTECTED_MATTER_STORE','DELETED')),
  malware_status text not null check (malware_status in ('PENDING','CLEAN','INFECTED','ERROR')),
  uploaded_by uuid not null references principals(id),
  created_at timestamptz not null default now(),
  promoted_at timestamptz,
  deleted_at timestamptz
);

create table if not exists translations (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid not null references matters(id),
  document_id uuid references documents(id),
  source_language text not null,
  target_language text not null,
  source_content_hash char(64) not null,
  model_ref text not null,
  translation_ref text not null,
  requires_review boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists audit_events (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references firms(id),
  matter_id uuid,
  principal_id uuid,
  event_type text not null,
  event_ref_hash char(64) not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Defense-in-depth RLS. The application must set these from an already authenticated,
-- server-derived context; browser-provided tenant/matter values are never authoritative.
alter table matters enable row level security;
alter table matter_access enable row level security;
alter table requirements enable row level security;
alter table documents enable row level security;
alter table translations enable row level security;
alter table audit_events enable row level security;

create policy matters_tenant_policy on matters
  using (firm_id::text = current_setting('trustready.tenant_id', true));
create policy matter_access_tenant_policy on matter_access
  using (firm_id::text = current_setting('trustready.tenant_id', true));
create policy requirements_tenant_policy on requirements
  using (firm_id::text = current_setting('trustready.tenant_id', true));
create policy documents_tenant_policy on documents
  using (firm_id::text = current_setting('trustready.tenant_id', true));
create policy translations_tenant_policy on translations
  using (firm_id::text = current_setting('trustready.tenant_id', true));
create policy audit_events_tenant_policy on audit_events
  using (firm_id::text = current_setting('trustready.tenant_id', true));

-- Audit events are append-only for the runtime role. Grant statements should be applied by
-- deployment tooling using separate migration/runtime DB roles; runtime receives no UPDATE/DELETE
-- privilege on audit_events.

create index if not exists idx_matters_firm on matters(firm_id);
create index if not exists idx_access_principal on matter_access(principal_id, matter_id);
create index if not exists idx_requirements_matter on requirements(matter_id);
create index if not exists idx_documents_matter on documents(matter_id, storage_state);
create index if not exists idx_audit_matter_created on audit_events(matter_id, created_at desc);