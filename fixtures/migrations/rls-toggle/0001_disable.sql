create table public.audit_log (
  id uuid primary key default gen_random_uuid(),
  event text not null
);

alter table public.audit_log enable row level security;
alter table public.audit_log disable row level security;
