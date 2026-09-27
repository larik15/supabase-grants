create table "Public"."Orders" (
  "Id" uuid primary key default gen_random_uuid(),
  "UserId" uuid not null,
  "Note" text default 'default; still one statement'
);

alter table "Public"."Orders" enable row level security;

create policy "Orders Select Own" on "Public"."Orders"
  for select
  to authenticated
  using (auth.uid() = "UserId");

grant select on "Public"."Orders" to authenticated;
