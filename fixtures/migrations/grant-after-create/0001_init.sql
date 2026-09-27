create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text not null
);

alter table public.notes enable row level security;

create policy "notes_select_own" on public.notes
  for select
  to authenticated
  using (auth.uid() = user_id);

grant select, insert on public.notes to authenticated;
grant select on public.notes to anon;
