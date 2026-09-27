create table public.comments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text not null
);

alter table public.comments enable row level security;

create policy "comments_select_own" on public.comments
  for select
  to authenticated
  using (auth.uid() = user_id);

grant select on public.comments to authenticated;
