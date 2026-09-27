create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total numeric not null
);

alter table public.orders enable row level security;

create policy "orders_select_own" on public.orders
  for select
  to authenticated
  using (auth.uid() = user_id);
