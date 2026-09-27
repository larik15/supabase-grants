create table public.widgets (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null
);

create function public.widget_count(p_owner uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  select count(*) into v_count from public.widgets where owner_id = p_owner;
  return v_count;
end;
$$;

alter table public.widgets enable row level security;

grant select on public.widgets to authenticated;
