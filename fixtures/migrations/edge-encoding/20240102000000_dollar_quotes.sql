-- $tag$ nested inside $$, and -- comments / semicolons inside the body
create function public.touch() returns trigger language plpgsql security definer as $$
begin
  -- a comment inside the body; with a semicolon
  perform $inner$ not the end; $inner$;
  return new;
end;
$$;
grant select on public.notes to authenticated;
create policy "notes read" on public.notes for select to authenticated using (auth.uid() = id);
