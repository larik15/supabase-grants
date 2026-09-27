-- CRLF line endings, a UTF-8 BOM, tabs, and an E-string with an escaped quote and a semicolon
create table	public.notes (
	id uuid primary key,
	body text default E'it\'s; fine'
);
alter table	public.notes	enable row level security;
