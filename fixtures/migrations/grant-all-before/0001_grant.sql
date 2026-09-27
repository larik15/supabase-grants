-- Grant runs before the table exists: per Postgres semantics this should
-- NOT cover a table created afterwards.
grant select on all tables in schema public to authenticated;
