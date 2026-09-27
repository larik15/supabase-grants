// Read-only introspection of a live Postgres/Supabase database. One client,
// sequential queries (pg forbids overlapping queries on a single client), all
// inside a single `begin isolation level repeatable read read only` transaction
// that is rolled back at the end: every query sees the same snapshot, and the
// server rejects any write.
//
// Only the `public` schema is inspected — it's the schema Supabase exposes
// through the Data API by default. Projects that expose extra schemas
// ("Exposed schemas" setting) are not covered.
//
// Role checks join pg_roles instead of naming 'anon'/'authenticated' as text
// literals, so a database without those roles returns no rows rather than a
// "role does not exist" error. search_path is set to '' for the transaction
// so regprocedure/regclass output is always schema-qualified.

export const MIN_MAINTAIN_VERSION = 170000;

const SQL_VERSION = `
select current_setting('server_version_num')::int as server_version_num;`;

// Partitions (relispartition) are listed as tables of their own: RLS and
// grants on a partition are separate from its parent's.
const SQL_TABLES = `
select n.nspname as schema, c.relname as table,
       c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced,
       c.relispartition as is_partition
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and n.nspname = 'public'
order by c.relname;`;

const SQL_POLICIES = `
select schemaname as schema, tablename as table, policyname as policy,
       permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;`;

// Table privileges the server knows about. MAINTAIN only exists from 17 on;
// passing it to has_table_privilege on an older server is an error.
export function tablePrivileges(serverVersionNum) {
  const privs = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];
  return serverVersionNum >= MIN_MAINTAIN_VERSION ? [...privs, 'MAINTAIN'] : privs;
}

// One row per (table, API role, privilege) the role holds, however obtained
// (by name, via PUBLIC, via membership). table_level = false means the role
// only holds it on some columns (has_any_column_privilege), i.e. "partially
// granted". has_any_column_privilege only accepts these four privileges.
export function grantsSql(serverVersionNum) {
  const values = tablePrivileges(serverVersionNum).map(p => `('${p}')`).join(', ');
  return `
select c.relname as table, r.rolname::text as grantee, p.privilege,
       has_table_privilege(r.oid, c.oid, p.privilege) as table_level
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join pg_roles r on r.rolname in ('anon', 'authenticated')
cross join (values ${values}) as p(privilege)
where c.relkind in ('r', 'p') and n.nspname = 'public'
  and (has_table_privilege(r.oid, c.oid, p.privilege)
       or case when p.privilege in ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
               then has_any_column_privilege(r.oid, c.oid, p.privilege)
               else false end)
order by c.relname, r.rolname, p.privilege;`;
}

// Sequences owned by a public table's column: 'a' = serial / owned by,
// 'i' = identity column.
const SQL_OWNED_SEQUENCES = `
select t.relname as table, sn.nspname as sequence_schema, s.relname as sequence
from pg_class s
join pg_namespace sn on sn.oid = s.relnamespace
join pg_depend d on d.classid = 'pg_class'::regclass and d.objid = s.oid
                and d.refclassid = 'pg_class'::regclass and d.deptype in ('a', 'i')
join pg_class t on t.oid = d.refobjid
join pg_namespace tn on tn.oid = t.relnamespace
where s.relkind = 'S' and tn.nspname = 'public'
order by t.relname, s.relname;`;

const SQL_SEQUENCE_GRANTS = `
select n.nspname as sequence_schema, c.relname as sequence, r.rolname::text as grantee, p.privilege
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join pg_roles r on r.rolname in ('anon', 'authenticated')
cross join (values ('SELECT'), ('USAGE'), ('UPDATE')) as p(privilege)
where c.relkind = 'S' and n.nspname = 'public'
  and has_sequence_privilege(r.oid, c.oid, p.privilege)
order by c.relname, r.rolname, p.privilege;`;

const SQL_VIEWS = `
select n.nspname as schema, c.relname as view,
       coalesce(lower(opt.option_value), 'false') in ('true', 'on', '1', 'yes') as security_invoker,
       array(select r.rolname::text from pg_roles r
             where r.rolname in ('anon', 'authenticated')
               and has_table_privilege(r.oid, c.oid, 'SELECT')
             order by r.rolname) as selectable_by
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join lateral (
  select option_value from pg_options_to_table(c.reloptions) where option_name = 'security_invoker'
) opt on true
where c.relkind = 'v' and n.nspname = 'public'
order by c.relname;`;

const SQL_MATVIEWS = `
select n.nspname as schema, c.relname as matview,
       array(select r.rolname::text from pg_roles r
             where r.rolname in ('anon', 'authenticated')
               and has_table_privilege(r.oid, c.oid, 'SELECT')
             order by r.rolname) as selectable_by
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'm' and n.nspname = 'public'
order by c.relname;`;

// Only the object kinds the default-grant change covers: r (tables and
// views), S (sequences), f (functions and procedures).
const SQL_DEFAULT_PRIVILEGES = `
select pg_get_userbyid(d.defaclrole) as role, n.nspname as schema,
       d.defaclobjtype as object_type, d.defaclacl::text[] as acl
from pg_default_acl d
join pg_namespace n on n.oid = d.defaclnamespace
where n.nspname = 'public' and d.defaclobjtype in ('r', 'S', 'f')
order by 1, 3;`;

const SQL_FUNCTIONS = `
select n.nspname as schema, p.proname as name,
       p.oid::regprocedure::text as signature,
       p.prosecdef as security_definer,
       p.proconfig as proconfig,
       p.prorettype = 'trigger'::regtype as is_trigger,
       exists (select 1 from pg_roles r where r.rolname = 'anon'
               and has_function_privilege(r.oid, p.oid, 'EXECUTE')) as anon_can_execute,
       exists (select 1 from pg_roles r where r.rolname = 'authenticated'
               and has_function_privilege(r.oid, p.oid, 'EXECUTE')) as authenticated_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prokind in ('f', 'p')
order by p.proname, 3;`;

// `set search_path = ''` counts as set — it's the recommended value.
export function hasSearchPath(proconfig) {
  return Array.isArray(proconfig) && proconfig.some(c => String(c).toLowerCase().startsWith('search_path='));
}

export const TRANSACTION = {
  BEGIN: 'begin isolation level repeatable read read only',
  SEARCH_PATH: "set local search_path = ''",
  ROLLBACK: 'rollback',
};

// databaseUrl: postgres:// connection string. deps.Client lets tests inject a
// fake pg Client without a real database.
export async function introspect(databaseUrl, deps = {}) {
  let Client = deps.Client;
  if (!Client) {
    const pg = await import('pg');
    Client = pg.default?.Client ?? pg.Client;
  }
  const client = new Client({
    connectionString: databaseUrl,
    ssl: /localhost|127\.0\.0\.1/.test(databaseUrl) ? false : { rejectUnauthorized: false },
  });
  await client.connect();
  try {
    await client.query(TRANSACTION.BEGIN);
    try {
      await client.query(TRANSACTION.SEARCH_PATH);
      const serverVersionNum = Number((await client.query(SQL_VERSION)).rows[0].server_version_num);
      const q = async sql => (await client.query(sql)).rows;
      return {
        serverVersionNum,
        tables: await q(SQL_TABLES),
        policies: await q(SQL_POLICIES),
        grants: await q(grantsSql(serverVersionNum)),
        ownedSequences: await q(SQL_OWNED_SEQUENCES),
        sequenceGrants: await q(SQL_SEQUENCE_GRANTS),
        views: await q(SQL_VIEWS),
        matviews: await q(SQL_MATVIEWS),
        defaultPrivileges: await q(SQL_DEFAULT_PRIVILEGES),
        functions: (await q(SQL_FUNCTIONS)).map(f => ({ ...f, has_search_path: hasSearchPath(f.proconfig) })),
      };
    } finally {
      await client.query(TRANSACTION.ROLLBACK);
    }
  } finally {
    await client.end();
  }
}

export const SQL = {
  SQL_VERSION,
  SQL_TABLES,
  SQL_POLICIES,
  SQL_OWNED_SEQUENCES,
  SQL_SEQUENCE_GRANTS,
  SQL_VIEWS,
  SQL_MATVIEWS,
  SQL_DEFAULT_PRIVILEGES,
  SQL_FUNCTIONS,
};
