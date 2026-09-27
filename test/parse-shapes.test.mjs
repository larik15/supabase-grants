import test from 'node:test';
import assert from 'node:assert/strict';
import { splitStatements, classifyStatement, parseMigration } from '../src/static/parse.mjs';

// --- tokenizer --------------------------------------------------------------

test('splitStatements: strips a UTF-8 BOM and copes with CRLF and tabs', () => {
  const stmts = splitStatements('\uFEFFcreate table\tpublic.t (id uuid);\r\ngrant select on public.t to anon;\r\n');
  assert.equal(stmts.length, 2);
  assert.equal(classifyStatement(stmts[0]).type, 'create_table');
});

test("splitStatements: E'...' strings honour backslash-escaped quotes", () => {
  const stmts = splitStatements(String.raw`insert into t values (E'it\'s; fine'); select 1;`);
  assert.equal(stmts.length, 2);
  assert.match(stmts[0], /it\\'s; fine/);
});

test('splitStatements: a plain string ending in a backslash is not an escape', () => {
  // standard_conforming_strings: backslash is literal outside E'...'
  const stmts = splitStatements(String.raw`select 'C:\'; select 2;`);
  assert.equal(stmts.length, 2);
});

test('splitStatements: $tag$ inside a $$ body, and -- inside a dollar body, do not end anything', () => {
  const sql = 'create function f() returns int language plpgsql as $$ begin -- no; end\n perform $x$ ; $x$; return 1; end; $$; select 2;';
  const stmts = splitStatements(sql);
  assert.equal(stmts.length, 2);
  assert.match(stmts[0], /return 1; end; \$\$$/);
});

test('splitStatements: $1 parameters and identifiers containing $ are not dollar quotes', () => {
  assert.equal(splitStatements('prepare p as select $1; select a$b$c from t; select 3;').length, 3);
});

// --- search_path tracking ---------------------------------------------------

test('set search_path changes the schema of later unqualified creates in the same file', () => {
  const stmts = parseMigration('create table a (id int); set search_path = app, public; create table b (id int);');
  assert.equal(stmts[0].schema, 'public');
  assert.deepEqual(stmts[1], { type: 'set_search_path', schemas: ['app', 'public'] });
  assert.equal(stmts[2].schema, 'app');
});

test("pg_dump style set_config('search_path', '', false) falls back to public", () => {
  const stmts = parseMigration("select pg_catalog.set_config('search_path', '', false); create table a (id int);");
  assert.deepEqual(stmts[0], { type: 'set_search_path', schemas: [] });
  assert.equal(stmts[1].schema, 'public');
});

test('"$user", pg_catalog and quoted names in search_path', () => {
  assert.deepEqual(classifyStatement('set search_path to "$user", "App", pg_catalog').schemas, ['App']);
});

test('unqualified references carry the search path so replay can resolve them', () => {
  const [, grant] = parseMigration('set search_path = app, public; grant select on t to anon;');
  assert.deepEqual(grant.target.tables, [{ schema: 'app', name: 't', searchPath: ['app', 'public'] }]);
});

// --- statement shapes --------------------------------------------------------

test('alter table only ... and alter table if exists only ...', () => {
  assert.equal(classifyStatement('alter table only public.t enable row level security').action, 'enable');
  assert.equal(classifyStatement('alter table if exists only public.t disable row level security').action, 'disable');
});

test('"public"."t" quoting resolves to the same table as public.t', () => {
  const s = classifyStatement('create table "public"."t" (id int)');
  assert.equal(s.schema, 'public');
  assert.equal(s.name, 't');
});

test('alter table ... set schema', () => {
  assert.deepEqual(classifyStatement('alter table public.t set schema archive'), {
    type: 'alter_table_set_schema', schema: 'public', name: 't', newSchema: 'archive',
  });
});

test('drop schema ... cascade', () => {
  assert.deepEqual(classifyStatement('drop schema if exists old, older cascade'), { type: 'drop_schema', schemas: ['old', 'older'], cascade: true });
  assert.equal(classifyStatement('drop schema old').cascade, false);
});

test('grant ... to public keeps PUBLIC as a role', () => {
  assert.deepEqual(classifyStatement('grant select on public.t to public').roles, ['public']);
});

test('grant on a schema is not mistaken for a table called "schema"', () => {
  const s = classifyStatement('grant usage on schema public to anon');
  assert.equal(s.target.kind, 'other_object');
});

test('column-level grants are recognised and flagged', () => {
  const s = classifyStatement('grant select (id, name), update (name) on public.t to authenticated');
  assert.deepEqual(s.privileges, ['SELECT', 'UPDATE']);
  assert.equal(s.columnLevel, true);
});

test('with grant option / granted by are not taken as role names', () => {
  assert.deepEqual(classifyStatement('grant select on public.t to authenticated with grant option').roles, ['authenticated']);
});

test('alter function ... set search_path / security definer', () => {
  assert.deepEqual(classifyStatement("alter function public.f(uuid, text) set search_path = ''"), {
    type: 'alter_function', schema: 'public', name: 'f', searchPathSet: true,
  });
  assert.equal(classifyStatement('alter function public.f() security definer').securityDefiner, true);
  assert.equal(classifyStatement('alter function public.f() owner to postgres').type, 'other');
});

test('create table ... partition of', () => {
  const s = classifyStatement("create table public.events_2024 partition of public.events for values from ('2024-01-01') to ('2025-01-01')");
  assert.deepEqual(s.partitionOf, { schema: 'public', name: 'events' });
});

test('create procedure is tracked like a function', () => {
  const s = classifyStatement("create or replace procedure public.p() language sql security definer as $$ select 1 $$");
  assert.equal(s.type, 'create_function');
  assert.equal(s.routine, 'procedure');
  assert.equal(s.securityDefiner, true);
});

test('security definer / search_path / returns trigger are read from the header, not the body', () => {
  const s = classifyStatement("create function public.f() returns int language plpgsql as $$ begin execute 'set search_path = x'; return 1; end $$");
  assert.equal(s.searchPathSet, false);
  const t = classifyStatement('create function public.t() returns trigger language plpgsql security definer as $$ begin return new; end $$');
  assert.equal(t.isTrigger, true);
});

test('temporary tables are ignored', () => {
  assert.equal(classifyStatement('create temp table scratch (id int)').type, 'other');
});

// --- unparsed ---------------------------------------------------------------

test('DO blocks and dynamic SQL are "unparsed", ordinary irrelevant statements are "other"', () => {
  assert.equal(classifyStatement("do $$ begin execute 'grant select on t to anon'; end $$").type, 'unparsed');
  assert.equal(classifyStatement("execute 'revoke all on t from anon'").type, 'unparsed');
  assert.equal(classifyStatement('create index on public.t (id)').type, 'other');
  assert.equal(classifyStatement("comment on table public.t is 'x'").type, 'other');
});

test('a relevant statement in a shape we cannot interpret is "unparsed"', () => {
  assert.equal(classifyStatement('grant select on (weird) to anon').type, 'unparsed');
  assert.equal(classifyStatement('grant anon to authenticator').type, 'other'); // role membership, not a table grant
});
