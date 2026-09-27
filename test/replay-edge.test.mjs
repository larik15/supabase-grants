import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { replayEffectiveState, effectiveStateToArray, functionsToArray, compareFileNames } from '../src/static/replay.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'migrations');

function fixture(name) {
  const dir = path.join(FIXTURES, name);
  return readdirSync(dir).filter(f => f.endsWith('.sql')).map(f => ({ name: f, sql: readFileSync(path.join(dir, f), 'utf8') }));
}

function replaySql(...sqls) {
  return replayEffectiveState(sqls.map((sql, i) => ({ name: `${String(i + 1).padStart(4, '0')}.sql`, sql })));
}

test('fixture edge-encoding: CRLF + BOM + tabs + E-string, and nested dollar quotes, replay cleanly', () => {
  const files = fixture('edge-encoding');
  assert.ok(files[0].sql.includes('\r\n'), 'fixture must keep its CRLF line endings (see .gitattributes)');
  assert.equal(files[0].sql.charCodeAt(0), 0xfeff, 'fixture must keep its BOM');

  const { tables, functions, warnings, unparsed } = replayEffectiveState(files);
  const [notes] = effectiveStateToArray(tables);
  assert.equal(notes.name, 'notes');
  assert.equal(notes.rlsEnabled, true);
  assert.deepEqual(notes.grants.authenticated, ['SELECT']);
  assert.equal(notes.policies[0].name, 'notes read');
  assert.equal(functionsToArray(functions)[0].isTrigger, true);
  assert.deepEqual(warnings, []);
  assert.equal(unparsed.total, 0);
});

test('fixture filename-order: files are replayed in plain string order (B_ before a_), not locale order', () => {
  assert.equal(compareFileNames('B_create.sql', 'a_grant.sql'), -1);
  const { tables } = replayEffectiveState(fixture('filename-order'));
  // B_create.sql runs first, so the later all-tables grant covers the table.
  assert.deepEqual(effectiveStateToArray(tables)[0].grants.authenticated, ['SELECT']);
});

test('a grant or policy on a table no migration creates is a warning, and is not applied', () => {
  const { tables, warnings } = replaySql(
    'grant select on public.ghost to anon; create policy p on public.ghost for select using (true); alter table public.ghost enable row level security;'
  );
  assert.equal(tables.size, 0);
  assert.deepEqual(warnings.map(w => [w.statement, w.target, w.file]), [
    ['grant', 'public.ghost', '0001.sql'],
    ['create_policy', 'public.ghost', '0001.sql'],
    ['alter_table_rls', 'public.ghost', '0001.sql'],
  ]);
});

test('drop table if exists on a missing table is not a warning', () => {
  assert.deepEqual(replaySql('drop table if exists public.ghost;').warnings, []);
});

test('unparsed statements are counted per file', () => {
  const { unparsed } = replaySql(
    "create table public.t (id int); do $$ begin execute 'grant all on public.t to anon'; end $$;",
    'select 1;',
    'do $$ begin null; end $$; do $$ begin null; end $$;'
  );
  assert.deepEqual(unparsed, { total: 3, byFile: { '0001.sql': 1, '0003.sql': 2 } });
});

test('unqualified references resolve along the search path to an existing table', () => {
  const { tables } = replaySql(
    'create table public.t (id int);',
    'set search_path = app, public; grant select on t to anon;'
  );
  assert.deepEqual(effectiveStateToArray(tables)[0].grants.anon, ['SELECT']);
});

test('unqualified creates after set search_path land in the first schema', () => {
  const { tables } = replaySql('set search_path = app; create table t (id int);');
  assert.equal(effectiveStateToArray(tables)[0].schema, 'app');
});

test('search_path does not carry over to the next file', () => {
  const { tables } = replaySql('set search_path = app;', 'create table t (id int);');
  assert.equal(effectiveStateToArray(tables)[0].schema, 'public');
});

test('alter table ... set schema moves the table with its policies and grants', () => {
  const { tables } = replaySql(`
    create table public.t (id int);
    create policy p on public.t for select to authenticated using (true);
    grant select on public.t to authenticated;
    alter table public.t set schema archive;
  `);
  const [t] = effectiveStateToArray(tables);
  assert.equal(`${t.schema}.${t.name}`, 'archive.t');
  assert.equal(t.policies[0].schema, 'archive');
  assert.deepEqual(t.grants.authenticated, ['SELECT']);
});

test('drop schema cascade removes its tables; without cascade nothing is dropped', () => {
  assert.equal(replaySql('create table app.t (id int); drop schema app cascade;').tables.size, 0);
  assert.equal(replaySql('create table app.t (id int); drop schema app;').tables.size, 1);
});

test('revoke ... on all tables in schema only affects tables that exist at that point', () => {
  const { tables } = replaySql(`
    create table public.a (id int);
    grant select on public.a to anon;
    revoke all on all tables in schema public from anon;
    create table public.b (id int);
    grant select on public.b to anon;
  `);
  const byName = Object.fromEntries(effectiveStateToArray(tables).map(t => [t.name, t]));
  assert.deepEqual(byName.a.grants.anon, []);
  assert.deepEqual(byName.b.grants.anon, ['SELECT']);
});

test('grant ... to public is recorded under the public role', () => {
  const { tables } = replaySql('create table public.t (id int); grant select on public.t to public;');
  assert.deepEqual(effectiveStateToArray(tables)[0].grants.public, ['SELECT']);
});

test('a column-level revoke does not remove a table-level grant', () => {
  const { tables } = replaySql('create table public.t (id int, secret text); grant select on public.t to anon; revoke select (secret) on public.t from anon;');
  assert.deepEqual(effectiveStateToArray(tables)[0].grants.anon, ['SELECT']);
});

test('alter function set search_path updates the function created earlier', () => {
  const { functions } = replaySql(
    'create function public.f() returns int language sql security definer as $$ select 1 $$;',
    "alter function public.f() set search_path = '';"
  );
  assert.equal(functionsToArray(functions)[0].searchPathSet, true);
});

test('partitions record their parent', () => {
  const { tables } = replaySql(
    'create table public.events (id int, at date) partition by range (at);',
    "create table public.events_2024 partition of public.events for values from ('2024-01-01') to ('2025-01-01');"
  );
  const byName = Object.fromEntries(effectiveStateToArray(tables).map(t => [t.name, t]));
  assert.equal(byName.events_2024.partitionOf, 'public.events');
  assert.equal(byName.events.partitionOf, null);
});

test('grants on a view or materialized view created by a migration are not warnings', () => {
  const { warnings, tables } = replaySql(`
    create table public.t (id int);
    create view public.v with (security_invoker = true) as select * from public.t;
    create materialized view public.m as select * from public.t;
    grant select on public.v to authenticated;
    revoke all on public.m from anon;
  `);
  assert.deepEqual(warnings, []);
  assert.equal(tables.size, 1); // views are known, not analyzed as tables
});

test('a grant on a view after it is dropped is a warning again', () => {
  const { warnings } = replaySql('create view public.v as select 1; drop view public.v; grant select on public.v to anon;');
  assert.equal(warnings.length, 1);
});

test('policies on Supabase platform tables (storage.objects, auth.users) are not warnings', () => {
  const { warnings } = replaySql(`
    create policy "avatars" on storage.objects for select to authenticated using (bucket_id = 'avatars');
    drop policy if exists "old" on storage.objects;
    grant select on auth.users to authenticated;
  `);
  assert.deepEqual(warnings, []);
});
