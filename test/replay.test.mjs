import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { replayFiles, effectiveStateToArray } from '../src/static/replay.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'migrations');

function loadScenario(name) {
  const dir = path.join(FIXTURES_ROOT, name);
  const files = readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .map(f => ({ name: f, sql: readFileSync(path.join(dir, f), 'utf8') }));
  return replayFiles(files);
}

test('(a) create table, no grant anywhere: table exists, no explicit grants', () => {
  const tables = loadScenario('create-no-grant');
  const [orders] = effectiveStateToArray(tables);
  assert.equal(orders.name, 'orders');
  assert.equal(orders.rlsEnabled, true);
  assert.deepEqual(orders.grants, {});
  assert.equal(orders.policies.length, 1);
  assert.equal(orders.policies[0].roles[0], 'authenticated');
});

test('(b) grant after create: table has the explicit grants', () => {
  const tables = loadScenario('grant-after-create');
  const [notes] = effectiveStateToArray(tables);
  assert.deepEqual(notes.grants.authenticated, ['INSERT', 'SELECT']);
  assert.deepEqual(notes.grants.anon, ['SELECT']);
});

test('(c1) grant on all tables in schema BEFORE the create does not cover it', () => {
  const tables = loadScenario('grant-all-before');
  const [late] = effectiveStateToArray(tables);
  assert.equal(late.name, 'late_table');
  assert.deepEqual(late.grants, {});
});

test('(c2) grant on all tables in schema AFTER the create covers it', () => {
  const tables = loadScenario('grant-all-after');
  const [early] = effectiveStateToArray(tables);
  assert.equal(early.name, 'early_table');
  assert.deepEqual(early.grants.authenticated, ['SELECT']);
});

test('(d) policy dropped in a later migration is gone from effective state, grant remains', () => {
  const tables = loadScenario('policy-dropped');
  const [comments] = effectiveStateToArray(tables);
  assert.equal(comments.policies.length, 0);
  assert.deepEqual(comments.grants.authenticated, ['SELECT']);
});

test('(e) RLS disabled then re-enabled across files ends up enabled', () => {
  const tables = loadScenario('rls-toggle');
  const [auditLog] = effectiveStateToArray(tables);
  assert.equal(auditLog.rlsEnabled, true);
});

test('(f) dollar-quoted function body with semicolons does not break replay of surrounding statements', () => {
  const tables = loadScenario('dollar-quoted-function');
  const [widgets] = effectiveStateToArray(tables);
  assert.equal(widgets.name, 'widgets');
  assert.equal(widgets.rlsEnabled, true);
  assert.deepEqual(widgets.grants.authenticated, ['SELECT']);
});

test('(g) quoted, mixed-case identifiers and a semicolon inside a string literal default', () => {
  const tables = loadScenario('quoted-identifiers');
  const [orders] = effectiveStateToArray(tables);
  assert.equal(orders.schema, 'Public');
  assert.equal(orders.name, 'Orders');
  assert.equal(orders.policies[0].name, 'Orders Select Own');
  assert.deepEqual(orders.grants.authenticated, ['SELECT']);
});

test('addition 1: "create table if not exists" for an existing table does not reset its state', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        alter table public.t enable row level security;
        create policy p on public.t for select to authenticated using (true);
        grant select on public.t to authenticated;
        create table if not exists public.t (id uuid);
      `,
    },
  ]);
  const [t] = effectiveStateToArray(tables);
  assert.equal(t.rlsEnabled, true);
  assert.equal(t.policies.length, 1);
  assert.deepEqual(t.grants.authenticated, ['SELECT']);
});

test('addition 2: a policy with no TO clause gets roles: ["public"]', () => {
  const tables = replayFiles([
    { name: '0001.sql', sql: `create table public.t (id uuid); create policy p on public.t for select using (true);` },
  ]);
  const [t] = effectiveStateToArray(tables);
  assert.deepEqual(t.policies[0].roles, ['public']);
});

test('addition 3: grants to service_role are recorded alongside anon/authenticated', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        grant select on public.t to anon;
        grant select, insert, update, delete on public.t to authenticated;
        grant all privileges on public.t to service_role;
      `,
    },
  ]);
  const [t] = effectiveStateToArray(tables);
  assert.deepEqual(t.grants.anon, ['SELECT']);
  assert.deepEqual(t.grants.authenticated, ['DELETE', 'INSERT', 'SELECT', 'UPDATE']);
  assert.deepEqual(t.grants.service_role, ['DELETE', 'INSERT', 'SELECT', 'UPDATE']);
});

test('addition 4: "as restrictive" policies are flagged and kept distinct from permissive ones', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        create policy allow_all on public.t for select to authenticated using (true);
        create policy narrow on public.t as restrictive for select to authenticated using (org_id = current_org());
      `,
    },
  ]);
  const [t] = effectiveStateToArray(tables);
  const byName = Object.fromEntries(t.policies.map(p => [p.name, p]));
  assert.equal(byName.allow_all.permissive, true);
  assert.equal(byName.narrow.permissive, false);
});

test('default privileges granted before a create table are applied to the new table; not applied retroactively to earlier ones', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        create table public.early (id uuid);
        alter default privileges in schema public grant select on tables to authenticated;
        create table public.later (id uuid);
      `,
    },
  ]);
  const byName = Object.fromEntries(effectiveStateToArray(tables).map(t => [t.name, t]));
  assert.deepEqual(byName.early.grants, {});
  assert.deepEqual(byName.later.grants.authenticated, ['SELECT']);
});

test('drop table removes it from effective state entirely', () => {
  const tables = replayFiles([
    { name: '0001.sql', sql: `create table public.gone (id uuid);` },
    { name: '0002.sql', sql: `drop table public.gone;` },
  ]);
  assert.equal(tables.size, 0);
});

test('alter table rename to: renamed table keeps its RLS/policies/grants, and grants against the new name after the rename attach correctly', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        create table public.orders (id uuid);
        alter table public.orders enable row level security;
        create policy p on public.orders for select to authenticated using (auth.uid() = id);
        grant select on public.orders to authenticated;
        alter table public.orders rename to purchase_orders;
        grant insert on public.purchase_orders to authenticated;
      `,
    },
  ]);
  assert.equal(tables.has('public.orders'), false);
  const [t] = effectiveStateToArray(tables);
  assert.equal(t.name, 'purchase_orders');
  assert.equal(t.rlsEnabled, true);
  assert.equal(t.policies.length, 1);
  assert.equal(t.policies[0].table, 'purchase_orders');
  assert.deepEqual(t.grants.authenticated, ['INSERT', 'SELECT']);
});

test('alter table rename to for a table that does not exist is a no-op (does not crash or invent a table)', () => {
  const tables = replayFiles([{ name: '0001.sql', sql: `alter table public.ghost rename to also_ghost;` }]);
  assert.equal(tables.size, 0);
});

test('explicit revokes are recorded in revokedFrom (direct, all-tables, and default privileges)', () => {
  const tables = replayFiles([
    {
      name: '0001.sql',
      sql: `
        alter default privileges in schema public revoke all on tables from anon;
        create table public.a (id uuid);
        create table public.b (id uuid);
        revoke select on public.a from authenticated;
        revoke all on all tables in schema public from authenticated;
      `,
    },
  ]);
  const byName = Object.fromEntries(effectiveStateToArray(tables).map(t => [t.name, t]));
  assert.deepEqual(byName.a.revokedFrom, ['anon', 'authenticated']);
  assert.deepEqual(byName.b.revokedFrom, ['anon', 'authenticated']);
});

test('files are replayed in filename order regardless of array order passed in', () => {
  const tables = replayFiles([
    { name: '0002_grant.sql', sql: `grant select on all tables in schema public to authenticated;` },
    { name: '0001_create.sql', sql: `create table public.t (id uuid);` },
  ]);
  const [t] = effectiveStateToArray(tables);
  assert.deepEqual(t.grants.authenticated, ['SELECT']);
});
