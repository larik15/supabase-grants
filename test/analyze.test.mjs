import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { replayEffectiveState, effectiveStateToArray, functionsToArray } from '../src/static/replay.mjs';
import { analyzeEffectiveState, summarizeFindings, exitCodeForFindings } from '../src/static/analyze.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'migrations');

function analyzeScenario(name, opts) {
  const dir = path.join(FIXTURES_ROOT, name);
  const files = readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .map(f => ({ name: f, sql: readFileSync(path.join(dir, f), 'utf8') }));
  const { tables, functions } = replayEffectiveState(files);
  return analyzeEffectiveState(
    { tables: effectiveStateToArray(tables), functions: functionsToArray(functions) },
    opts
  );
}

function byKind(findings, kind) {
  return findings.filter(f => f.kind === kind);
}

// --- table_without_explicit_grant --------------------------------------

test('table_without_explicit_grant fires when no grant exists anywhere, medium before cutover', () => {
  const findings = analyzeScenario('create-no-grant', { now: '2026-01-01' });
  const f = byKind(findings, 'table_without_explicit_grant');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
  assert.equal(f[0].table, 'public.orders');
});

test('table_without_explicit_grant is high after the 2026-10-30 cutover', () => {
  const findings = analyzeScenario('create-no-grant', { now: '2026-11-01' });
  assert.equal(byKind(findings, 'table_without_explicit_grant')[0].severity, 'high');
});

test('an explicit direct grant clears table_without_explicit_grant', () => {
  const findings = analyzeScenario('grant-after-create', { now: '2026-01-01' });
  assert.equal(byKind(findings, 'table_without_explicit_grant').length, 0);
});

test('grant-all-tables-in-schema BEFORE the create still leaves the table flagged (no false negative)', () => {
  const findings = analyzeScenario('grant-all-before', { now: '2026-01-01' });
  const f = byKind(findings, 'table_without_explicit_grant');
  assert.equal(f.length, 1);
  assert.equal(f[0].table, 'public.late_table');
});

test('grant-all-tables-in-schema AFTER the create clears the flag (no false positive)', () => {
  const findings = analyzeScenario('grant-all-after', { now: '2026-01-01' });
  assert.equal(byKind(findings, 'table_without_explicit_grant').length, 0);
});

test('a table outside public with no grant gets info-level not_in_api_schema, not table_without_explicit_grant', () => {
  const { tables } = replayEffectiveState([
    { name: '0001.sql', sql: `create table private.secrets (id uuid);` },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-11-01' });
  assert.equal(byKind(findings, 'table_without_explicit_grant').length, 0);
  const f = byKind(findings, 'not_in_api_schema');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'info');
  assert.equal(f[0].table, 'private.secrets');
});

test('a table outside public WITH an explicit grant gets neither finding', () => {
  const { tables } = replayEffectiveState([
    { name: '0001.sql', sql: `create table private.secrets (id uuid); grant select on private.secrets to authenticated;` },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'table_without_explicit_grant').length, 0);
  assert.equal(byKind(findings, 'not_in_api_schema').length, 0);
});

// --- rls_disabled --------------------------------------------------------

test('rls_disabled does not fire when RLS is enabled', () => {
  const findings = analyzeScenario('grant-after-create', { now: '2026-01-01' });
  assert.equal(byKind(findings, 'rls_disabled').length, 0);
});

test('rls disabled + explicit grant present -> critical rls_disabled finding', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        grant select on public.t to authenticated;
      `,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  const f = byKind(findings, 'rls_disabled');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'critical');
});

function rlsDisabledFor(sql) {
  const { tables } = replayEffectiveState([{ name: '0001.sql', sql }]);
  return byKind(analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' }), 'rls_disabled');
}

test('public table without RLS and no grant at all is still critical (legacy default grants expose it)', () => {
  const f = rlsDisabledFor(`create table public.t (id uuid);`);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'critical');
  assert.match(f[0].message, /legacy default grants/);
});

test('public table without RLS is medium once the migrations explicitly revoke from both anon and authenticated', () => {
  const f = rlsDisabledFor(`
    create table public.t (id uuid);
    revoke all on public.t from anon, authenticated;
  `);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
});

test('a revoke from anon alone does not lower rls_disabled (authenticated still has the defaults)', () => {
  const f = rlsDisabledFor(`
    create table public.t (id uuid);
    revoke all on public.t from anon;
  `);
  assert.equal(f[0].severity, 'critical');
});

test('revoke on all tables in schema after the create counts as an explicit revoke', () => {
  const f = rlsDisabledFor(`
    create table public.t (id uuid);
    revoke all on all tables in schema public from anon, authenticated;
  `);
  assert.equal(f[0].severity, 'medium');
});

test('revoke then an explicit re-grant is critical again', () => {
  const f = rlsDisabledFor(`
    create table public.t (id uuid);
    revoke all on public.t from anon, authenticated;
    grant select on public.t to anon;
  `);
  assert.equal(f[0].severity, 'critical');
});

test('a non-public table without RLS and without an explicit grant is not flagged (not in the API schema)', () => {
  assert.equal(rlsDisabledFor(`create table private.t (id uuid);`).length, 0);
});

// --- policy_no_to_clause / policy_open_* ---------------------------------

test('policy with no TO clause -> policy_no_to_clause, severity high for a write command', () => {
  const { tables } = replayEffectiveState([
    { name: '0001.sql', sql: `create table public.t (id uuid); create policy p on public.t for delete using (true);` },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  const f = byKind(findings, 'policy_no_to_clause');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
});

test('policy_open_read for using (true) on a SELECT policy, high when anon is included', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `create table public.t (id uuid); create policy p on public.t for select to anon using (true);`,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  const f = byKind(findings, 'policy_open_read');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
});

test('policy_open_insert for with check (true)', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `create table public.t (id uuid); create policy p on public.t for insert to authenticated with check (true);`,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'policy_open_insert').length, 1);
});

test('policy_open_write (critical) for UPDATE/DELETE using (true)', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `create table public.t (id uuid); create policy p on public.t for delete to authenticated using (true);`,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  const f = byKind(findings, 'policy_open_write');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'critical');
});

test('a RESTRICTIVE using (true) policy does not trigger policy_open_read/write (addition 4)', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        create policy p on public.t as restrictive for select to authenticated using (true);
      `,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'policy_open_read').length, 0);
  assert.equal(byKind(findings, 'policy_open_write').length, 0);
});

test('an ownership-checked policy (not true) produces no policy_open_* findings', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `
        create table public.t (id uuid);
        create policy p on public.t for select to authenticated using (auth.uid() = user_id);
      `,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'policy_open_read').length, 0);
});

// --- definer_no_search_path ----------------------------------------------

test('definer_no_search_path fires for security definer without set search_path', () => {
  const { functions } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `create function public.f() returns int language sql security definer as $$ select 1; $$;`,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: [], functions: functionsToArray(functions) }, { now: '2026-01-01' });
  const f = byKind(findings, 'definer_no_search_path');
  assert.equal(f.length, 1);
  assert.equal(f[0].function, 'public.f');
});

test('definer_no_search_path does not fire when search_path is set', () => {
  const { functions } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `create function public.f() returns int language sql security definer set search_path = '' as $$ select 1; $$;`,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: [], functions: functionsToArray(functions) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'definer_no_search_path').length, 0);
});

test('a non-definer function is never flagged', () => {
  const { functions } = replayEffectiveState([
    { name: '0001.sql', sql: `create function public.f() returns int language sql as $$ select 1; $$;` },
  ]);
  const findings = analyzeEffectiveState({ tables: [], functions: functionsToArray(functions) }, { now: '2026-01-01' });
  assert.equal(byKind(findings, 'definer_no_search_path').length, 0);
});

// --- summary / exit code --------------------------------------------------

test('summarizeFindings counts by severity', () => {
  const summary = summarizeFindings([{ severity: 'critical' }, { severity: 'high' }, { severity: 'high' }, { severity: 'info' }]);
  assert.deepEqual(summary, { critical: 1, high: 2, medium: 0, low: 0, info: 1 });
});

test('exitCodeForFindings: critical > high > clean', () => {
  assert.equal(exitCodeForFindings([{ severity: 'critical' }]), 2);
  assert.equal(exitCodeForFindings([{ severity: 'high' }]), 1);
  assert.equal(exitCodeForFindings([{ severity: 'medium' }, { severity: 'info' }]), 0);
  assert.equal(exitCodeForFindings([]), 0);
});

test('findings are sorted most-severe first', () => {
  const { tables } = replayEffectiveState([
    {
      name: '0001.sql',
      sql: `
        create table public.a (id uuid);
        create table public.b (id uuid);
        grant select on public.b to authenticated;
        create policy p on public.b for delete to authenticated using (true);
      `,
    },
  ]);
  const findings = analyzeEffectiveState({ tables: effectiveStateToArray(tables) }, { now: '2026-01-01' });
  const severities = findings.map(f => f.severity);
  const rank = { critical: 0, high: 1, medium: 2, info: 3 };
  for (let i = 1; i < severities.length; i++) {
    assert.ok(rank[severities[i - 1]] <= rank[severities[i]]);
  }
});

// --- second review round ----------------------------------------------------

function findingsFor(sql, opts = { now: '2026-01-01' }) {
  const { tables, functions } = replayEffectiveState([{ name: '0001.sql', sql }]);
  return analyzeEffectiveState({ tables: effectiveStateToArray(tables), functions: functionsToArray(functions) }, opts);
}

for (const expr of ['true', '(true)', '((true))', '1=1', '1 = 1', 'TRUE']) {
  test(`policy_open_read matches the literal pattern using (${expr})`, () => {
    const f = findingsFor(`create table public.t (id int); create policy p on public.t for select to authenticated using (${expr});`);
    assert.equal(byKind(f, 'policy_open_read').length, 1);
  });
}

test('a non-literal always-true expression is not matched (documented limitation)', () => {
  const f = findingsFor('create table public.t (id int); create policy p on public.t for select to authenticated using (2 > 1);');
  assert.equal(byKind(f, 'policy_open_read').length, 0);
});

for (const expr of [
  'auth.uid() is not null',
  '(select auth.uid()) IS NOT NULL',
  "auth.role() = 'authenticated'",
  "(auth.role() = 'authenticated'::text)",
  'auth.jwt() is not null',
]) {
  test(`policy_open_to_all_authenticated matches: ${expr}`, () => {
    const f = findingsFor(`create table public.t (id int); create policy p on public.t for update to authenticated using (${expr});`);
    const hit = byKind(f, 'policy_open_to_all_authenticated');
    assert.equal(hit.length, 1);
    assert.equal(hit[0].severity, 'medium');
  });
}

test('policy_open_to_all_authenticated reads with check for INSERT policies', () => {
  const f = findingsFor('create table public.t (id int); create policy p on public.t for insert to authenticated with check (auth.uid() is not null);');
  assert.equal(byKind(f, 'policy_open_to_all_authenticated').length, 1);
});

test('an ownership check is not "open to all authenticated"', () => {
  const f = findingsFor('create table public.t (id int); create policy p on public.t for select to authenticated using (auth.uid() = user_id);');
  assert.equal(byKind(f, 'policy_open_to_all_authenticated').length, 0);
});

test('a grant to PUBLIC counts as an explicit grant (no table_without_explicit_grant)', () => {
  const f = findingsFor('create table public.t (id int); alter table public.t enable row level security; grant select on public.t to public;');
  assert.equal(byKind(f, 'table_without_explicit_grant').length, 0);
});

test('a partition without its own grant is not table_without_explicit_grant', () => {
  const f = findingsFor(`
    create table public.events (id int, at date) partition by range (at);
    grant select on public.events to authenticated;
    create table public.events_2024 partition of public.events for values from ('2024-01-01') to ('2025-01-01');
  `);
  assert.deepEqual(byKind(f, 'table_without_explicit_grant').map(x => x.table), []);
});

test('SECURITY DEFINER trigger functions are not definer_no_search_path', () => {
  const f = findingsFor('create function public.t() returns trigger language plpgsql security definer as $$ begin return new; end $$;');
  assert.equal(byKind(f, 'definer_no_search_path').length, 0);
});

test('alter function ... set search_path in a later statement clears definer_no_search_path', () => {
  const f = findingsFor(`
    create function public.f() returns int language sql security definer as $$ select 1 $$;
    alter function public.f() set search_path = '';
  `);
  assert.equal(byKind(f, 'definer_no_search_path').length, 0);
});

test("create function ... set search_path = '' counts as set", () => {
  const f = findingsFor("create function public.f() returns int language sql security definer set search_path = '' as $$ select 1 $$;");
  assert.equal(byKind(f, 'definer_no_search_path').length, 0);
});
