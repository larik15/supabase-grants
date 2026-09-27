import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLive, parseAcl } from '../src/live/analyze.mjs';

function byKind(findings, kind) {
  return findings.filter(f => f.kind === kind);
}

function baseRows(overrides = {}) {
  return {
    tables: [{ schema: 'public', table: 'orders', rls_enabled: true, rls_forced: false }],
    policies: [],
    grants: [],
    defaultPrivileges: [],
    functions: [],
    ...overrides,
  };
}

test('grant_without_policy: anon has a privilege with no permissive policy backing it (high, since DELETE)', () => {
  const rows = baseRows({ grants: [{ table: 'orders', grantee: 'anon', privilege: 'DELETE' }] });
  const findings = analyzeLive(rows);
  const f = byKind(findings, 'grant_without_policy');
  assert.equal(f.length, 1);
  assert.equal(f[0].role, 'anon');
  assert.equal(f[0].privilege, 'DELETE');
  assert.equal(f[0].severity, 'high');
});

test('grant_without_policy: anon SELECT with no policy is medium', () => {
  const rows = baseRows({ grants: [{ table: 'orders', grantee: 'anon', privilege: 'SELECT' }] });
  const f = byKind(analyzeLive(rows), 'grant_without_policy');
  assert.equal(f[0].severity, 'medium');
});

test('grant_without_policy: authenticated with no policy is low', () => {
  const rows = baseRows({ grants: [{ table: 'orders', grantee: 'authenticated', privilege: 'UPDATE' }] });
  const f = byKind(analyzeLive(rows), 'grant_without_policy');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'low');
});

test('a matching permissive policy clears grant_without_policy', () => {
  const rows = baseRows({
    grants: [{ table: 'orders', grantee: 'authenticated', privilege: 'SELECT' }],
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT', qual: 'auth.uid() = user_id', with_check: null }],
  });
  assert.equal(byKind(analyzeLive(rows), 'grant_without_policy').length, 0);
});

test('an ALL-command policy satisfies every individual privilege', () => {
  const rows = baseRows({
    grants: [
      { table: 'orders', grantee: 'authenticated', privilege: 'SELECT' },
      { table: 'orders', grantee: 'authenticated', privilege: 'INSERT' },
    ],
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'ALL', qual: 'true', with_check: 'true' }],
  });
  assert.equal(byKind(analyzeLive(rows), 'grant_without_policy').length, 0);
});

test('policy_without_grant: a policy exists but the role has no matching privilege (info, dead policy)', () => {
  const rows = baseRows({
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT', qual: 'true', with_check: null }],
  });
  const f = byKind(analyzeLive(rows), 'policy_without_grant');
  assert.equal(f.length, 1);
  assert.equal(f[0].role, 'authenticated');
  assert.equal(f[0].privilege, 'SELECT');
  assert.equal(f[0].severity, 'info');
});

test('a RESTRICTIVE policy does not count as "needed" (addition 4 carried into live analysis)', () => {
  const rows = baseRows({
    grants: [{ table: 'orders', grantee: 'authenticated', privilege: 'SELECT' }],
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'RESTRICTIVE', roles: ['authenticated'], cmd: 'SELECT', qual: 'org_id = current_org()', with_check: null }],
  });
  const findings = analyzeLive(rows);
  // restrictive alone grants nothing, so the SELECT grant is still unbacked by any permissive policy.
  assert.equal(byKind(findings, 'grant_without_policy').length, 1);
  assert.equal(byKind(findings, 'policy_without_grant').length, 0);
});

test('rls_off_exposed: RLS disabled + an API-role grant is critical, and policy-level checks are skipped', () => {
  const rows = baseRows({
    tables: [{ schema: 'public', table: 'orders', rls_enabled: false, rls_forced: false }],
    grants: [{ table: 'orders', grantee: 'anon', privilege: 'SELECT' }],
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'PERMISSIVE', roles: [], cmd: 'SELECT', qual: 'true', with_check: null }],
  });
  const findings = analyzeLive(rows);
  assert.equal(byKind(findings, 'rls_off_exposed').length, 1);
  assert.equal(byKind(findings, 'rls_off_exposed')[0].severity, 'critical');
  // policies are inert with RLS off, so open-policy findings must not fire here.
  assert.equal(byKind(findings, 'policy_open_read').length, 0);
  assert.equal(byKind(findings, 'grant_without_policy').length, 0);
});

test('RLS disabled with no grants at all produces no finding (nothing reachable)', () => {
  const rows = baseRows({ tables: [{ schema: 'public', table: 'orders', rls_enabled: false, rls_forced: false }] });
  assert.equal(analyzeLive(rows).length, 0);
});

test('not_exposed: RLS on, zero grants to anon/authenticated', () => {
  const rows = baseRows();
  const f = byKind(analyzeLive(rows), 'not_exposed');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'info');
});

test('legacy_default_privileges: default ACL still exposes anon/authenticated', () => {
  const rows = baseRows({
    defaultPrivileges: [{ role: 'postgres', schema: 'public', object_type: 'r', acl: ['anon=r/postgres', 'authenticated=arwdDxt/postgres'] }],
  });
  const f = byKind(analyzeLive(rows), 'legacy_default_privileges');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'info');
});

test('legacy_default_privileges does not fire for a default ACL that only covers other roles', () => {
  const rows = baseRows({
    defaultPrivileges: [{ role: 'postgres', schema: 'public', object_type: 'r', acl: ['postgres=arwdDxt/postgres'] }],
  });
  assert.equal(byKind(analyzeLive(rows), 'legacy_default_privileges').length, 0);
});

test('definer_exposed + definer_no_search_path both fire for a definer function callable by anon with no search_path', () => {
  const rows = baseRows({
    tables: [],
    functions: [{ schema: 'public', name: 'f', args: '', security_definer: true, anon_can_execute: true, authenticated_can_execute: false, has_search_path: false }],
  });
  const findings = analyzeLive(rows);
  const exposed = byKind(findings, 'definer_exposed');
  assert.equal(exposed.length, 1);
  assert.equal(exposed[0].severity, 'high');
  assert.equal(byKind(findings, 'definer_no_search_path').length, 1);
});

test('a definer function only callable by authenticated is medium, not high', () => {
  const rows = baseRows({
    tables: [],
    functions: [{ schema: 'public', name: 'f', args: '', security_definer: true, anon_can_execute: false, authenticated_can_execute: true, has_search_path: true }],
  });
  const findings = analyzeLive(rows);
  assert.equal(byKind(findings, 'definer_exposed')[0].severity, 'medium');
  assert.equal(byKind(findings, 'definer_no_search_path').length, 0);
});

test('a non-definer function and one not executable by anon/authenticated produce nothing', () => {
  const rows = baseRows({
    tables: [],
    functions: [
      { schema: 'public', name: 'f', args: '', security_definer: false, anon_can_execute: true, authenticated_can_execute: true, has_search_path: false },
      { schema: 'public', name: 'g', args: '', security_definer: true, anon_can_execute: false, authenticated_can_execute: false, has_search_path: false },
    ],
  });
  const findings = analyzeLive(rows);
  assert.equal(byKind(findings, 'definer_exposed').length, 0);
  // g has no exposure but still has no search_path, and is still a definer function.
  assert.equal(byKind(findings, 'definer_no_search_path').length, 1);
});

// --- grant_dangerous_privilege ------------------------------------------

test('grant_dangerous_privilege: TRUNCATE held by anon is high, and fires even with RLS off', () => {
  const rows = baseRows({
    tables: [{ schema: 'public', table: 'orders', rls_enabled: false, rls_forced: false }],
    grants: [{ table: 'orders', grantee: 'anon', privilege: 'TRUNCATE' }],
  });
  const f = byKind(analyzeLive(rows), 'grant_dangerous_privilege');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.equal(f[0].privilege, 'TRUNCATE');
  assert.match(f[0].message, /not subject to RLS/);
});

test('grant_dangerous_privilege: REFERENCES and TRIGGER are medium, for authenticated too', () => {
  const rows = baseRows({
    grants: [
      { table: 'orders', grantee: 'authenticated', privilege: 'REFERENCES' },
      { table: 'orders', grantee: 'authenticated', privilege: 'TRIGGER' },
    ],
  });
  const f = byKind(analyzeLive(rows), 'grant_dangerous_privilege');
  assert.deepEqual(f.map(x => [x.privilege, x.severity]).sort(), [['REFERENCES', 'medium'], ['TRIGGER', 'medium']]);
});

test('only DML privileges count as "exposed": a table with just REFERENCES is still not_exposed', () => {
  const rows = baseRows({ grants: [{ table: 'orders', grantee: 'anon', privilege: 'REFERENCES' }] });
  assert.equal(byKind(analyzeLive(rows), 'not_exposed').length, 1);
});

// --- owned sequences on policy_without_grant ----------------------------

test('policy_without_grant carries the owned sequences the role still lacks usage/select on', () => {
  const rows = baseRows({
    policies: [{ schema: 'public', table: 'orders', policy: 'p', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: 'auth.uid() = user_id' }],
    ownedSequences: [{ table: 'orders', sequence_schema: 'public', sequence: 'orders_id_seq' }],
    sequenceGrants: [{ sequence_schema: 'public', sequence: 'orders_id_seq', grantee: 'authenticated', privilege: 'SELECT' }],
  });
  const [f] = byKind(analyzeLive(rows), 'policy_without_grant');
  assert.deepEqual(f.sequences, [{ sequence: 'public.orders_id_seq', privileges: ['USAGE'] }]);
});

// --- views ----------------------------------------------------------------

test('view_without_security_invoker: an anon-selectable view without security_invoker is high', () => {
  const rows = baseRows({ tables: [], views: [{ schema: 'public', view: 'v', security_invoker: false, selectable_by: ['anon', 'authenticated'] }] });
  const f = byKind(analyzeLive(rows), 'view_without_security_invoker');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.match(f[0].message, /Splinter/);
  assert.match(f[0].fix, /^alter view public\.v set \(security_invoker = true\);/);
  assert.match(f[0].fix, /Postgres 15\+/);
});

test('a view with security_invoker, or one no API role can select, is not flagged', () => {
  const rows = baseRows({
    tables: [],
    views: [
      { schema: 'public', view: 'safe', security_invoker: true, selectable_by: ['anon'] },
      { schema: 'public', view: 'internal', security_invoker: false, selectable_by: [] },
    ],
  });
  assert.equal(byKind(analyzeLive(rows), 'view_without_security_invoker').length, 0);
});

// --- legacy default privileges across object kinds -----------------------

test('legacy_default_privileges covers tables, sequences and functions and records exact grants', () => {
  const rows = baseRows({
    tables: [],
    defaultPrivileges: [
      { role: 'postgres', schema: 'public', object_type: 'r', acl: ['anon=arwdDxt/postgres', 'postgres=arwdDxt/postgres'] },
      { role: 'postgres', schema: 'public', object_type: 'S', acl: ['authenticated=rwU/postgres'] },
      { role: 'postgres', schema: 'public', object_type: 'f', acl: ['anon=X/postgres'] },
      { role: 'postgres', schema: 'public', object_type: 'T', acl: ['anon=U/postgres'] }, // types: out of scope
    ],
  });
  const f = byKind(analyzeLive(rows), 'legacy_default_privileges');
  assert.deepEqual(f.map(x => x.objectType).sort(), ['functions', 'sequences', 'tables']);
  const tables = f.find(x => x.objectType === 'tables');
  assert.deepEqual(tables.grants, [
    { grantee: 'anon', privileges: ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] },
  ]);
});

test('parseAcl: PUBLIC grantee, grant-option stars, quoted role names', () => {
  assert.deepEqual(parseAcl(['=r/postgres', 'anon=r*w/postgres', '"Weird Role"=X/postgres']), [
    { grantee: 'public', privileges: ['SELECT'] },
    { grantee: 'anon', privileges: ['SELECT', 'UPDATE'] },
    { grantee: 'Weird Role', privileges: ['EXECUTE'] },
  ]);
});

// --- second review round ----------------------------------------------------

const P = (cmd, extra = {}) => ({ schema: 'public', table: 'orders', policy: `p_${cmd}`, permissive: 'PERMISSIVE', roles: ['authenticated'], cmd, qual: 'auth.uid() = user_id', with_check: null, ...extra });

test('column-only privileges are "partially granted": never policy_without_grant, never grant_without_policy', () => {
  const rows = baseRows({
    policies: [P('SELECT')],
    grants: [
      { table: 'orders', grantee: 'authenticated', privilege: 'SELECT', table_level: false },
      { table: 'orders', grantee: 'anon', privilege: 'UPDATE', table_level: false },
    ],
  });
  const findings = analyzeLive(rows);
  assert.equal(byKind(findings, 'policy_without_grant').filter(f => f.privilege === 'SELECT').length, 0);
  assert.equal(byKind(findings, 'grant_without_policy').length, 0);
  // column grants still make the table reachable
  assert.equal(byKind(findings, 'not_exposed').length, 0);
});

test('write_without_select_policy: UPDATE/DELETE policies without a SELECT policy (medium)', () => {
  const rows = baseRows({ policies: [P('UPDATE'), P('DELETE')] });
  const f = byKind(analyzeLive(rows), 'write_without_select_policy');
  assert.equal(f.length, 1);
  assert.equal(f[0].role, 'authenticated');
  assert.equal(f[0].severity, 'medium');
  assert.match(f[0].message, /0 rows/);
});

test('write_without_select_policy does not fire when a SELECT or ALL policy exists', () => {
  assert.equal(byKind(analyzeLive(baseRows({ policies: [P('UPDATE'), P('SELECT')] })), 'write_without_select_policy').length, 0);
  assert.equal(byKind(analyzeLive(baseRows({ policies: [P('INSERT'), P('ALL')] })), 'write_without_select_policy').length, 0);
});

test('SELECT is never reported as grant_without_policy for a role that has a write policy', () => {
  const rows = baseRows({
    policies: [P('UPDATE')],
    grants: [
      { table: 'orders', grantee: 'authenticated', privilege: 'SELECT', table_level: true },
      { table: 'orders', grantee: 'authenticated', privilege: 'UPDATE', table_level: true },
    ],
  });
  const f = byKind(analyzeLive(rows), 'grant_without_policy');
  assert.ok(f.every(x => x.privilege !== 'SELECT'));
});

test('matview_exposed: a materialized view an API role can select is high', () => {
  const rows = baseRows({ tables: [], matviews: [{ schema: 'public', matview: 'stats', selectable_by: ['anon'] }] });
  const f = byKind(analyzeLive(rows), 'matview_exposed');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.match(f[0].message, /can't have RLS/);
  assert.match(f[0].message, /Splinter/);
  assert.equal(byKind(analyzeLive(baseRows({ tables: [], matviews: [{ schema: 'public', matview: 'x', selectable_by: [] }] })), 'matview_exposed').length, 0);
});

test('MAINTAIN held by an API role is grant_dangerous_privilege (medium)', () => {
  const rows = baseRows({ grants: [{ table: 'orders', grantee: 'anon', privilege: 'MAINTAIN', table_level: true }] });
  const f = byKind(analyzeLive(rows), 'grant_dangerous_privilege');
  assert.deepEqual(f.map(x => [x.privilege, x.severity]), [['MAINTAIN', 'medium']]);
});

test('trigger functions are skipped by the definer checks; findings are keyed by regprocedure signature', () => {
  const rows = baseRows({
    tables: [],
    functions: [
      { schema: 'public', name: 'trg', signature: 'public.trg()', security_definer: true, is_trigger: true, anon_can_execute: true, authenticated_can_execute: true, has_search_path: false },
      { schema: 'public', name: 'f', signature: 'public.f(uuid)', security_definer: true, is_trigger: false, anon_can_execute: true, authenticated_can_execute: false, has_search_path: false },
      { schema: 'public', name: 'f', signature: 'public.f(text)', security_definer: true, is_trigger: false, anon_can_execute: false, authenticated_can_execute: true, has_search_path: true },
    ],
  });
  const findings = analyzeLive(rows);
  assert.deepEqual(byKind(findings, 'definer_exposed').map(f => f.function).sort(), ['public.f(text)', 'public.f(uuid)']);
  assert.deepEqual(byKind(findings, 'definer_no_search_path').map(f => f.function), ['public.f(uuid)']);
  assert.match(byKind(findings, 'definer_no_search_path')[0].message, /may be exploitable/);
});

test('policy_open_to_all_authenticated is also reported by the live audit', () => {
  const rows = baseRows({ policies: [P('SELECT', { qual: '(auth.uid() IS NOT NULL)' })] });
  assert.equal(byKind(analyzeLive(rows), 'policy_open_to_all_authenticated').length, 1);
});
