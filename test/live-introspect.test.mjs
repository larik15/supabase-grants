import test from 'node:test';
import assert from 'node:assert/strict';
import { introspect, SQL, grantsSql, tablePrivileges, hasSearchPath, TRANSACTION } from '../src/live/introspect.mjs';

function fakeClientFor(serverVersionNum) {
  return class FakeClient {
    constructor(config) {
      FakeClient.lastConfig = config;
      FakeClient.calls = [];
    }
    async connect() {}
    async query(sql) {
      FakeClient.calls.push(sql);
      if (Object.values(TRANSACTION).includes(sql)) return { rows: [] };
      if (sql === SQL.SQL_VERSION) return { rows: [{ server_version_num: String(serverVersionNum) }] };
      if (sql === grantsSql(serverVersionNum)) return { rows: [{ table: 'orders', grantee: 'anon', privilege: 'DELETE', table_level: true }] };
      if (sql === SQL.SQL_TABLES) return { rows: [{ schema: 'public', table: 'orders', rls_enabled: true, rls_forced: false, is_partition: false }] };
      if (sql === SQL.SQL_FUNCTIONS) {
        return { rows: [{ schema: 'public', name: 'f', signature: 'public.f(uuid)', security_definer: true, proconfig: ['search_path=""'], is_trigger: false, anon_can_execute: true, authenticated_can_execute: false }] };
      }
      if (Object.values(SQL).includes(sql)) return { rows: [] };
      throw new Error(`FakeClient got an unexpected query: ${sql}`);
    }
    async end() {}
  };
}

test('introspect: returns every query result under its key, plus the server version', async () => {
  const Client = fakeClientFor(170004);
  const result = await introspect('postgres://user:pass@example.com:5432/postgres', { Client });
  assert.equal(result.serverVersionNum, 170004);
  assert.equal(result.tables[0].table, 'orders');
  assert.equal(result.grants[0].privilege, 'DELETE');
  assert.equal(result.functions[0].signature, 'public.f(uuid)');
  for (const key of ['policies', 'ownedSequences', 'sequenceGrants', 'views', 'matviews', 'defaultPrivileges']) {
    assert.deepEqual(result[key], [], key);
  }
});

test('introspect: everything runs in one repeatable-read read-only transaction that is rolled back', async () => {
  const Client = fakeClientFor(170004);
  await introspect('postgres://user:pass@example.com:5432/postgres', { Client });
  const calls = Client.calls;
  assert.equal(calls[0], 'begin isolation level repeatable read read only');
  assert.equal(calls[1], "set local search_path = ''");
  assert.equal(calls.at(-1), 'rollback');
  assert.equal(calls.filter(c => c.startsWith('begin')).length, 1);
});

test('introspect: MAINTAIN is only checked on Postgres 17+', () => {
  assert.deepEqual(tablePrivileges(150008), ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']);
  assert.ok(tablePrivileges(170000).includes('MAINTAIN'));
  assert.doesNotMatch(grantsSql(150008), /MAINTAIN/);
  assert.match(grantsSql(170004), /'MAINTAIN'/);
});

test('introspect: on Postgres 15 the grants query sent to the server never mentions MAINTAIN', async () => {
  const Client = fakeClientFor(150008);
  await introspect('postgres://user:pass@example.com:5432/postgres', { Client });
  assert.ok(Client.calls.every(c => !/MAINTAIN/.test(c)));
});

test('introspect: grants use has_table_privilege plus has_any_column_privilege for column-level grants', () => {
  const sql = grantsSql(170004);
  assert.match(sql, /has_table_privilege\(r\.oid, c\.oid, p\.privilege\) as table_level/);
  assert.match(sql, /has_any_column_privilege/);
  // has_any_column_privilege only accepts these four; the CASE keeps DELETE etc. away from it.
  assert.match(sql, /when p\.privilege in \('SELECT', 'INSERT', 'UPDATE', 'REFERENCES'\)/);
  assert.doesNotMatch(sql, /role_table_grants/);
});

test('introspect: tables include partitioned tables and partitions; default ACLs are filtered to r/S/f', () => {
  assert.match(SQL.SQL_TABLES, /relkind in \('r', 'p'\)/);
  assert.match(SQL.SQL_TABLES, /relispartition/);
  assert.match(SQL.SQL_DEFAULT_PRIVILEGES, /defaclobjtype in \('r', 'S', 'f'\)/);
  assert.match(SQL.SQL_MATVIEWS, /relkind = 'm'/);
});

test('introspect: functions are keyed by regprocedure and trigger functions are marked', () => {
  assert.match(SQL.SQL_FUNCTIONS, /oid::regprocedure::text as signature/);
  assert.match(SQL.SQL_FUNCTIONS, /prorettype = 'trigger'::regtype as is_trigger/);
});

test("hasSearchPath: set search_path = '' counts as set", () => {
  assert.equal(hasSearchPath(['search_path=""']), true);
  assert.equal(hasSearchPath(['search_path=public, pg_temp']), true);
  assert.equal(hasSearchPath(['work_mem=64MB']), false);
  assert.equal(hasSearchPath(null), false);
});

test('introspect: disables ssl for a localhost connection string, enables it otherwise', async () => {
  const Client = fakeClientFor(170004);
  await introspect('postgres://user:pass@localhost:5432/postgres', { Client });
  assert.equal(Client.lastConfig.ssl, false);
  await introspect('postgres://user:pass@example.supabase.com:5432/postgres', { Client });
  assert.deepEqual(Client.lastConfig.ssl, { rejectUnauthorized: false });
});

test('introspect: every catalog query is a plain SELECT', () => {
  for (const sql of [...Object.values(SQL), grantsSql(170004)]) assert.match(sql.trim().toLowerCase(), /^select\b/);
});
