import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { exitCodeForFindings, parseIgnore, applyIgnores } from '../src/shared/findings.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN = path.join(ROOT, 'bin', 'supabase-grants.mjs');
const FIXTURES = path.join(ROOT, 'fixtures', 'migrations');

function run(...args) {
  const env = { ...process.env };
  delete env.DATABASE_URL;
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function tmpMigrations(sql) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'supabase-grants-cli-'));
  writeFileSync(path.join(dir, '0001_init.sql'), sql);
  return dir;
}

// --- exit code helpers -------------------------------------------------------

test('exitCodeForFindings: critical=2, at/above --fail-on=1, else 0', () => {
  const high = [{ severity: 'high' }];
  const medium = [{ severity: 'medium' }];
  assert.equal(exitCodeForFindings([{ severity: 'critical' }]), 2);
  assert.equal(exitCodeForFindings(high), 1);
  assert.equal(exitCodeForFindings(medium), 0);
  assert.equal(exitCodeForFindings(medium, 'medium'), 1);
  assert.equal(exitCodeForFindings(high, 'critical'), 0);
  assert.equal(exitCodeForFindings([{ severity: 'critical' }], 'none'), 0);
  assert.throws(() => exitCodeForFindings([], 'severe'), /unknown --fail-on/);
});

test('parseIgnore / applyIgnores match tables, and functions with or without their argument list', () => {
  const ignores = ['public.t:rls_disabled', 'public.f:definer_no_search_path'].map(parseIgnore);
  const findings = [
    { kind: 'rls_disabled', table: 'public.t' },
    { kind: 'rls_disabled', table: 'public.u' },
    { kind: 'policy_open_read', table: 'public.t' },
    { kind: 'definer_no_search_path', table: null, function: 'public.f(uuid)' },
  ];
  const { kept, ignored } = applyIgnores(findings, ignores);
  assert.equal(ignored.length, 2);
  assert.deepEqual(kept.map(f => `${f.table}:${f.kind}`), ['public.u:rls_disabled', 'public.t:policy_open_read']);
  assert.throws(() => parseIgnore('rls_disabled'), /schema\.table>:<kind>/);
});

// --- CLI ---------------------------------------------------------------------

test('scan: exit 3 for a path that does not exist', () => {
  const r = run('scan', path.join(ROOT, 'no-such-dir'));
  assert.equal(r.code, 3);
  assert.match(r.stderr, /not a directory/);
});

test('scan: exit 3 when zero tables are found (wrong directory)', () => {
  const dir = tmpMigrations('select 1;');
  try {
    const r = run('scan', dir);
    assert.equal(r.code, 3);
    assert.match(r.stderr, /no tables found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unknown command and bad flags are exit 3', () => {
  assert.equal(run('frobnicate').code, 3);
  assert.equal(run('scan', FIXTURES, '--fail-on', 'severe').code, 3);
  assert.equal(run('scan', FIXTURES, '--ignore', 'nonsense').code, 3);
});

test('live: exit 3 without a database URL, and when the connection is refused', () => {
  assert.equal(run('live').code, 3);
  const r = run('live', '--db', 'postgres://u:p@127.0.0.1:1/postgres');
  assert.equal(r.code, 3);
  assert.match(r.stderr, /could not introspect/);
});

test('scan: exit 2 on a critical finding; --ignore removes it; --fail-on controls the rest', () => {
  const dir = tmpMigrations('create table public.t (id int);'); // RLS off + no grant: rls_disabled (critical) + table_without_explicit_grant
  try {
    assert.equal(run('scan', dir, '--json').code, 2);
    // rls_disabled ignored -> only table_without_explicit_grant (medium before 2026-10-30, high after)
    const ignored = run('scan', dir, '--json', '--ignore', 'public.t:rls_disabled', '--fail-on', 'critical');
    assert.equal(ignored.code, 0);
    const report = JSON.parse(ignored.stdout);
    assert.equal(report.ignored_findings, 1);
    assert.ok(report.findings.every(f => f.kind !== 'rls_disabled'));
    assert.equal(run('scan', dir, '--ignore', 'public.t:rls_disabled', '--fail-on', 'medium').code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan --json: schema_version 1, a severity on every finding, parser coverage fields', () => {
  const r = run('scan', path.join(FIXTURES, 'create-no-grant'), '--json', '--fail-on', 'none');
  assert.equal(r.code, 0);
  const report = JSON.parse(r.stdout);
  assert.equal(report.schema_version, 1);
  assert.ok(report.findings.length > 0);
  assert.ok(report.findings.every(f => ['critical', 'high', 'medium', 'low', 'info'].includes(f.severity)));
  assert.deepEqual(report.unparsed_statements, { total: 0, byFile: {} });
  assert.deepEqual(report.warnings, []);
});
