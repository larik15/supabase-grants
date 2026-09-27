import test from 'node:test';
import assert from 'node:assert/strict';
import { toReportData, toJson } from '../src/report/json.mjs';
import { toMarkdown } from '../src/report/markdown.mjs';

function sampleReport() {
  return toReportData({
    source: 'fixtures/x',
    tables: [
      {
        schema: 'public',
        name: 'orders',
        rlsEnabled: true,
        policies: [{ name: 'orders_select', cmd: 'SELECT', roles: ['authenticated'], permissive: true }],
        grants: { authenticated: ['SELECT'] },
      },
      {
        schema: 'public',
        name: 'internal_stuff',
        rlsEnabled: false,
        policies: [],
        grants: {},
      },
    ],
    functions: [],
    findings: [
      {
        severity: 'medium',
        kind: 'table_without_explicit_grant',
        table: 'public.internal_stuff',
        message: 'no explicit grant',
        fix: 'grant select on public.internal_stuff to authenticated;',
      },
    ],
  });
}

test('toReportData: summary counts match the findings passed in', () => {
  const report = sampleReport();
  assert.deepEqual(report.summary, { critical: 0, high: 0, medium: 1, low: 0, info: 0 });
  assert.equal(report.source, 'fixtures/x');
});

test('toJson: round-trips through JSON.parse', () => {
  const report = sampleReport();
  const parsed = JSON.parse(toJson(report));
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.tables[0].name, 'orders');
});

test('toMarkdown: includes summary table, finding, and effective-state row', () => {
  const md = toMarkdown(sampleReport());
  assert.match(md, /\| Medium \| 1 \|/);
  assert.match(md, /### public\.internal_stuff/);
  assert.match(md, /table_without_explicit_grant/);
  // columns: table | RLS | policies | PUBLIC | anon | authenticated | service_role
  assert.match(md, /public\.orders \| on \| 1 \| — \| — \| select \| —/);
  assert.match(md, /public\.internal_stuff \| off \| 0 \| — \| — \| — \| —/);
  assert.match(md, /## Parser coverage/);
});

test('toMarkdown: "No findings." when the findings array is empty', () => {
  const report = toReportData({ source: 'x', tables: [], functions: [], findings: [] });
  assert.match(toMarkdown(report), /No findings\./);
});
