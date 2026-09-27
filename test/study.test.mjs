import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { readRepoList, outputPathFor, collect, hashMigrations, isValidSlug, gitEnv } from '../src/study/collect.mjs';
import { aggregateReports, toStudyMarkdown } from '../src/study/aggregate.mjs';

test('readRepoList: trims, drops blank lines and comments', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'supabase-grants-test-'));
  const file = path.join(dir, 'repos.txt');
  await writeFile(file, '\nowner/one\n  owner/two  \n# a comment\n\nowner/three\n');
  try {
    const repos = await readRepoList(file);
    assert.deepEqual(repos, ['owner/one', 'owner/two', 'owner/three']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('outputPathFor: maps owner/repo to owner__repo.json under outDir', () => {
  assert.equal(outputPathFor('study', 'owner/repo'), path.join('study', 'owner__repo.json'));
});

test('collect: resumes by skipping any repo that already has a JSON file in outDir (no clone attempted)', async () => {
  const workDir = await mkdtemp(path.join(os.tmpdir(), 'supabase-grants-resume-test-'));
  try {
    const listFile = path.join(workDir, 'repos.txt');
    await writeFile(listFile, 'owner/one\nowner/two\n');
    const outDir = path.join(workDir, 'study');
    await mkdir(outDir, { recursive: true });
    const already = { source: 'owner/one', tables: [], functions: [], findings: [] };
    await writeFile(outputPathFor(outDir, 'owner/one'), JSON.stringify(already));
    await writeFile(outputPathFor(outDir, 'owner/two'), JSON.stringify(already));

    const { summary, results } = await collect({ listPath: listFile, outDir, concurrency: 2 });
    assert.equal(summary.total, 2);
    assert.equal(summary.skipped, 2);
    assert.ok(results.every(r => r.status === 'skipped'));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('hashMigrations: same content in a different file order hashes the same (order-independent)', () => {
  const a = [{ name: '0001.sql', sql: 'create table t (id uuid);' }, { name: '0002.sql', sql: 'grant select on t to anon;' }];
  const b = [{ name: '0002.sql', sql: 'grant select on t to anon;' }, { name: '0001.sql', sql: 'create table t (id uuid);' }];
  assert.equal(hashMigrations(a), hashMigrations(b));
});

test('hashMigrations: different content hashes differently', () => {
  const a = [{ name: '0001.sql', sql: 'create table t (id uuid);' }];
  const b = [{ name: '0001.sql', sql: 'create table t (id int);' }];
  assert.notEqual(hashMigrations(a), hashMigrations(b));
});

function fakeReport({ tables = [], findings = [], migrations_hash } = {}) {
  return { source: 'should-not-leak/into-aggregate', tables, findings, migrations_hash };
}

test('aggregateReports: counts repos and tables, computes percentages', () => {
  const reports = [
    fakeReport({
      tables: [{ schema: 'public', name: 'a', rlsEnabled: true }],
      findings: [{ kind: 'table_without_explicit_grant' }, { kind: 'policy_open_read' }],
    }),
    fakeReport({
      tables: [{ schema: 'public', name: 'b', rlsEnabled: false }, { schema: 'public', name: 'c', rlsEnabled: true }],
      findings: [],
    }),
  ];
  const agg = aggregateReports(reports);
  assert.equal(agg.reposScanned, 2);
  assert.equal(agg.tablesTotal, 3);
  assert.equal(agg.avgTablesPerRepo, 1.5);
  assert.equal(agg.medianTablesPerRepo, 1.5);
  assert.equal(agg.maxTablesPerRepo, 2);
  assert.equal(agg.percentRepos.reposMissingGrant, 50);
  assert.equal(agg.percentRepos.reposOpenRead, 50);
  assert.equal(agg.percentRepos.reposOpenWrite, 0);
  assert.equal(agg.percentRepos.rlsDisabledTable, 50);
  assert.equal(agg.findingCountByKind.table_without_explicit_grant, 1);
  assert.equal(agg.findingCountByKind.policy_open_read, 1);
});

test('aggregateReports: two findings of the same kind in one repo still count that repo once', () => {
  const reports = [
    fakeReport({
      tables: [],
      findings: [
        { kind: 'policy_no_to_clause' },
        { kind: 'policy_no_to_clause' },
      ],
    }),
  ];
  const agg = aggregateReports(reports);
  assert.equal(agg.percentRepos.reposNoToClause, 100);
  assert.equal(agg.findingCountByKind.policy_no_to_clause, 2);
});

test('aggregateReports: zero repos does not divide by zero', () => {
  const agg = aggregateReports([]);
  assert.equal(agg.reposScanned, 0);
  assert.equal(agg.avgTablesPerRepo, 0);
  assert.equal(agg.medianTablesPerRepo, 0);
  assert.equal(agg.maxTablesPerRepo, 0);
  assert.equal(agg.percentRepos.reposMissingGrant, 0);
});

test('aggregateReports: a second report with the same migrations_hash (a rename/fork) is not double-counted', () => {
  const reports = [
    fakeReport({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }], migrations_hash: 'abc' }),
    fakeReport({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }], migrations_hash: 'abc' }), // same content, different slug
    fakeReport({ tables: [{ schema: 'public', name: 'b', rlsEnabled: true }], migrations_hash: 'def' }),
  ];
  const agg = aggregateReports(reports);
  assert.equal(agg.reposScanned, 2);
  assert.equal(agg.duplicatesRemoved, 1);
  assert.equal(agg.tablesTotal, 2);
});

test('aggregateReports: reports with no migrations_hash (older scans) are never deduped against each other', () => {
  const reports = [fakeReport({ tables: [] }), fakeReport({ tables: [] })];
  const agg = aggregateReports(reports);
  assert.equal(agg.reposScanned, 2);
  assert.equal(agg.duplicatesRemoved, 0);
});

test('aggregateReports: "toy" repos (<=1 table) are counted separately, with percentages shown with and without them', () => {
  const toy = fakeReport({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }], findings: [{ kind: 'policy_open_read' }] });
  const zeroTable = fakeReport({ tables: [], findings: [{ kind: 'policy_open_read' }] });
  const real = fakeReport({
    tables: [{ schema: 'public', name: 'b', rlsEnabled: true }, { schema: 'public', name: 'c', rlsEnabled: true }],
    findings: [],
  });
  const agg = aggregateReports([toy, zeroTable, real]);
  assert.equal(agg.reposScanned, 3);
  assert.equal(agg.toyRepoCount, 2);
  assert.equal(agg.nonToyRepoCount, 1);
  // all repos: 2 of 3 have policy_open_read
  assert.equal(agg.percentRepos.reposOpenRead, pctHelper(2, 3));
  // excluding toy repos: only `real` remains, which has no findings
  assert.equal(agg.percentReposExcludingToy.reposOpenRead, 0);
});

function pctHelper(n, total) {
  return Math.round((n / total) * 1000) / 10;
}

test('toStudyMarkdown includes the toy-repo count and a two-column share table', () => {
  const toy = fakeReport({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }], findings: [] });
  const md = toStudyMarkdown(aggregateReports([toy]));
  assert.match(md, /"Toy" repos/);
  assert.match(md, /% of all repos \(n=1\)/);
  assert.match(md, /% excluding toy repos \(n=0\)/);
});

test('toStudyMarkdown includes a Limitations section', () => {
  const md = toStudyMarkdown(aggregateReports([fakeReport({ tables: [] })]));
  assert.match(md, /## Limitations/);
  assert.match(md, /Static only/);
  assert.match(md, /not random/);
  assert.match(md, /default README text/);
});

test('toStudyMarkdown never contains a repo identifier from the input reports', () => {
  const reports = [fakeReport({ findings: [{ kind: 'policy_open_write' }] })];
  const md = toStudyMarkdown(aggregateReports(reports));
  assert.doesNotMatch(md, /should-not-leak/);
  assert.match(md, /policy_open_write/); // kind names are fine, they're not identifying
});

test('toStudyMarkdown includes headline counts and both tables', () => {
  const md = toStudyMarkdown(aggregateReports([fakeReport({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }] })]));
  assert.match(md, /\| Scanned \| 1 \|/);
  assert.match(md, /## Share of repos affected/);
  assert.match(md, /## Raw finding counts, by kind/);
});

// --- second review round ----------------------------------------------------

test('isValidSlug: only owner/repo made of [A-Za-z0-9_.-], no path tricks', () => {
  for (const ok of ['owner/repo', 'Some-Org/my.repo_2']) assert.equal(isValidSlug(ok), true, ok);
  for (const bad of ['owner', 'owner/repo/extra', '../etc/passwd', 'owner/..', 'owner/repo;rm -rf', 'owner /repo', '-x/y z', 'a/b\n']) {
    assert.equal(isValidSlug(bad), false, JSON.stringify(bad));
  }
});

test('collect: invalid slugs are never cloned or written, only counted', async () => {
  const workDir = await mkdtemp(path.join(os.tmpdir(), 'supabase-grants-slug-test-'));
  try {
    const listFile = path.join(workDir, 'repos.txt');
    await writeFile(listFile, '../../evil\nnot a slug\n');
    const outDir = path.join(workDir, 'study');
    const { summary } = await collect({ listPath: listFile, outDir });
    assert.equal(summary.invalidSlug, 2);
    assert.deepEqual(await readdir(outDir), []);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('gitEnv: never prompts; GITHUB_TOKEN goes into env config, not argv', () => {
  const plain = gitEnv({ PATH: '/bin' });
  assert.equal(plain.GIT_TERMINAL_PROMPT, '0');
  assert.equal(plain.GIT_CONFIG_COUNT, undefined);
  const withToken = gitEnv({ PATH: '/bin', GITHUB_TOKEN: 'tok' });
  assert.equal(withToken.GIT_CONFIG_KEY_0, 'http.https://github.com/.extraheader');
  assert.equal(withToken.GIT_CONFIG_VALUE_0, `AUTHORIZATION: basic ${Buffer.from('x-access-token:tok').toString('base64')}`);
});

function scanned(extra) {
  return { status: 'scanned', source: 'should-not-leak/x', tables: [], findings: [], ...extra };
}

test('aggregate: funnel counts every status, rates use scanned repos only', () => {
  const agg = aggregateReports([
    scanned({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }, { schema: 'public', name: 'b', rlsEnabled: true }] }),
    { status: 'no_migrations', source: 'x/y' },
    { status: 'clone_failed', source: 'x/z', error: 'gone' },
    { status: 'scan_failed', source: 'x/w', error: 'boom' },
  ]);
  // cloned = scanned + no_migrations + scan_failed
  assert.deepEqual(agg.funnel, { attempted: 4, cloned: 3, withMigrations: 2, scanned: 1, cloneFailed: 1, scanFailed: 1 });
  assert.equal(agg.reposScanned, 1);
});

test('aggregate: per-table rates count each table once per kind', () => {
  const agg = aggregateReports([
    scanned({
      tables: ['a', 'b', 'c', 'd'].map(name => ({ schema: 'public', name, rlsEnabled: true })),
      findings: [
        { kind: 'policy_open_read', table: 'public.a' },
        { kind: 'policy_open_read', table: 'public.a' }, // two open policies on one table
        { kind: 'policy_open_read', table: 'public.b' },
        { kind: 'rls_disabled', table: 'public.c' },
      ],
    }),
  ]);
  assert.equal(agg.percentTables.policy_open_read, 50);
  assert.equal(agg.percentTables.rls_disabled, 25);
});

test('aggregate: parser coverage totals', () => {
  const agg = aggregateReports([
    scanned({ unparsed_statements: { total: 3, byFile: {} }, warnings: [{}, {}] }),
    scanned({ unparsed_statements: { total: 0, byFile: {} }, warnings: [] }),
  ]);
  assert.deepEqual(agg.parserCoverage, { unparsedStatements: 3, reposWithUnparsed: 50, warnings: 2, reposWithWarnings: 50 });
});

test('STUDY.md shows the funnel and per-table tables, no per-year table, and still names no repo', () => {
  const md = toStudyMarkdown(aggregateReports([
    scanned({ last_commit_date: '2026-01-01T00:00:00Z', tables: [{ schema: 'public', name: 'a', rlsEnabled: true }] }),
    { status: 'clone_failed', source: 'should-not-leak/y' },
  ]));
  for (const heading of ['## Sample', '## Share of repos affected', '## Share of tables affected', '## Parser coverage', '## Limitations']) {
    assert.match(md, new RegExp(heading));
  }
  assert.doesNotMatch(md, /year of last commit/i);
  assert.match(md, /\| Attempted \| 2 \|/);
  assert.doesNotMatch(md, /should-not-leak/);
});

test('aggregate: reports the size of the largest group of identical migrations', () => {
  const agg = aggregateReports([
    scanned({ migrations_hash: 'a' }), scanned({ migrations_hash: 'a' }), scanned({ migrations_hash: 'a' }),
    scanned({ migrations_hash: 'b' }),
  ]);
  assert.equal(agg.duplicatesRemoved, 2);
  assert.equal(agg.largestDuplicateGroup, 3);
  assert.match(toStudyMarkdown(agg), /largest group is 3 repos/);
});

test('aggregate: grantLowerBound counts repos with no grant statement anywhere', () => {
  const agg = aggregateReports([
    scanned({ saw_grant_statement: true, unparsed_contains_grant_keyword: false }),
    scanned({ saw_grant_statement: false, unparsed_contains_grant_keyword: true }),
    scanned({ saw_grant_statement: false, unparsed_contains_grant_keyword: false }),
    scanned({ saw_grant_statement: false, unparsed_contains_grant_keyword: false }),
  ]);
  assert.deepEqual(agg.grantLowerBound, { noGrantCount: 2, reposScanned: 4, percentNoGrant: 50 });
});

test('aggregate: grantLowerBound treats records without the fields (older scans) as having no grant', () => {
  const agg = aggregateReports([scanned({}), scanned({ saw_grant_statement: true })]);
  assert.equal(agg.grantLowerBound.noGrantCount, 1);
});

test('STUDY.md states the lower bound as a sentence alongside the upper bound', () => {
  const agg = aggregateReports([
    scanned({ tables: [{ schema: 'public', name: 'a', rlsEnabled: true }], findings: [{ kind: 'table_without_explicit_grant', table: 'public.a' }], saw_grant_statement: false, unparsed_contains_grant_keyword: false }),
  ]);
  const md = toStudyMarkdown(agg);
  assert.match(md, /Lower bound: 100% of repos \(1 of 1\) have no grant statement anywhere in their migrations/);
  assert.match(md, /the 100% figure above is the upper bound/);
});
