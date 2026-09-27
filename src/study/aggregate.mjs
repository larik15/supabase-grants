// Turns the per-repo records written by collect.mjs into aggregate numbers
// for the write-up. Pure function over record objects — no repo name ever
// appears in the output (see toStudyMarkdown), only counts.

// Finding kinds reported as "% of repos with at least one".
const REPO_KINDS = [
  ['table_without_explicit_grant', 'reposMissingGrant', 'Migrations depend on legacy default grants (no explicit grant for at least one table)'],
  ['policy_open_read', 'reposOpenRead', 'At least one policy_open_read — always-true using on a readable policy'],
  ['policy_open_write', 'reposOpenWrite', 'At least one policy_open_write — always-true using on UPDATE/DELETE'],
  ['policy_open_to_all_authenticated', 'reposOpenToAllAuthenticated', 'At least one policy that only checks the caller is signed in'],
  ['policy_no_to_clause', 'reposNoToClause', 'At least one policy with no TO clause (applies to PUBLIC)'],
  ['definer_no_search_path', 'reposDefinerNoSearchPath', 'At least one SECURITY DEFINER function without a fixed search_path'],
];

// Table-level finding kinds reported as "% of tables with at least one".
const TABLE_KINDS = [
  ['table_without_explicit_grant', 'No explicit grant to anon/authenticated'],
  ['rls_disabled', 'RLS disabled'],
  ['policy_open_read', 'Always-true read policy'],
  ['policy_open_insert', 'Always-true insert policy'],
  ['policy_open_write', 'Always-true update/delete policy'],
  ['policy_open_to_all_authenticated', 'Policy that only checks the caller is signed in'],
  ['policy_no_to_clause', 'Policy with no TO clause'],
];

function pct(n, total) {
  return total ? Math.round((n / total) * 1000) / 10 : 0;
}

function median(numbers) {
  if (!numbers.length) return 0;
  const sorted = [...numbers].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// Records from before statuses existed only exist for scanned repos.
function statusOf(record) {
  return record.status || (Array.isArray(record.tables) ? 'scanned' : 'unknown');
}

// Two different owner/repo slugs can be the exact same codebase (a GitHub
// rename, or a fork that never touched its migrations) — keep the first
// occurrence of each migrations_hash and drop the rest so it's counted once.
// Reports with no hash (older scans) are always kept.
function dedupeByMigrationsHash(reports) {
  const groupSize = new Map();
  const kept = [];
  let removed = 0;
  for (const report of reports) {
    const hash = report.migrations_hash;
    if (hash) {
      groupSize.set(hash, (groupSize.get(hash) || 0) + 1);
      if (groupSize.get(hash) > 1) {
        removed++;
        continue;
      }
    }
    kept.push(report);
  }
  return { kept, removed, largestGroup: Math.max(1, ...groupSize.values()) };
}

// A repo with 0-1 tables is barely a schema at all — a template/starter left
// untouched, or a project abandoned right after `supabase init`. One finding
// on a 1-table repo moves its percentages as much as a real app with 50 tables
// and one bad policy, so the share is reported with and without them.
function isToyRepo(report) {
  return report.tables.length <= 1;
}

function kindsIn(report) {
  return new Set(report.findings.map(f => f.kind));
}

function shareOfRepos(reports) {
  const total = reports.length;
  const percentRepos = Object.fromEntries(
    REPO_KINDS.map(([kind, key]) => [key, pct(reports.filter(r => kindsIn(r).has(kind)).length, total)])
  );
  percentRepos.rlsDisabledTable = pct(reports.filter(r => r.tables.some(t => !t.rlsEnabled)).length, total);
  return percentRepos;
}

function shareOfTables(reports) {
  const tablesTotal = reports.reduce((n, r) => n + r.tables.length, 0);
  return Object.fromEntries(
    TABLE_KINDS.map(([kind]) => {
      let tables = 0;
      for (const r of reports) tables += new Set(r.findings.filter(f => f.kind === kind && f.table).map(f => f.table)).size;
      return [kind, pct(tables, tablesTotal)];
    })
  );
}


// records: every JSON record written by collect.mjs (any status).
export function aggregateReports(records) {
  const status = s => records.filter(r => statusOf(r) === s).length;
  const funnel = {
    attempted: records.length,
    cloned: status('scanned') + status('no_migrations') + status('scan_failed'),
    withMigrations: status('scanned') + status('scan_failed'),
    scanned: status('scanned'),
    cloneFailed: status('clone_failed'),
    scanFailed: status('scan_failed'),
  };

  const { kept: reports, removed: duplicatesRemoved, largestGroup } = dedupeByMigrationsHash(records.filter(r => statusOf(r) === 'scanned'));
  const reposScanned = reports.length;
  const nonToyReports = reports.filter(r => !isToyRepo(r));
  const tableCountsPerRepo = reports.map(r => r.tables.length);
  const tablesTotal = tableCountsPerRepo.reduce((a, b) => a + b, 0);

  const findingCountByKind = {};
  for (const r of reports) for (const f of r.findings) findingCountByKind[f.kind] = (findingCountByKind[f.kind] || 0) + 1;

  const unparsedCounts = reports.map(r => r.unparsed_statements?.total || 0);
  const warningCounts = reports.map(r => (r.warnings || []).length);

  return {
    funnel,
    reposScanned,
    duplicatesRemoved,
    largestDuplicateGroup: largestGroup,
    toyRepoCount: reposScanned - nonToyReports.length,
    nonToyRepoCount: nonToyReports.length,
    tablesTotal,
    avgTablesPerRepo: reposScanned ? Math.round((tablesTotal / reposScanned) * 10) / 10 : 0,
    medianTablesPerRepo: median(tableCountsPerRepo),
    maxTablesPerRepo: tableCountsPerRepo.length ? Math.max(...tableCountsPerRepo) : 0,
    percentRepos: shareOfRepos(reports),
    percentReposExcludingToy: shareOfRepos(nonToyReports),
    percentTables: shareOfTables(reports),
    parserCoverage: {
      unparsedStatements: unparsedCounts.reduce((a, b) => a + b, 0),
      reposWithUnparsed: pct(unparsedCounts.filter(n => n > 0).length, reposScanned),
      warnings: warningCounts.reduce((a, b) => a + b, 0),
      reposWithWarnings: pct(warningCounts.filter(n => n > 0).length, reposScanned),
    },
    findingCountByKind,
  };
}

export function toStudyMarkdown(agg) {
  const lines = [];
  const push = (...ls) => lines.push(...ls);
  const f = agg.funnel;

  push('# Supabase grants — study', '');
  push(
    'Static scan of public repositories that keep Supabase migrations in `supabase/migrations`. Aggregate numbers ' +
      'only — no repo names, clone URLs or file paths appear anywhere in this file.',
    ''
  );

  push('## Sample', '');
  push('| Stage | Repos |', '|---|---|');
  push(`| Attempted | ${f.attempted} |`);
  push(`| Cloned | ${f.cloned} |`);
  push(`| With \`supabase/migrations\` | ${f.withMigrations} |`);
  push(`| Scanned | ${f.scanned} |`);
  push('');
  push(`- ${f.cloneFailed} could not be cloned (renamed, deleted or made private since the list was built)${f.scanFailed ? `; ${f.scanFailed} had migrations the scanner failed on` : ''}.`);
  if (agg.duplicatesRemoved) {
    push(`- ${agg.duplicatesRemoved} scanned repo(s) had byte-identical migrations to one already counted (renames, forks, shared templates) and are counted once: **${agg.reposScanned}** repos below.${agg.largestDuplicateGroup > 2 ? ` The largest group is ${agg.largestDuplicateGroup} repos sharing one set of migrations.` : ''}`);
  }
  push(
    `- Tables found: **${agg.tablesTotal}** (median ${agg.medianTablesPerRepo} per repo, mean ${agg.avgTablesPerRepo} — ` +
      `a few very large schemas pull the mean above the median; the largest repo has ${agg.maxTablesPerRepo}).`
  );
  push(
    `- "Toy" repos (0-1 tables — a template or an abandoned \`supabase init\`): **${agg.toyRepoCount}** ` +
      `(${pct(agg.toyRepoCount, agg.reposScanned)}%). The per-repo table shows rates with and without them.`
  );
  push('');

  push('## Share of repos affected', '');
  push(
    "Existing tables keep whatever grants they already have — none of this affects a table already running in " +
      "production. \"Depends on legacy default grants\" means at least one table's migration has no explicit " +
      '`grant ... to anon/authenticated` and relies on the platform granting it automatically. The platform stops ' +
      'setting that default for projects created after 2026-05-30 and for every project from 2026-10-30 (a project ' +
      'can re-add it with ALTER DEFAULT PRIVILEGES); in a new environment built from these migrations without it (a ' +
      'fresh project, branch, or redeploy), every Data API request to the table returns 42501 permission denied (with ' +
      'a hint naming the missing grant).',
    ''
  );
  push(`| Condition | % of all repos (n=${agg.reposScanned}) | % excluding toy repos (n=${agg.nonToyRepoCount}) |`, '|---|---|---|');
  for (const [, key, label] of REPO_KINDS) push(`| ${label} | ${agg.percentRepos[key]}% | ${agg.percentReposExcludingToy[key]}% |`);
  push(`| At least one table with RLS disabled | ${agg.percentRepos.rlsDisabledTable}% | ${agg.percentReposExcludingToy.rlsDisabledTable}% |`);
  push('');

  push('## Share of tables affected', '');
  push(`| Condition | % of tables (n=${agg.tablesTotal}) |`, '|---|---|');
  for (const [kind, label] of TABLE_KINDS) push(`| ${label} | ${agg.percentTables[kind]}% |`);
  push('');

  push('## Raw finding counts, by kind', '');
  push('| Finding kind | Count |', '|---|---|');
  for (const [kind, count] of Object.entries(agg.findingCountByKind).sort((a, b) => b[1] - a[1])) push(`| ${kind} | ${count} |`);
  push('');

  const pc = agg.parserCoverage;
  push('## Parser coverage', '');
  push(`- Statements that could affect grants/RLS but couldn't be interpreted (DO blocks, dynamic SQL, unusual syntax): **${pc.unparsedStatements}**, in ${pc.reposWithUnparsed}% of repos.`);
  push(`- Statements targeting a table no earlier migration creates (not applied): **${pc.warnings}**, in ${pc.reposWithWarnings}% of repos.`);
  push('');

  push('## Limitations', '');
  push(
    '- **The sample is not random.** Repos were found with GitHub repository search on the default README text ' +
      'Lovable generates for new projects. Search returns at most about 1,000 results and favours recently updated ' +
      'repos, and only repos that keep migrations in `supabase/migrations` (Supabase CLI layout) are scanned.'
  );
  push(
    '- **Static only.** These numbers come from migration files, never a live database. A table flagged for a ' +
      'legacy-grant dependency is at risk, not necessarily broken today — that depends on whether its project still ' +
      "has the platform's default grants, which a static scan cannot see."
  );
  push(
    '- **Tables created outside migrations are invisible** to this scan (dashboard, SQL editor), and statements ' +
      'the parser couldn\'t interpret are counted above rather than applied.'
  );
  push(
    '- **Shallow clone, default branch only.** Migrations on other branches, or removed from history, are not seen.'
  );
  push(
    '- **Literal patterns, not semantic analysis.** Policy expressions are matched against a short list of literal ' +
      'forms (`true`, `1 = 1`, `auth.uid() is not null`, ...); an equivalent written differently is not caught.'
  );
  push('- **Repos that were renamed, deleted or made private** since the list was built are excluded, not corrected for.');
  push('- **Duplicate detection is exact-match only**: a fork with one changed migration counts as a separate repo.');
  push('- **A snapshot, not a monitor.** The numbers reflect the scan date only.');
  push('');
  return lines.join('\n');
}
