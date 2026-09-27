#!/usr/bin/env node
import { writeFileSync, existsSync, statSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { scan } from '../src/index.mjs';
import { toMarkdown } from '../src/report/markdown.mjs';
import { toJson, SCHEMA_VERSION } from '../src/report/json.mjs';
import { introspect } from '../src/live/introspect.mjs';
import { analyzeLive } from '../src/live/analyze.mjs';
import { buildLeastPrivilegePlan } from '../src/live/plan.mjs';
import { collect } from '../src/study/collect.mjs';
import { aggregateReports, toStudyMarkdown } from '../src/study/aggregate.mjs';
import {
  summarizeFindings,
  exitCodeForFindings,
  parseIgnore,
  applyIgnores,
  FAIL_ON_VALUES,
  EXIT,
} from '../src/shared/findings.mjs';

const VALUE_FLAGS = new Set(['md', 'db', 'plan', 'list', 'aggregate', 'out', 'concurrency', 'max', 'ignore', 'fail-on']);
const REPEATABLE = new Set(['ignore']);

const USAGE = [
  'Usage: supabase-grants scan [dir] [--json] [--md report.md] [--ignore schema.table:kind]... [--fail-on <severity>]',
  '       supabase-grants live [--db <url>] [--plan out.sql] [--pin-defaults] [--json] [--ignore ...] [--fail-on ...]',
  '       supabase-grants study --list repos.txt [--out study] [--concurrency 4] [--max N]',
  '       supabase-grants study --aggregate study [--md STUDY.md]',
  `Exit codes: 0 clean, 1 finding at/above --fail-on (default high), 2 critical, 3 tool error. --fail-on: ${FAIL_ON_VALUES.join('|')}`,
].join('\n');

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opts = { _: [] };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith('--')) {
      opts._.push(a);
      continue;
    }
    const name = a.slice(2);
    if (!VALUE_FLAGS.has(name)) {
      opts[name] = true;
      continue;
    }
    const value = rest[++i];
    if (value === undefined) throw new Error(`--${name} needs a value`);
    if (REPEATABLE.has(name)) (opts[name] ||= []).push(value);
    else opts[name] = value;
  }
  return { command, opts };
}

class ToolError extends Error {}

// Validates --ignore / --fail-on up front so a typo is a tool error, not a
// silently different exit code.
function findingFilters(opts) {
  try {
    const ignores = (opts.ignore || []).map(parseIgnore);
    const failOn = opts['fail-on'] || 'high';
    exitCodeForFindings([], failOn);
    return { ignores, failOn };
  } catch (err) {
    throw new ToolError(err.message);
  }
}

function runScanCommand(opts) {
  const { ignores, failOn } = findingFilters(opts);
  const dir = opts._[0] || 'supabase/migrations';
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new ToolError(`"${dir}" is not a directory`);

  let report;
  try {
    report = scan(dir);
  } catch (err) {
    throw new ToolError(`scanning "${dir}" failed: ${err.message}`);
  }
  if (report.tables.length === 0) {
    throw new ToolError(`no tables found in the *.sql files of "${dir}" — is this the migrations directory?`);
  }

  const { kept, ignored } = applyIgnores(report.findings, ignores);
  report.findings = kept;
  report.summary = summarizeFindings(kept);
  report.ignored_findings = ignored.length;

  if (opts.md) writeFileSync(opts.md, toMarkdown(report));
  if (opts.json) console.log(toJson(report));
  else if (!opts.md) console.log(toMarkdown(report));
  if (opts.md) console.error(`Wrote ${opts.md}`);

  return exitCodeForFindings(kept, failOn);
}

function rollbackPathFor(planPath) {
  return /\.sql$/i.test(planPath) ? planPath.replace(/\.sql$/i, '_rollback.sql') : `${planPath}_rollback.sql`;
}

function printLiveReport(findings, plan, ignoredCount) {
  console.log('# supabase-grants — live audit');
  console.log('');
  console.log('## Summary');
  for (const [severity, count] of Object.entries(summarizeFindings(findings))) console.log(`- ${severity}: ${count}`);
  if (ignoredCount) console.log(`- suppressed with --ignore: ${ignoredCount}`);
  console.log('');
  console.log('## Findings');
  if (findings.length === 0) {
    console.log('No findings.');
  } else {
    for (const f of findings) {
      const where = f.table ?? f.function ?? (f.grantorRole ? `defaults for ${f.grantorRole}: ${f.objectType}` : null);
      console.log(`- [${f.severity}] ${f.kind}${where ? ` (${where})` : ''} — ${f.message}`);
      if (f.fix) console.log(`    fix: ${f.fix}`);
    }
  }
  console.log('');
  console.log(`## Least-privilege migration (${plan.filename})`);
  console.log(plan.migrationSql);
}

async function runLiveCommand(opts) {
  const { ignores, failOn } = findingFilters(opts);
  const databaseUrl = opts.db || process.env.DATABASE_URL;
  if (!databaseUrl) throw new ToolError('pass --db <connection-string> or set DATABASE_URL');

  let rows;
  try {
    rows = await introspect(databaseUrl);
  } catch (err) {
    throw new ToolError(`could not introspect the database: ${err.message}`);
  }

  const { kept: findings, ignored } = applyIgnores(analyzeLive(rows), ignores);
  const plan = buildLeastPrivilegePlan(findings, { pinDefaults: !!opts['pin-defaults'] });

  if (opts.json) {
    console.log(JSON.stringify({
      schema_version: SCHEMA_VERSION,
      server_version_num: rows.serverVersionNum,
      summary: summarizeFindings(findings),
      ignored_findings: ignored.length,
      findings,
      plan,
    }, null, 2));
  } else {
    printLiveReport(findings, plan, ignored.length);
  }

  // Only ever writes files, never executes anything against the database.
  if (opts.plan) {
    const rollbackPath = rollbackPathFor(opts.plan);
    writeFileSync(opts.plan, plan.migrationSql);
    writeFileSync(rollbackPath, plan.rollbackSql);
    console.error(`Wrote ${opts.plan} and ${rollbackPath} (not executed).`);
  }

  return exitCodeForFindings(findings, failOn);
}

async function runStudyAggregate(opts) {
  const dir = opts.aggregate;
  if (!existsSync(dir)) throw new ToolError(`"${dir}" does not exist`);
  const files = (await readdir(dir)).filter(f => f.toLowerCase().endsWith('.json'));
  const records = await Promise.all(files.map(async f => JSON.parse(await readFile(path.join(dir, f), 'utf8'))));
  const agg = aggregateReports(records);
  const mdPath = opts.md || 'STUDY.md';
  writeFileSync(mdPath, toStudyMarkdown(agg));
  console.log(`Aggregated ${records.length} repo record(s) from ${dir} -> ${mdPath}`);
  console.log(JSON.stringify(agg, null, 2));
  return EXIT.CLEAN;
}

async function runStudyCollect(opts) {
  if (!opts.list) throw new ToolError('study needs --list <repos.txt> or --aggregate <dir>');
  if (!existsSync(opts.list)) throw new ToolError(`"${opts.list}" does not exist`);
  const { summary, results } = await collect({
    listPath: opts.list,
    outDir: opts.out || 'study',
    max: opts.max ? Number(opts.max) : undefined,
    concurrency: opts.concurrency ? Number(opts.concurrency) : 4,
    onProgress: opts.quiet ? undefined : ({ done, total, result }) => {
      const detail = result.status === 'clone_failed' || result.status === 'scan_failed' ? `: ${result.error}` : '';
      console.error(`[${done}/${total}] ${result.repo} — ${result.status}${detail}`);
    },
  });
  console.log(JSON.stringify(summary, null, 2));
  if (opts.json) console.log(JSON.stringify(results, null, 2));
  return EXIT.CLEAN;
}

async function main() {
  const { command, opts } = parseArgs(process.argv.slice(2));
  switch (command) {
    case 'scan':
      return runScanCommand(opts);
    case 'live':
      return runLiveCommand(opts);
    case 'study':
      return opts.aggregate ? runStudyAggregate(opts) : runStudyCollect(opts);
    default:
      throw new ToolError(command ? `unknown command "${command}"\n${USAGE}` : USAGE);
  }
}

try {
  process.exitCode = await main();
} catch (err) {
  // Anything unexpected is also a tool error (3), never a findings exit code.
  console.error(`supabase-grants: ${err instanceof ToolError ? err.message : err.stack || err.message}`);
  process.exitCode = EXIT.TOOL_ERROR;
}
