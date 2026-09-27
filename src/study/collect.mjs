// Clones a list of public repos (blobless, depth 1, sparse: only
// supabase/migrations is checked out), runs the static scan on each, writes
// one JSON record per attempted repo, then deletes the clone. Never touches a
// live database.
//
// Records are written as soon as each repo finishes, so a killed process loses
// at most the repos in flight. On the next run a repo whose record already
// exists is skipped — except `clone_failed`, which is retried — so rerunning
// with the same --list/--out resumes.
//
// Record statuses: scanned | no_migrations | clone_failed | scan_failed.
// Lines of the list that aren't a valid owner/repo slug are never used in a
// command or a path; they're only counted.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { scan, loadSqlFiles } from '../index.mjs';
import { SCHEMA_VERSION } from '../report/json.mjs';
import { TOOL_VERSION } from '../version.mjs';

const execFileAsync = promisify(execFile);

export const SLUG_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function isValidSlug(slug) {
  return SLUG_RE.test(slug) && !slug.split('/').some(part => part === '.' || part === '..');
}

export async function readRepoList(listPath) {
  const text = await readFile(listPath, 'utf8');
  return text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

export function outputPathFor(outDir, repoSlug) {
  return path.join(outDir, `${repoSlug.replace('/', '__')}.json`);
}

async function readRecord(p) {
  try {
    return JSON.parse(await readFile(p, 'utf8'));
  } catch {
    return null;
  }
}

// sha256 of the migration files' contents, concatenated in filename order.
// Lets aggregate.mjs recognize the same codebase scanned under two different
// owner/repo slugs (a GitHub rename, or a fork with untouched migrations)
// and count it once instead of twice.
export function hashMigrations(files) {
  const concatenated = [...files]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map(f => f.sql)
    .join('\n');
  return createHash('sha256').update(concatenated).digest('hex');
}

// Git never prompts (a deleted/private repo fails instead of hanging). An
// optional GITHUB_TOKEN is passed through git's environment config, so it
// never appears on a command line, in a log line or in a record.
export function gitEnv(env = process.env) {
  const out = { ...env, GIT_TERMINAL_PROMPT: '0' };
  if (env.GITHUB_TOKEN) {
    const basic = Buffer.from(`x-access-token:${env.GITHUB_TOKEN}`).toString('base64');
    Object.assign(out, {
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
      GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basic}`,
    });
  }
  return out;
}

async function git(args, opts) {
  const { stdout } = await execFileAsync('git', args, { timeout: opts.timeoutMs ?? 120000, env: gitEnv() });
  return stdout.trim();
}

async function cloneMigrationsOnly(repoSlug, destDir, opts) {
  const url = `https://github.com/${repoSlug}.git`;
  await git(['clone', '--filter=blob:none', '--depth', '1', '--sparse', '--no-tags', '--quiet', url, destDir], opts);
  await git(['-C', destDir, 'sparse-checkout', 'set', 'supabase/migrations'], opts);
  return {
    head_sha: await git(['-C', destDir, 'rev-parse', 'HEAD'], opts),
    last_commit_date: await git(['-C', destDir, 'log', '-1', '--format=%cI'], opts),
  };
}

async function findMigrationsDir(cloneDir) {
  const migrationsDir = path.join(cloneDir, 'supabase', 'migrations');
  try {
    const entries = await readdir(migrationsDir);
    return entries.some(f => f.toLowerCase().endsWith('.sql')) ? migrationsDir : null;
  } catch {
    return null;
  }
}

async function collectOne(repoSlug, outDir, opts) {
  if (!isValidSlug(repoSlug)) return { repo: repoSlug, status: 'invalid_slug' };

  const outPath = outputPathFor(outDir, repoSlug);
  const existing = await readRecord(outPath);
  if (existing && existing.status !== 'clone_failed') return { repo: repoSlug, status: 'skipped', previous: existing.status };

  const base = { schema_version: SCHEMA_VERSION, source: repoSlug, tool_version: TOOL_VERSION };
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'supabase-grants-study-'));
  const cloneDir = path.join(tmpRoot, 'repo');
  let record;
  try {
    let meta;
    try {
      meta = await cloneMigrationsOnly(repoSlug, cloneDir, opts);
    } catch (err) {
      record = { ...base, status: 'clone_failed', error: err.message.split('\n')[0] };
      return { repo: repoSlug, status: record.status, error: record.error };
    }

    const migrationsDir = await findMigrationsDir(cloneDir);
    if (!migrationsDir) {
      record = { ...base, status: 'no_migrations', ...meta };
      return { repo: repoSlug, status: record.status };
    }

    try {
      const report = scan(migrationsDir, { now: opts.now });
      // `source` names the repo: fine in this local, gitignored record, never
      // carried into the aggregate.
      record = {
        ...report,
        ...base,
        status: 'scanned',
        ...meta,
        migrations_hash: hashMigrations(loadSqlFiles(migrationsDir)),
      };
      return { repo: repoSlug, status: record.status };
    } catch (err) {
      record = { ...base, status: 'scan_failed', ...meta, error: err.message };
      return { repo: repoSlug, status: record.status, error: record.error };
    }
  } finally {
    if (record) await writeFile(outPath, JSON.stringify(record, null, 2));
    await rm(tmpRoot, { recursive: true, force: true }).catch(() => {});
  }
}

async function runPool(items, worker, concurrency) {
  const results = new Array(items.length);
  let next = 0;
  async function runner() {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, runner));
  return results;
}

// opts: { listPath, outDir='study', max, concurrency=4, now, onProgress }
export async function collect(opts) {
  const allRepos = await readRepoList(opts.listPath);
  const repos = opts.max ? allRepos.slice(0, opts.max) : allRepos;
  const outDir = opts.outDir || 'study';
  await mkdir(outDir, { recursive: true });

  const startedAt = Date.now();
  let done = 0;
  const results = await runPool(
    repos,
    async repoSlug => {
      const r = await collectOne(repoSlug, outDir, opts);
      done++;
      if (opts.onProgress) opts.onProgress({ done, total: repos.length, result: r });
      return r;
    },
    opts.concurrency || 4
  );

  const count = status => results.filter(r => r.status === status).length;
  const summary = {
    total: results.length,
    invalidSlug: count('invalid_slug'),
    skipped: count('skipped'),
    cloneFailed: count('clone_failed'),
    noMigrations: count('no_migrations'),
    scanFailed: count('scan_failed'),
    scanned: count('scanned'),
    elapsedMs: Date.now() - startedAt,
  };
  return { summary, results };
}
