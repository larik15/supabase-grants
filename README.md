# supabase-grants

Do the table privileges (GRANTs) on your Supabase project match what your RLS policies actually allow?

`supabase-grants` answers that from two angles: a **static scan** of your `supabase/migrations/*.sql`
(no database needed), and a **live audit** of a running Supabase/Postgres database that also plans a
least-privilege migration for you.

Supported: Postgres 15 and 17 (the Supabase versions in use). The live audit has been tested against
Postgres 17 only.

## Why

Row Level Security policies only matter if a role has table privileges to begin with — Postgres checks
GRANTs first, then RLS. Two ways that goes wrong:

1. **A policy exists, but the grant doesn't.** You write `create policy ... for select using (...)`, but
   nothing ever grants `select` on that table to `authenticated`. The policy is dead code, and every
   request to the table through the Data API returns `42501 permission denied` with a hint. This happens
   when migrations written for a project that had Supabase's automatic grants are applied to one that
   doesn't (see below).
2. **The grant exists, but no policy backs it.** A role holds `DELETE` at the privilege level with no
   policy that ever lets it delete anything. Harmless today because RLS blocks it — but it's one policy
   typo, or one "disable RLS for this migration" moment, away from being a real hole.

### The Supabase default-grant change

Supabase used to set default privileges so that `anon`, `authenticated` and `service_role` automatically
received access to every new table, view, sequence and function in `public`. The platform stops setting
that default: opt-in since **2026-04-28**, the default for new projects since **2026-05-30**, and for
every project from **2026-10-30**. A project can re-add it with `ALTER DEFAULT PRIVILEGES`.

It does **not** revoke anything: objects that already received the grants keep them.

What it means: a migration that creates a table and never grants it to `anon`/`authenticated` only ever
worked because of the default. Apply it where the default isn't set — a new project, a preview branch, a
restore — and the table has no API privileges at all: requests return `42501 permission denied` (with a
hint naming the missing grant), and any new table created the same way behaves the same.
`supabase-grants scan` finds every such table and tells you the grant to add.

### What this adds beyond Security Advisor

Supabase's Security Advisor (the [Splinter](https://github.com/supabase/splinter) lints) inspects a live
project. `supabase-grants` works earlier and closer to the code:

- it runs on the **migration files in CI, before they are applied** — no project, no credentials;
- it compares **grants against policies** in both directions, which is the question the default-grant
  change makes urgent;
- it **plans the fix**: `live --plan` writes a revoke/grant migration and its exact rollback.

Where a check overlaps with Splinter, it says so below.

## Install

No install needed — run it with `npx`:

```bash
npx supabase-grants scan supabase/migrations
```

Or install it globally:

```bash
npm i -g supabase-grants
supabase-grants scan supabase/migrations
```

From a clone of this repository (Node 20+, no build step):

```bash
npm install
node bin/supabase-grants.mjs scan path/to/supabase/migrations
```

One runtime dependency: `pg`, used only by `live`.

## Commands

The examples below use `npx supabase-grants`; a global install drops the `npx` prefix, and from a clone,
run `node bin/supabase-grants.mjs` instead.

### `scan` — static, no database

```bash
npx supabase-grants scan supabase/migrations --md scan-report.md
npx supabase-grants scan supabase/migrations --json --fail-on medium
```

Parses and replays every `*.sql` file in the directory (default `supabase/migrations`), building the
*effective* state of each table — does it exist, is RLS on, which policies apply, what has been granted or
revoked to which role — then reports the findings listed under
[Findings and severities](#findings-and-severities).

**File order.** Files are replayed in filename order by plain string comparison (not a locale-aware sort),
which matches the Supabase CLI for its `<timestamp>_<name>.sql` naming.

**Names.** Unquoted identifiers are lowercased, `"quoted"` ones are kept exactly. Unqualified names resolve
against the file's search path: `public` by default, changed for the rest of that file by `set
search_path = ...` (or pg_dump's `select set_config('search_path', ...)`). An unqualified `create table`
goes into the first schema on the path; an unqualified reference resolves to the first schema on the path
that has a table of that name.

Supported statements:

- `create table` (incl. `if not exists`, `unlogged`, `... as select`, `... (like ...)`, `... partition of`),
  `drop table`, `alter table [if exists] [only] ... rename to | set schema`
- `alter table [if exists] [only] ... enable | disable | [no] force row level security`
- `create view` / `create materialized view` / `drop view` (tracked as existing, not analyzed)
- `create policy` (`as permissive | restrictive`, `for <cmd>`, `to <roles>`, `using`, `with check`),
  `alter policy` (incl. `rename to`), `drop policy [if exists]`
- `grant` / `revoke` on a table (incl. column lists and `to public`), on `all tables in schema`
  (applied to the tables that exist at that point, like Postgres), on a sequence, on a function
- `alter default privileges [for role ...] [in schema ...] grant | revoke ... on tables`
- `create [or replace] function | procedure` (`security definer`, `set search_path`, `returns trigger`),
  `alter function | procedure ... set | reset search_path | security definer | security invoker`
- `drop schema ... cascade`, `set search_path`

Handles `--` and `/* */` comments, `'...'` and `E'...'` strings, `"quoted"` identifiers, `$$`/`$tag$`
bodies, CRLF line endings and a UTF-8 BOM.

What the scan **can't** see is counted instead of guessed:

- `unparsed_statements` — statements that could change grants/RLS but can't be interpreted statically:
  `DO` blocks, dynamic SQL, a grant or policy in a shape outside the list above. Counted per file.
- `warnings` — a policy/grant/RLS statement on a table no earlier migration creates. It is **not applied**
  (the table is not invented). Supabase's own schemas (`storage.objects`, `auth.users`, ...) are exempt.

Both appear in the Markdown and JSON reports. **Tables created in the dashboard or the SQL editor, without
a migration file, are invisible to the static scan** — they show up only as warnings. Use `live` for those.

### `live` — read-only audit and a planned migration

```bash
npx supabase-grants live --db "$DATABASE_URL" --plan least_privilege.sql --pin-defaults
```

`--db` falls back to the `DATABASE_URL` environment variable. Use the **session-mode pooler** connection
string from the dashboard (Connect → Session pooler):

```
postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
```

The direct connection (`db.<project-ref>.supabase.co:5432`) is IPv6-only unless the project has the IPv4
add-on.

Everything runs in **one read-only transaction** (`begin isolation level repeatable read read only` …
`rollback`): every query sees the same snapshot and the server rejects any write. What it checks:

- **Privileges** via `has_table_privilege(role, table, privilege)` for `anon` and `authenticated`, which sees
  grants made to `PUBLIC` or through role membership, not just grants by name — for SELECT, INSERT, UPDATE,
  DELETE, TRUNCATE, REFERENCES, TRIGGER, plus MAINTAIN on Postgres 17+ (the server version is read first;
  MAINTAIN is never passed to an older server). Privileges held only on some columns
  (`has_any_column_privilege`) count as **partially granted**: the table is reachable, but it is never
  reported as a missing grant or planned as a table-level revoke.
- **Grants vs policies**: for every table × role × command, a privilege with no matching permissive policy
  is `grant_without_policy`, a permissive policy with no privilege is `policy_without_grant`. With RLS off
  the comparison is skipped (policies are inert) and the table gets one `rls_off_exposed` if reachable.
  Partitions are checked as tables of their own.
- **Write policies without a SELECT policy** (`write_without_select_policy`): UPDATE/DELETE with a WHERE
  clause only reach rows the role can select, and INSERT … RETURNING needs to read the new row, so they
  silently affect 0 rows. SELECT is never planned for revocation from a role that has a write policy on
  the table.
- **Views** in `public` an API role can select without `security_invoker = true` (Postgres 15+), and
  **materialized views** an API role can select (they can't have RLS).
- **SECURITY DEFINER functions and procedures** (not trigger functions), keyed by their full signature
  (`oid::regprocedure`). `set search_path = ''` counts as a fixed search path.
- **Legacy default privileges** in `public` for tables, sequences and functions (`pg_default_acl`, per
  grantor role).

`--plan least_privilege.sql` writes the least-privilege migration to that file and its exact rollback next
to it as `least_privilege_rollback.sql`. **Nothing is ever executed** — the tool only writes SQL. The plan:

- revokes every `grant_without_policy` and `grant_dangerous_privilege` privilege;
- grants every `policy_without_grant` privilege, plus `usage, select` on the sequences behind that table's
  serial/identity columns (found via `pg_depend`) when the role lacks them — otherwise inserts fail;
- with `--pin-defaults`, and only if they exist, revokes the legacy defaults with `alter default privileges
  for role postgres in schema public revoke all on tables | sequences | functions from anon,
  authenticated`. Migrations run as `postgres`, so that's the only grantor a migration can change; defaults
  set by other roles (e.g. `supabase_admin`) are listed in a comment and left alone;
- never touches `service_role`, and never rewrites a policy expression.

### `study` — numbers across many repos

```bash
npx supabase-grants study --list repos.txt --out study --concurrency 4
npx supabase-grants study --aggregate study --md STUDY.md
```

`--list` reads `owner/repo` lines. Every line is checked against `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$` before
it is used in a URL, a git command or a file name; lines that don't match are only counted. Each repo is
cloned with `git clone --filter=blob:none --depth 1 --sparse` and a sparse checkout of
`supabase/migrations` only, scanned with the **static** scan (`live` is never used), and deleted.

One JSON record is written per attempted repo, as soon as it finishes, with a `status` of `scanned`,
`no_migrations`, `clone_failed` or `scan_failed`, the HEAD commit sha, the last commit date
(`git log -1 --format=%cI`), the tool version, and for scanned repos the full report (findings, unparsed
statement count, warnings) plus a `migrations_hash` (sha256 of the migration contents). Rerunning with the
same `--list`/`--out` skips repos that already have a record, except `clone_failed`, which is retried.
`--max N` limits the run to the first N lines.

Set `GITHUB_TOKEN` to raise GitHub's rate limits for the clones. It is passed to git through environment
configuration, never on a command line, in a log line or in a record. Git never prompts for credentials.

`--aggregate` counts repos with identical `migrations_hash` once (renames, untouched forks) and writes
`STUDY.md` with aggregate numbers only: the attempted → cloned → with migrations → scanned funnel, the share
of repos and the share of tables affected by each finding kind, and parser coverage.

**`study/` is gitignored. The per-repo records name the repositories they came from — never publish
them.** Only the aggregate `STUDY.md` is meant to be shared; a test checks it contains no repository
identifier.

## Findings and severities

| Kind | Where | Severity |
|---|---|---|
| `rls_disabled` | scan | critical; medium if the migrations explicitly revoke from both `anon` and `authenticated` |
| `rls_off_exposed` | live | critical |
| `policy_open_write` — always-true `using` on UPDATE/DELETE/ALL | both | critical |
| `policy_open_insert` — always-true `with check` on INSERT/ALL | both | high |
| `policy_open_read` — always-true `using` on SELECT/ALL | both | high if it applies to `anon`/`PUBLIC`, else medium |
| `policy_no_to_clause` — policy applies to `PUBLIC` | both | high for write commands, medium for SELECT |
| `grant_dangerous_privilege` | live | high for TRUNCATE, medium for REFERENCES/TRIGGER/MAINTAIN |
| `grant_without_policy` | live | high for anon INSERT/UPDATE/DELETE, medium for anon SELECT, low for authenticated |
| `view_without_security_invoker` | live | high (Splinter has a similar lint, `security_definer_view`) |
| `matview_exposed` | live | high (Splinter has a similar lint, `materialized_view_in_api`) |
| `definer_exposed` — SECURITY DEFINER function executable by an API role | live | high if `anon`, medium if only `authenticated` |
| `table_without_explicit_grant` | scan | medium; high from 2026-10-30 |
| `policy_open_to_all_authenticated` — policy only checks the caller is signed in | both | medium |
| `write_without_select_policy` | live | medium |
| `definer_no_search_path` | both | medium — "may be exploitable"; mirrors Splinter lint 0011 `function_search_path_mutable`, restricted to SECURITY DEFINER functions |
| `policy_without_grant` | live | info |
| `not_exposed` | live | info |
| `not_in_api_schema` | scan | info |
| `legacy_default_privileges` | live | info |

The policy checks are **literal-pattern checks**, not an evaluation of the expression. After lowercasing,
removing whitespace and `::text` casts, and stripping redundant outer parentheses:

- "always-true" means exactly `true` or `1=1` (so `true`, `(true)`, `1 = 1` match; `2 > 1` does not);
- "only checks the caller is signed in" means exactly `auth.uid() is not null`, `auth.jwt() is not null` or
  `auth.role() = 'authenticated'`, each also in the `(select auth.uid())` form.

Restrictive policies never trigger the `policy_open_*` findings and never count as "needed" — they can only
narrow what a permissive policy allows.

## Exit codes and CI options

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` |
| 1 | a finding at or above `--fail-on` (default `high`) |
| 2 | a critical finding (unless `--fail-on none`) |
| 3 | tool error: bad path, zero tables found, connection refused, a crash |

- `--fail-on <critical|high|medium|low|info|none>` sets the threshold for exit code 1.
- `--ignore <schema.table>:<kind>` (repeatable) drops matching findings before the report, the exit code and
  the plan. For function findings, `schema.function` matches every overload.
- `--json` output carries `schema_version: 1`, and every finding has a `severity`.

## Limitations

- **Only the `public` schema.** The schemas exposed through the Data API are configurable (the "Exposed
  schemas" setting); both `scan` and `live` assume `public` only. Tables in other schemas get at most an
  info note from `scan` and are not inspected by `live`.
- **Not a full SQL parser.** Statements outside the supported list are ignored or, when they could matter,
  counted as `unparsed_statements` — e.g. `DO` blocks, dynamic SQL, `alter table ... add column`, or
  privileges granted through role membership.
- **The static scan can't see platform defaults.** It only knows what the migration files grant and revoke,
  not whether the target project still has the legacy default grants — that uncertainty is exactly what
  `table_without_explicit_grant` and `rls_disabled` describe.
- **Literal patterns** (see above): an always-true or signed-in-only policy written in another form is not
  caught.
- **`live` runs as whichever role connects** and needs to read the catalogs (`pg_class`, `pg_policies`,
  `pg_proc`, `pg_default_acl`, `pg_depend`).

## Tests

```bash
npm test
```

Plain `node --test`. Parsing, replay, analysis and plan generation are pure functions tested with fixtures
(including CRLF/BOM, E-strings, nested dollar quotes and filename ordering) and fake rows; the CLI's exit
codes are tested end to end. No network, no database.
