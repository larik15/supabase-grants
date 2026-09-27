# Supabase grants — study

Static scan of public repositories that keep Supabase migrations in `supabase/migrations`. Aggregate numbers only — no repo names, clone URLs or file paths appear anywhere in this file.

## Sample

| Stage | Repos |
|---|---|
| Attempted | 981 |
| Cloned | 976 |
| With `supabase/migrations` | 673 |
| Scanned | 673 |

- 5 could not be cloned (renamed, deleted or made private since the list was built).
- 95 scanned repo(s) had byte-identical migrations to one already counted (renames, forks, shared templates) and are counted once: **578** repos below. The largest group is 89 repos sharing one set of migrations.
- Tables found: **22729** (median 16.5 per repo, mean 39.3 — a few very large schemas pull the mean above the median; the largest repo has 1457).
- "Toy" repos (0-1 tables — a template or an abandoned `supabase init`): **39** (6.7%). The per-repo table shows rates with and without them.

## Share of repos affected

Existing tables keep whatever grants they already have — none of this affects a table already running in production. "Depends on legacy default grants" means at least one table's migration has no explicit `grant ... to anon/authenticated` and relies on the platform granting it automatically. The platform stops setting that default for projects created after 2026-05-30 and for every project from 2026-10-30 (a project can re-add it with ALTER DEFAULT PRIVILEGES); in a new environment built from these migrations without it (a fresh project, branch, or redeploy), every Data API request to the table returns 42501 permission denied (with a hint naming the missing grant).

| Condition | % of all repos (n=578) | % excluding toy repos (n=539) |
|---|---|---|
| Migrations depend on legacy default grants (no explicit grant for at least one table) | 78% | 80.1% |
| At least one policy_open_read — always-true using on a readable policy | 68% | 71.1% |
| At least one policy_open_write — always-true using on UPDATE/DELETE | 27.9% | 28.9% |
| At least one policy that only checks the caller is signed in | 14.7% | 15.6% |
| At least one policy with no TO clause (applies to PUBLIC) | 65.9% | 67.5% |
| At least one SECURITY DEFINER function without a fixed search_path | 13.1% | 13.9% |
| At least one table with RLS disabled | 15.6% | 16.7% |

## Share of tables affected

| Condition | % of tables (n=22729) |
|---|---|
| No explicit grant to anon/authenticated | 61.7% |
| RLS disabled | 5.8% |
| Always-true read policy | 17.1% |
| Always-true insert policy | 6.6% |
| Always-true update/delete policy | 5% |
| Policy that only checks the caller is signed in | 1.1% |
| Policy with no TO clause | 39.2% |

## Raw finding counts, by kind

| Finding kind | Count |
|---|---|
| policy_no_to_clause | 21551 |
| table_without_explicit_grant | 14029 |
| policy_open_read | 4159 |
| policy_open_insert | 1562 |
| rls_disabled | 1317 |
| policy_open_write | 1263 |
| not_in_api_schema | 579 |
| definer_no_search_path | 459 |
| policy_open_to_all_authenticated | 297 |

## Parser coverage

- Statements that could affect grants/RLS but couldn't be interpreted (DO blocks, dynamic SQL, unusual syntax): **12989**, in 65.4% of repos.
- Statements targeting a table no earlier migration creates (not applied): **9512**, in 24.9% of repos.

## Limitations

- **The sample is not random.** Repos were found with GitHub repository search on the default README text Lovable generates for new projects. Search returns at most about 1,000 results and favours recently updated repos, and only repos that keep migrations in `supabase/migrations` (Supabase CLI layout) are scanned.
- **Static only.** These numbers come from migration files, never a live database. A table flagged for a legacy-grant dependency is at risk, not necessarily broken today — that depends on whether its project still has the platform's default grants, which a static scan cannot see.
- **Tables created outside migrations are invisible** to this scan (dashboard, SQL editor), and statements the parser couldn't interpret are counted above rather than applied.
- **Shallow clone, default branch only.** Migrations on other branches, or removed from history, are not seen.
- **Literal patterns, not semantic analysis.** Policy expressions are matched against a short list of literal forms (`true`, `1 = 1`, `auth.uid() is not null`, ...); an equivalent written differently is not caught.
- **Repos that were renamed, deleted or made private** since the list was built are excluded, not corrected for.
- **Duplicate detection is exact-match only**: a fork with one changed migration counts as a separate repo.
- **A snapshot, not a monitor.** The numbers reflect the scan date only.
