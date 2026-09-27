# Supabase grants — study

Static scan of public repositories that keep Supabase migrations in `supabase/migrations`. Aggregate numbers only — no repo names, clone URLs or file paths appear anywhere in this file.

## Sample

| Stage | Repos |
|---|---|
| Attempted | 981 |
| Cloned | 976 |
| With `supabase/migrations` | 675 |
| Scanned | 675 |

- 5 could not be cloned (renamed, deleted or made private since the list was built).
- 95 scanned repo(s) had byte-identical migrations to one already counted (renames, forks, shared templates) and are counted once: **580** repos below. The largest group is 89 repos sharing one set of migrations.
- Tables found: **22821** (median 16.5 per repo, mean 39.3 — a few very large schemas pull the mean above the median; the largest repo has 1457).
- "Toy" repos (0-1 tables — a template or an abandoned `supabase init`): **40** (6.9%). The per-repo table shows rates with and without them.

## Share of repos affected

Existing tables keep whatever grants they already have — none of this affects a table already running in production. "Depends on legacy default grants" means at least one table's migration has no explicit `grant ... to anon/authenticated` and relies on the platform granting it automatically. The platform stops setting that default for projects created after 2026-05-30 and for every project from 2026-10-30 (a project can re-add it with ALTER DEFAULT PRIVILEGES); in a new environment built from these migrations without it (a fresh project, branch, or redeploy), every Data API request to the table returns 42501 permission denied (with a hint naming the missing grant).

| Condition | % of all repos (n=580) | % excluding toy repos (n=540) |
|---|---|---|
| Migrations depend on legacy default grants (no explicit grant for at least one table) | 78.1% | 80.4% |
| At least one policy_open_read — always-true using on a readable policy | 67.8% | 70.9% |
| At least one policy_open_write — always-true using on UPDATE/DELETE | 28.1% | 29.3% |
| At least one policy that only checks the caller is signed in | 14.8% | 15.7% |
| At least one policy with no TO clause (applies to PUBLIC) | 65.7% | 67.4% |
| At least one SECURITY DEFINER function without a fixed search_path | 13.1% | 13.9% |
| At least one table with RLS disabled | 15.7% | 16.9% |

Lower bound: 17.2% of repos (100 of 580) have no grant statement anywhere in their migrations — no parsed `GRANT`, and no unparsed statement containing the word "grant"; the 78.1% figure above is the upper bound.

## Share of tables affected

| Condition | % of tables (n=22821) |
|---|---|
| No explicit grant to anon/authenticated | 62% |
| RLS disabled | 5.8% |
| Always-true read policy | 17% |
| Always-true insert policy | 6.6% |
| Always-true update/delete policy | 4.9% |
| Policy that only checks the caller is signed in | 1.1% |
| Policy with no TO clause | 39.1% |

## Raw finding counts, by kind

| Finding kind | Count |
|---|---|
| policy_no_to_clause | 21569 |
| table_without_explicit_grant | 14152 |
| policy_open_read | 4161 |
| policy_open_insert | 1561 |
| rls_disabled | 1323 |
| policy_open_write | 1262 |
| not_in_api_schema | 581 |
| definer_no_search_path | 459 |
| policy_open_to_all_authenticated | 302 |

## Parser coverage

- Statements that could affect grants/RLS but couldn't be interpreted (DO blocks, dynamic SQL, unusual syntax): **13134**, in 65.3% of repos.
- Statements targeting a table no earlier migration creates (not applied): **9616**, in 25% of repos.

## Limitations

- **The sample is not random.** Repos were found with GitHub repository search on the default README text Lovable generates for new projects. Search returns at most about 1,000 results and favours recently updated repos, and only repos that keep migrations in `supabase/migrations` (Supabase CLI layout) are scanned.
- **Static only.** These numbers come from migration files, never a live database. A table flagged for a legacy-grant dependency is at risk, not necessarily broken today — that depends on whether its project still has the platform's default grants, which a static scan cannot see.
- **Tables created outside migrations are invisible** to this scan (dashboard, SQL editor), and statements the parser couldn't interpret are counted above rather than applied.
- **Shallow clone, default branch only.** Migrations on other branches, or removed from history, are not seen.
- **Literal patterns, not semantic analysis.** Policy expressions are matched against a short list of literal forms (`true`, `1 = 1`, `auth.uid() is not null`, ...); an equivalent written differently is not caught.
- **Repos that were renamed, deleted or made private** since the list was built are excluded, not corrected for.
- **Duplicate detection is exact-match only**: a fork with one changed migration counts as a separate repo.
- **A snapshot, not a monitor.** The numbers reflect the scan date only.
