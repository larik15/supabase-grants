// Pure findings over the effective state produced by replay.mjs. No SQL, no
// network — just rows in, findings out, so this is unit-testable without a
// database or files.
//
// Table/RLS-level checks here are static-only (table_without_explicit_grant,
// rls_disabled, not_in_api_schema). Policy- and function-level checks are
// shared with live/analyze.mjs — see src/shared/policy-findings.mjs.

import { policyFindings, definerNoSearchPathFinding } from '../shared/policy-findings.mjs';
import { sortFindings, summarizeFindings, exitCodeForFindings } from '../shared/findings.mjs';

export { summarizeFindings, exitCodeForFindings };

const DEFAULT_CUTOVER = '2026-10-30T00:00:00Z';

function hasAnyGrant(grants, roles) {
  return roles.some(role => (grants[role] || []).length > 0);
}

function tableLabel(t) {
  return `${t.schema}.${t.name}`;
}

// A public table without RLS is critical even with no explicit grant in the
// migrations: on a project created before the default change, the legacy
// default grants already give anon/authenticated full access to it. Only an
// explicit revoke from both roles (which strips those defaults) lowers it.
function rlsDisabledFindings(t, label, exposedToApi) {
  const fix = `alter table ${label} enable row level security; then add policies.`;
  if (exposedToApi) {
    return [{
      severity: 'critical',
      kind: 'rls_disabled',
      table: label,
      message: `RLS is disabled on ${label} and the migrations explicitly grant it to anon/authenticated — every row is readable/writable through the API.`,
      fix,
    }];
  }
  if (t.schema !== 'public') return [];

  const revokedFrom = t.revokedFrom || [];
  if (['anon', 'authenticated'].every(role => revokedFrom.includes(role))) {
    return [{
      severity: 'medium',
      kind: 'rls_disabled',
      table: label,
      message: `RLS is disabled on ${label}. The migrations explicitly revoke from anon and authenticated, so the platform's default grants shouldn't reach it — but the table is fully open to whichever role is granted access next, with nothing in between.`,
      fix,
    }];
  }
  return [{
    severity: 'critical',
    kind: 'rls_disabled',
    table: label,
    message: `RLS is disabled on ${label}. On any project created before Supabase's default change, the legacy default grants give anon and authenticated full privileges on every public table — so this table is readable and writable by anyone with the anon key, with no policy in between. Nothing in the migrations revokes those defaults.`,
    fix,
  }];
}

// A grant to PUBLIC reaches anon and authenticated too.
const API_GRANTEES = ['anon', 'authenticated', 'public'];

function findingsForTable(t, { afterCutover }) {
  const findings = [];
  const label = tableLabel(t);
  const exposedToApi = hasAnyGrant(t.grants, API_GRANTEES);

  if (t.schema !== 'public') {
    // The Oct 30 change and the Data API itself only cover `public` (and any
    // schema explicitly exposed via db_schema config, which this static scan
    // has no way to see) — a table elsewhere isn't "missing" a grant, it was
    // never in scope for one.
    if (!exposedToApi) {
      findings.push({
        severity: 'info',
        kind: 'not_in_api_schema',
        table: label,
        message: `${label} is outside the public schema and has no explicit grant to anon/authenticated — not reachable through the Data API by default, and not affected by the 2026-10-30 change either way.`,
        fix: null,
      });
    }
  } else if (!exposedToApi && !t.partitionOf) {
    // Partitions are normally reached through their parent, so a partition
    // without its own grant is expected.
    findings.push({
      severity: afterCutover ? 'high' : 'medium',
      kind: 'table_without_explicit_grant',
      table: label,
      message: `${label} has no explicit GRANT to anon or authenticated in the scanned migrations. This table's migration relies on the platform's legacy default grants. Applied to a project created after 2026-05-30 — or to any project after 2026-10-30 — every Data API request to the table returns 42501 permission denied (with a hint naming the missing grant) in new environments, branches and redeploys, and any new table created the same way will too.`,
      fix: `grant select, insert, update, delete on ${label} to authenticated; -- narrow to what the app actually needs`,
    });
  }

  if (!t.rlsEnabled) findings.push(...rlsDisabledFindings(t, label, exposedToApi));

  for (const policy of t.policies) findings.push(...policyFindings(label, policy));

  return findings;
}

function findingsForFunction(fn) {
  const finding = definerNoSearchPathFinding(`${fn.schema}.${fn.name}`, fn);
  return finding ? [finding] : [];
}

// tables: array from replay.effectiveStateToArray
// functions: array from replay.functionsToArray
// opts.now / opts.cutover: Date | ISO string, mainly for tests.
export function analyzeEffectiveState({ tables, functions = [] }, opts = {}) {
  const now = opts.now ? new Date(opts.now) : new Date();
  const cutover = new Date(opts.cutover || DEFAULT_CUTOVER);
  const afterCutover = now >= cutover;

  const findings = [
    ...tables.flatMap(t => findingsForTable(t, { afterCutover })),
    ...functions.flatMap(findingsForFunction),
  ];

  return sortFindings(findings);
}
