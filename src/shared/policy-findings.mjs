// Policy-level findings shared by static/analyze.mjs (from a migration replay)
// and live/analyze.mjs (from a live `pg_policies` query) — both normalize
// their policy rows to the same shape before calling this:
//   { name, cmd, roles: string[], permissive: boolean, using: string|null, withCheck: string|null }
// (roles includes 'public' when the policy has no TO clause, matching what
// Postgres itself puts in pg_policies.roles.)
//
// Expression checks are literal patterns after normalization (lowercase,
// whitespace and ::text casts removed, redundant outer parentheses stripped),
// not an evaluation of the expression: `1 = 1` is caught, `2 > 1` is not.
//
// Vocabulary/severity heuristics adapted from supabase-security-mcp's
// src/policies.mjs (analyzePolicies).

// True when the parenthesis at index 0 closes at the very end of the string.
function wrapsWhole(s) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') {
      depth--;
      if (depth === 0 && i < s.length - 1) return false;
    }
  }
  return depth === 0;
}

export function normalizeExpr(expr) {
  let s = String(expr).toLowerCase().replace(/::text\b/g, '').replace(/\s+/g, '');
  while (s.startsWith('(') && s.endsWith(')') && wrapsWhole(s)) s = s.slice(1, -1);
  return s;
}

const OPEN_EXPRS = new Set(['true', '1=1']);

// Expressions that are true for every signed-in user, i.e. for anyone who can
// create an account.
const ALL_AUTHENTICATED_EXPRS = new Set([
  'auth.uid()isnotnull',
  '(selectauth.uid())isnotnull',
  'auth.jwt()isnotnull',
  '(selectauth.jwt())isnotnull',
  "auth.role()='authenticated'",
  "(selectauth.role())='authenticated'",
]);

function isTrueExpr(expr) {
  return expr != null && OPEN_EXPRS.has(normalizeExpr(expr));
}

function isAllAuthenticatedExpr(expr) {
  return expr != null && ALL_AUTHENTICATED_EXPRS.has(normalizeExpr(expr));
}

function isWriteCmd(cmd) {
  return cmd === 'ALL' || cmd === 'INSERT' || cmd === 'UPDATE' || cmd === 'DELETE';
}

// The expressions that decide which rows a command can touch.
function relevantExprs(policy) {
  if (policy.cmd === 'INSERT') return [policy.withCheck];
  if (policy.cmd === 'SELECT' || policy.cmd === 'DELETE') return [policy.using];
  return [policy.using, policy.withCheck];
}

// tableLabel: "schema.table", used in finding.table and messages.
export function policyFindings(tableLabel, policy) {
  const findings = [];
  const roles = policy.roles;
  const isPublicRole = roles.includes('public');
  const cmd = policy.cmd;

  if (isPublicRole) {
    findings.push({
      severity: isWriteCmd(cmd) ? 'high' : 'medium',
      kind: 'policy_no_to_clause',
      table: tableLabel,
      policy: policy.name,
      message: `Policy "${policy.name}" on ${tableLabel} (${cmd}) has no TO clause, so it applies to PUBLIC — including anon — regardless of what its name suggests.`,
      fix: `Recreate the policy with an explicit "to authenticated" (or "to anon" if that's intended).`,
    });
  }

  // Restrictive policies only narrow what permissive policies already allow;
  // an open restrictive policy grants nothing by itself, so it doesn't count here.
  if (!policy.permissive) return findings;

  const open = [];
  if ((cmd === 'SELECT' || cmd === 'ALL') && isTrueExpr(policy.using)) {
    open.push('read');
    findings.push({
      severity: roles.includes('anon') || isPublicRole ? 'high' : 'medium',
      kind: 'policy_open_read',
      table: tableLabel,
      policy: policy.name,
      message: `Policy "${policy.name}" on ${tableLabel} allows ${cmd} with an always-true using expression for [${roles.join(', ')}] — every row is readable.`,
      fix: `Replace with an ownership check, e.g. using (auth.uid() = user_id).`,
    });
  }

  if ((cmd === 'INSERT' || cmd === 'ALL') && isTrueExpr(policy.withCheck)) {
    open.push('insert');
    findings.push({
      severity: 'high',
      kind: 'policy_open_insert',
      table: tableLabel,
      policy: policy.name,
      message: `Policy "${policy.name}" on ${tableLabel} allows INSERT with an always-true with check for [${roles.join(', ')}] — anyone in that role can write arbitrary rows.`,
      fix: `Use with check (auth.uid() = user_id) so users can only insert rows they own.`,
    });
  }

  if ((cmd === 'UPDATE' || cmd === 'DELETE' || cmd === 'ALL') && isTrueExpr(policy.using)) {
    open.push('write');
    findings.push({
      severity: 'critical',
      kind: 'policy_open_write',
      table: tableLabel,
      policy: policy.name,
      message: `Policy "${policy.name}" on ${tableLabel} allows ${cmd} with an always-true using expression for [${roles.join(', ')}] — any row can be modified or deleted.`,
      fix: `Add using (auth.uid() = user_id) (and a matching with check for UPDATE).`,
    });
  }

  if (!open.length && relevantExprs(policy).some(isAllAuthenticatedExpr)) {
    findings.push({
      severity: 'medium',
      kind: 'policy_open_to_all_authenticated',
      table: tableLabel,
      policy: policy.name,
      message: `Policy "${policy.name}" on ${tableLabel} (${cmd}) only checks that the caller is signed in (e.g. auth.uid() is not null), so every authenticated user can ${cmd === 'ALL' ? 'read and write' : cmd.toLowerCase()} every row — and anyone can become an authenticated user unless sign-ups are disabled.`,
      fix: `Scope it to the row, e.g. using (auth.uid() = user_id), or to a membership check.`,
    });
  }

  return findings;
}

export function definerNoSearchPathFinding(fnLabel, fn) {
  if (!fn.securityDefiner || fn.searchPathSet || fn.isTrigger) return null;
  return {
    severity: 'medium',
    kind: 'definer_no_search_path',
    table: null,
    function: fnLabel,
    message: `Function ${fnLabel} runs as SECURITY DEFINER without a fixed search_path, which may be exploitable: whoever can create objects in a schema earlier on the caller's search_path can shadow what the function calls. Mirrors Splinter lint 0011 (function_search_path_mutable).`,
    fix: `alter function ${fnLabel.replace(/\(.*\)$/, '')}(...) set search_path = '';  -- then schema-qualify names inside the function`,
  };
}
