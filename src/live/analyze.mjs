// Pure functions over introspect.mjs's rows: do the table privileges (GRANTs)
// match what the RLS policies actually allow? No DB, no SQL — just rows in,
// findings out (see test/live-analyze.test.mjs for the fake-row fixtures).

import { policyFindings, definerNoSearchPathFinding } from '../shared/policy-findings.mjs';
import { sortFindings } from '../shared/findings.mjs';

const API_ROLES = ['anon', 'authenticated'];
const TABLE_CMDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

// Table privileges the Data API never needs. TRUNCATE in particular is not
// subject to RLS at all.
const DANGEROUS_PRIVS = {
  TRUNCATE: {
    severity: 'high',
    why: 'TRUNCATE is not subject to RLS at all — any code path that runs as this role (an RPC, a trigger, a direct connection) can empty the table in one statement, whatever the policies say. The Data API itself never issues TRUNCATE, which is why nobody notices it is granted.',
  },
  REFERENCES: {
    severity: 'medium',
    why: 'REFERENCES lets the role create foreign keys pointing at this table, which can be used to probe which values exist in it without SELECT. The Data API never needs it.',
  },
  TRIGGER: {
    severity: 'medium',
    why: 'TRIGGER lets the role attach triggers to this table, i.e. run its own code on every write by anyone. The Data API never needs it.',
  },
  MAINTAIN: {
    severity: 'medium',
    why: 'MAINTAIN (Postgres 17+) lets the role run VACUUM, ANALYZE, CLUSTER, REINDEX, REFRESH MATERIALIZED VIEW and LOCK TABLE on this table. The Data API never needs it.',
  },
};

function tableLabel(t) {
  return `${t.schema}.${t.table}`;
}

function normalizeRoles(roles) {
  if (Array.isArray(roles)) return roles.map(r => String(r).toLowerCase());
  if (typeof roles === 'string') return roles.replace(/[{}]/g, '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return ['public'];
}

function normalizePolicy(row) {
  return {
    name: row.policy,
    cmd: String(row.cmd || 'ALL').toUpperCase(),
    roles: normalizeRoles(row.roles),
    permissive: row.permissive === true || String(row.permissive).toUpperCase() === 'PERMISSIVE',
    using: row.qual,
    withCheck: row.with_check,
  };
}

// key -> role -> Set<privilege>
function buildPrivilegeIndex(rows, keyOf) {
  const index = new Map();
  for (const row of rows) {
    const key = keyOf(row);
    if (!index.has(key)) index.set(key, new Map());
    const byRole = index.get(key);
    if (!byRole.has(row.grantee)) byRole.set(row.grantee, new Set());
    byRole.get(row.grantee).add(String(row.privilege).toUpperCase());
  }
  return index;
}

function buildPolicyIndex(policyRows) {
  const index = new Map();
  for (const row of policyRows) {
    if (!index.has(row.table)) index.set(row.table, []);
    index.get(row.table).push(normalizePolicy(row));
  }
  return index;
}

function buildOwnedSequenceIndex(rows) {
  const index = new Map();
  for (const row of rows) {
    if (!index.has(row.table)) index.set(row.table, []);
    index.get(row.table).push(`${row.sequence_schema}.${row.sequence}`);
  }
  return index;
}

function hasPriv(byRole, role, priv) {
  return (byRole.get(role) || new Set()).has(priv);
}

// "Exposed" means reachable through the Data API, i.e. any DML privilege,
// on the whole table or on some of its columns.
function hasAnyApiGrant(...indexes) {
  return API_ROLES.some(role => TABLE_CMDS.some(cmd => indexes.some(byRole => hasPriv(byRole, role, cmd))));
}

function appliesTo(policy, role) {
  return policy.roles.includes(role) || policy.roles.includes('public');
}

function isNeeded(policies, role, cmd) {
  return policies.some(p => p.permissive && appliesTo(p, role) && (p.cmd === cmd || p.cmd === 'ALL'));
}

const WRITE_CMDS = ['INSERT', 'UPDATE', 'DELETE'];

// Any policy (permissive or restrictive) that concerns writes by this role.
// SELECT is never revoked from such a role: UPDATE/DELETE only see rows the
// role can SELECT, and INSERT ... RETURNING needs SELECT too.
function hasWritePolicy(policies, role) {
  return policies.some(p => appliesTo(p, role) && (WRITE_CMDS.includes(p.cmd) || p.cmd === 'ALL'));
}

function writeWithoutSelectFinding(label, policies, role) {
  const writeCmds = [...new Set(policies.filter(p => p.permissive && appliesTo(p, role) && WRITE_CMDS.includes(p.cmd)).map(p => p.cmd))];
  if (!writeCmds.length || isNeeded(policies, role, 'SELECT')) return null;
  return {
    severity: 'medium',
    kind: 'write_without_select_policy',
    table: label,
    role,
    message: `${role} has ${writeCmds.join('/')} policies on ${label} but no SELECT policy. UPDATE and DELETE with a WHERE clause only reach rows the role can select, and INSERT ... RETURNING needs to read the new row, so these silently affect 0 rows or fail even though a write policy exists.`,
    fix: `Add a SELECT policy for ${role} matching the rows it may write (e.g. using (auth.uid() = user_id)).`,
  };
}

// Severity per spec: DELETE/UPDATE/INSERT for anon = high, SELECT for anon =
// medium, anything for authenticated = low.
function grantWithoutPolicySeverity(role, priv) {
  if (role === 'anon') return priv === 'SELECT' ? 'medium' : 'high';
  return 'low';
}

// Sequences behind the table's serial/identity columns that the role would
// still be missing USAGE/SELECT on once the table itself is granted.
function missingSequencePrivileges(sequences, sequenceIndex, role) {
  return sequences
    .map(seq => ({
      sequence: seq,
      privileges: ['USAGE', 'SELECT'].filter(p => !hasPriv(sequenceIndex.get(seq) || new Map(), role, p)),
    }))
    .filter(s => s.privileges.length);
}

function findingsForTable(t, ctx) {
  const findings = [];
  const label = tableLabel(t);
  const grantsByRole = ctx.grantsIndex.get(t.table) || new Map();
  const partialByRole = ctx.partialIndex.get(t.table) || new Map();
  const policies = ctx.policyIndex.get(t.table) || [];

  // Not governed by RLS, so reported whether RLS is on or off.
  for (const role of API_ROLES) {
    for (const [priv, { severity, why }] of Object.entries(DANGEROUS_PRIVS)) {
      if (!hasPriv(grantsByRole, role, priv)) continue;
      findings.push({
        severity,
        kind: 'grant_dangerous_privilege',
        table: label,
        role,
        privilege: priv,
        message: `${role} holds ${priv} on ${label}. ${why}`,
        fix: `revoke ${priv.toLowerCase()} on ${label} from ${role};`,
      });
    }
  }

  if (!t.rls_enabled) {
    // Policies are inert with RLS off; the only thing that matters is whether
    // anything can already reach the table.
    if (hasAnyApiGrant(grantsByRole, partialByRole)) {
      findings.push({
        severity: 'critical',
        kind: 'rls_off_exposed',
        table: label,
        message: `RLS is disabled on ${label} and anon/authenticated already have table privileges — every row is readable/writable through the API right now, regardless of any policies defined.`,
        fix: `alter table ${label} enable row level security;`,
      });
    }
    return findings;
  }

  for (const policy of policies) findings.push(...policyFindings(label, policy));

  const ownedSequences = ctx.ownedSequenceIndex.get(t.table) || [];

  for (const role of API_ROLES) {
    const writeWithoutSelect = writeWithoutSelectFinding(label, policies, role);
    if (writeWithoutSelect) findings.push(writeWithoutSelect);
    const keepSelect = hasWritePolicy(policies, role);

    for (const cmd of TABLE_CMDS) {
      const granted = hasPriv(grantsByRole, role, cmd);
      // Held on some columns only: "partially granted" — neither a missing
      // grant nor a table-level revoke candidate.
      if (!granted && hasPriv(partialByRole, role, cmd)) continue;
      const needed = isNeeded(policies, role, cmd);
      if (granted && !needed) {
        if (cmd === 'SELECT' && keepSelect) continue;
        findings.push({
          severity: grantWithoutPolicySeverity(role, cmd),
          kind: 'grant_without_policy',
          table: label,
          role,
          privilege: cmd,
          message: `${role} has ${cmd} on ${label} at the privilege level, but no permissive policy lets ${role} ${cmd.toLowerCase()} anything — today RLS blocks it, but the privilege is one policy typo away from live.`,
          fix: `revoke ${cmd.toLowerCase()} on ${label} from ${role};`,
        });
      } else if (!granted && needed) {
        findings.push({
          severity: 'info',
          kind: 'policy_without_grant',
          table: label,
          role,
          privilege: cmd,
          sequences: missingSequencePrivileges(ownedSequences, ctx.sequenceIndex, role),
          message: `A policy on ${label} lets ${role} ${cmd.toLowerCase()}, but ${role} has no ${cmd} privilege on the table — the policy is dead code today.`,
          fix: `grant ${cmd.toLowerCase()} on ${label} to ${role};`,
        });
      }
    }
  }

  if (!hasAnyApiGrant(grantsByRole, partialByRole)) {
    findings.push({
      severity: 'info',
      kind: 'not_exposed',
      table: label,
      message: `${label} has RLS enabled and no grants to anon/authenticated at all — not reachable through the API. Fine if this is meant to be an internal table.`,
      fix: null,
    });
  }

  return findings;
}

function findingsForView(v) {
  const selectableBy = normalizeRoles(v.selectable_by).filter(r => API_ROLES.includes(r));
  if (v.security_invoker || selectableBy.length === 0) return [];
  const label = `${v.schema}.${v.view}`;
  return [{
    severity: 'high',
    kind: 'view_without_security_invoker',
    table: label,
    message: `View ${label} is selectable by [${selectableBy.join(', ')}] and runs with its owner's privileges (no security_invoker), so the RLS policies of the tables it reads from are checked against the view owner, not the caller — usually meaning they don't apply at all. Supabase's Splinter linter flags the same thing as security_definer_view.`,
    fix: `alter view ${label} set (security_invoker = true);  -- requires Postgres 15+`,
  }];
}

function findingsForMatview(m) {
  const selectableBy = normalizeRoles(m.selectable_by).filter(r => API_ROLES.includes(r));
  if (selectableBy.length === 0) return [];
  const label = `${m.schema}.${m.matview}`;
  return [{
    severity: 'high',
    kind: 'matview_exposed',
    table: label,
    message: `Materialized view ${label} is selectable by [${selectableBy.join(', ')}]. Materialized views can't have RLS, so every row in it is readable through the Data API. Splinter has a similar lint (materialized_view_in_api).`,
    fix: `revoke select on ${label} from ${selectableBy.join(', ')};  -- or move it out of the exposed schema`,
  }];
}

// aclitem text: "grantee=privs/grantor", empty grantee = PUBLIC, "*" after a
// letter = with grant option.
const ACL_LETTERS = {
  r: 'SELECT', a: 'INSERT', w: 'UPDATE', d: 'DELETE', D: 'TRUNCATE', x: 'REFERENCES',
  t: 'TRIGGER', X: 'EXECUTE', U: 'USAGE', m: 'MAINTAIN',
};

export function parseAcl(acl) {
  if (!Array.isArray(acl)) return [];
  return acl.map(entry => {
    const [granteePart, rest = ''] = String(entry).split('=');
    const letters = rest.split('/')[0].replace(/\*/g, '');
    return {
      grantee: granteePart === '' ? 'public' : granteePart.replace(/^"|"$/g, ''),
      privileges: [...letters].map(l => ACL_LETTERS[l]).filter(Boolean),
    };
  });
}

// pg_default_acl object types covered by the 2026-10-30 change.
const DEFAULT_ACL_OBJECTS = { r: 'tables', S: 'sequences', f: 'functions' };

function findingsForDefaultPrivileges(defaultPrivilegeRows) {
  const findings = [];
  for (const row of defaultPrivilegeRows) {
    const objectType = DEFAULT_ACL_OBJECTS[row.object_type];
    if (!objectType) continue;
    const grants = parseAcl(row.acl).filter(g => API_ROLES.includes(g.grantee) && g.privileges.length);
    if (!grants.length) continue;
    findings.push({
      severity: 'info',
      kind: 'legacy_default_privileges',
      table: null,
      grantorRole: row.role,
      objectType,
      grants,
      message: `Default privileges in schema public (set by role "${row.role}") still auto-grant new ${objectType} to [${grants.map(g => g.grantee).join(', ')}] — this project is running on the platform's legacy default grants. The platform stops setting that default for projects created after 2026-05-30 and for every project from 2026-10-30 (a project can re-add it with ALTER DEFAULT PRIVILEGES); code that relies on it breaks in any environment that doesn't have it.`,
      fix: null,
    });
  }
  return findings;
}

// Keyed by the function's regprocedure signature (schema.name(argtypes)), so
// overloads are reported separately. Trigger functions are skipped: they
// can't be called through the API, only fired by their table.
function findingsForFunction(fn) {
  const findings = [];
  const label = fn.signature || `${fn.schema}.${fn.name}(${fn.args ?? ''})`;
  if (fn.security_definer && !fn.is_trigger) {
    const who = [fn.anon_can_execute && 'anon', fn.authenticated_can_execute && 'authenticated'].filter(Boolean);
    if (who.length) {
      findings.push({
        severity: fn.anon_can_execute ? 'high' : 'medium',
        kind: 'definer_exposed',
        table: null,
        function: label,
        message: `Function ${label} runs as SECURITY DEFINER (bypasses RLS) and is executable by [${who.join(', ')}].`,
        fix: `Add an explicit auth check inside the function, or revoke execute from ${who.join('/')}.`,
      });
    }
    const searchPathFinding = definerNoSearchPathFinding(label, { securityDefiner: true, searchPathSet: fn.has_search_path });
    if (searchPathFinding) findings.push(searchPathFinding);
  }
  return findings;
}

// rows: the object returned by live/introspect.mjs's introspect().
export function analyzeLive(rows) {
  const grants = rows.grants || [];
  const ctx = {
    grantsIndex: buildPrivilegeIndex(grants.filter(g => g.table_level !== false), r => r.table),
    partialIndex: buildPrivilegeIndex(grants.filter(g => g.table_level === false), r => r.table),
    policyIndex: buildPolicyIndex(rows.policies || []),
    ownedSequenceIndex: buildOwnedSequenceIndex(rows.ownedSequences || []),
    sequenceIndex: buildPrivilegeIndex(rows.sequenceGrants || [], r => `${r.sequence_schema}.${r.sequence}`),
  };

  const findings = [
    ...rows.tables.flatMap(t => findingsForTable(t, ctx)),
    ...(rows.views || []).flatMap(findingsForView),
    ...(rows.matviews || []).flatMap(findingsForMatview),
    ...findingsForDefaultPrivileges(rows.defaultPrivileges || []),
    ...(rows.functions || []).flatMap(findingsForFunction),
  ];

  return sortFindings(findings);
}
