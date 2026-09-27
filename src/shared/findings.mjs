// Ordering/summary/exit-code/ignore helpers shared by static and live analyze.

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const FAIL_ON_VALUES = [...Object.keys(SEVERITY_ORDER), 'none'];

export const EXIT = { CLEAN: 0, HIGH: 1, CRITICAL: 2, TOOL_ERROR: 3 };

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.table || '').localeCompare(b.table || '')
  );
}

export function summarizeFindings(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  return summary;
}

// 2 if any critical finding, 1 if any finding at or above `failOn` (default
// high), 0 otherwise. `failOn: 'none'` always returns 0. Tool errors (3) are
// decided by the CLI, not here.
export function exitCodeForFindings(findings, failOn = 'high') {
  if (failOn === 'none') return EXIT.CLEAN;
  const threshold = SEVERITY_ORDER[failOn];
  if (threshold === undefined) throw new Error(`unknown --fail-on value "${failOn}" (use one of ${FAIL_ON_VALUES.join(', ')})`);
  if (findings.some(f => f.severity === 'critical')) return EXIT.CRITICAL;
  return findings.some(f => SEVERITY_ORDER[f.severity] <= threshold) ? EXIT.HIGH : EXIT.CLEAN;
}

// "schema.table:kind" -> { target, kind }. The target also matches a function
// finding by its name with or without the argument list.
export function parseIgnore(spec) {
  const m = /^([^:\s]+\.[^:\s]+):([a-z_]+)$/.exec(spec || '');
  if (!m) throw new Error(`--ignore expects <schema.table>:<kind>, got "${spec}"`);
  return { target: m[1], kind: m[2] };
}

function findingTargets(f) {
  const targets = [];
  if (f.table) targets.push(f.table);
  if (f.function) targets.push(f.function, f.function.replace(/\(.*\)$/, ''));
  return targets;
}

export function applyIgnores(findings, ignores) {
  if (!ignores.length) return { kept: findings, ignored: [] };
  const kept = [];
  const ignored = [];
  for (const f of findings) {
    const hit = ignores.some(ig => ig.kind === f.kind && findingTargets(f).includes(ig.target));
    (hit ? ignored : kept).push(f);
  }
  return { kept, ignored };
}
