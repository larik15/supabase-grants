import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { replayEffectiveState, effectiveStateToArray, functionsToArray } from './static/replay.mjs';
import { analyzeEffectiveState } from './static/analyze.mjs';
import { toReportData } from './report/json.mjs';

// Reads every *.sql file directly inside `dir` (flat, like supabase/migrations).
export function loadSqlFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter(e => e.isFile() && e.name.toLowerCase().endsWith('.sql'))
    .map(e => ({ name: e.name, sql: readFileSync(path.join(dir, e.name), 'utf8') }));
}

// Runs the full static scan: parse + replay + analyze, returns report data
// (see report/json.mjs) ready for toMarkdown()/toJson().
export function scan(dir, opts = {}) {
  const files = loadSqlFiles(dir);
  const { tables, functions, warnings, unparsed, sawGrantStatement, unparsedContainsGrantKeyword } = replayEffectiveState(files);
  const tablesArr = effectiveStateToArray(tables);
  const functionsArr = functionsToArray(functions);
  const findings = analyzeEffectiveState({ tables: tablesArr, functions: functionsArr }, opts);
  return toReportData({
    source: dir,
    tables: tablesArr,
    functions: functionsArr,
    findings,
    warnings,
    unparsed,
    sawGrantStatement,
    unparsedContainsGrantKeyword,
  });
}
