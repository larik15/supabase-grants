import { summarizeFindings } from '../shared/findings.mjs';

export const SCHEMA_VERSION = 1;

// Builds the plain-object report shape shared by --json output and the study
// per-repo files. Callers JSON.stringify(...) it themselves.
export function toReportData({
  source,
  tables,
  functions = [],
  findings,
  warnings = [],
  unparsed = { total: 0, byFile: {} },
  ignored = [],
  sawGrantStatement = false,
  unparsedContainsGrantKeyword = false,
}) {
  return {
    schema_version: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    source,
    summary: summarizeFindings(findings),
    unparsed_statements: unparsed,
    warnings,
    ignored_findings: ignored.length,
    // For the study's "lower bound" number: did the migrations contain an
    // actual GRANT statement anywhere, or the word "grant" inside a
    // statement we couldn't parse?
    saw_grant_statement: sawGrantStatement,
    unparsed_contains_grant_keyword: unparsedContainsGrantKeyword,
    tables,
    functions,
    findings,
  };
}

export function toJson(report, { pretty = true } = {}) {
  return JSON.stringify(report, null, pretty ? 2 : undefined);
}
