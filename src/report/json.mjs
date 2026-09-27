import { summarizeFindings } from '../shared/findings.mjs';

export const SCHEMA_VERSION = 1;

// Builds the plain-object report shape shared by --json output and the study
// per-repo files. Callers JSON.stringify(...) it themselves.
export function toReportData({ source, tables, functions = [], findings, warnings = [], unparsed = { total: 0, byFile: {} }, ignored = [] }) {
  return {
    schema_version: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    source,
    summary: summarizeFindings(findings),
    unparsed_statements: unparsed,
    warnings,
    ignored_findings: ignored.length,
    tables,
    functions,
    findings,
  };
}

export function toJson(report, { pretty = true } = {}) {
  return JSON.stringify(report, null, pretty ? 2 : undefined);
}
