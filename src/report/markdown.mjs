const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

function fmtGrants(grants, role) {
  const privs = grants[role];
  return privs && privs.length ? privs.map(p => p.toLowerCase()).join(', ') : '—';
}

function findingLines(f) {
  const where = f.table ? f.table : f.function;
  const lines = [`- **[${SEVERITY_LABEL[f.severity]}] ${f.kind}** (${where}) — ${f.message}`];
  if (f.fix) lines.push(`  - Fix: \`${f.fix}\``);
  return lines;
}

// report: the object from report/json.mjs's toReportData().
export function toMarkdown(report) {
  const { source, generatedAt, summary, tables, findings } = report;
  const lines = [];

  lines.push('# Supabase Grants — static scan');
  lines.push('');
  lines.push(`Source: \`${source}\`  ·  Generated: ${generatedAt}`);
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|---|---|');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    lines.push(`| ${SEVERITY_LABEL[sev]} | ${summary[sev]} |`);
  }
  lines.push('');

  lines.push('## Findings');
  lines.push('');
  if (findings.length === 0) {
    lines.push('No findings.');
  } else {
    const byTable = new Map();
    const functionFindings = [];
    for (const f of findings) {
      if (f.table) {
        if (!byTable.has(f.table)) byTable.set(f.table, []);
        byTable.get(f.table).push(f);
      } else {
        functionFindings.push(f);
      }
    }
    for (const [table, tableFindings] of byTable) {
      lines.push(`### ${table}`);
      lines.push('');
      for (const f of tableFindings) lines.push(...findingLines(f));
      lines.push('');
    }
    if (functionFindings.length) {
      lines.push('### Functions');
      lines.push('');
      for (const f of functionFindings) lines.push(...findingLines(f));
      lines.push('');
    }
  }

  lines.push('## Effective state');
  lines.push('');
  lines.push('| Table | RLS | Policies | PUBLIC | anon | authenticated | service_role |');
  lines.push('|---|---|---|---|---|---|---|');
  for (const t of tables) {
    lines.push(
      `| ${t.schema}.${t.name} | ${t.rlsEnabled ? 'on' : 'off'} | ${t.policies.length} | ${fmtGrants(t.grants, 'public')} | ${fmtGrants(t.grants, 'anon')} | ${fmtGrants(t.grants, 'authenticated')} | ${fmtGrants(t.grants, 'service_role')} |`
    );
  }
  lines.push('');

  const unparsed = report.unparsed_statements || { total: 0, byFile: {} };
  const warnings = report.warnings || [];
  lines.push('## Parser coverage');
  lines.push('');
  lines.push(
    `- Statements that could affect grants/RLS but couldn't be interpreted (DO blocks, dynamic SQL, unusual syntax): **${unparsed.total}**`
  );
  for (const [file, count] of Object.entries(unparsed.byFile)) lines.push(`  - \`${file}\`: ${count}`);
  lines.push(`- Statements targeting a table no earlier migration creates (not applied): **${warnings.length}**`);
  for (const w of warnings) lines.push(`  - \`${w.file}\`: ${w.statement} on \`${w.target}\``);
  if (report.ignored_findings) lines.push(`- Findings suppressed with --ignore: **${report.ignored_findings}**`);
  lines.push('');

  return lines.join('\n');
}
