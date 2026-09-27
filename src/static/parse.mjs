// Tolerant SQL splitter + statement classifier for `supabase/migrations/*.sql`.
// Not a real SQL parser: it recognizes the statement shapes that matter for
// grants/RLS/policies and tags everything else as `other`. Statements that
// look relevant but can't be interpreted (DO blocks, dynamic SQL, a grant or
// policy in a shape we don't understand) come back as `unparsed` so the
// report can say how much of a migration set was actually understood.
//
// Identifiers: unquoted -> lowercase, "quoted" -> exact. Unqualified names
// resolve against the file's current search_path (default `public`; a
// `set search_path` statement changes it for the rest of that file). Creates
// use the first schema on the path; references carry the whole path so replay
// can resolve them against the tables that exist at that point.

const IDENT_SRC = `"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*`;
const QUALIFIED_RE = new RegExp(`^\\s*(${IDENT_SRC})(?:\\s*\\.\\s*(${IDENT_SRC}))?`);

export const DEFAULT_SEARCH_PATH = ['public'];

function unquoteIdent(raw) {
  const s = raw.trim();
  if (s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1).replace(/""/g, '"');
  return s.toLowerCase();
}

// Parses a possibly schema-qualified identifier at the start of `str`.
// Returns { schema, name, matchLength[, searchPath] } or null.
function parseQualifiedName(str, ctx) {
  const m = QUALIFIED_RE.exec(str);
  if (!m) return null;
  const a = unquoteIdent(m[1]);
  if (m[2] != null) return { schema: a, name: unquoteIdent(m[2]), matchLength: m[0].length };
  const searchPath = ctx?.searchPath?.length ? ctx.searchPath : DEFAULT_SEARCH_PATH;
  const q = { schema: searchPath[0], name: a, matchLength: m[0].length };
  if (searchPath.length > 1) q.searchPath = searchPath;
  return q;
}

// A reference to an existing relation: keeps the search path (if any) so
// replay can resolve it; drops parse bookkeeping.
function ref({ schema, name, searchPath }) {
  return searchPath ? { schema, name, searchPath } : { schema, name };
}

// Splits a comma-separated list, ignoring commas inside quotes and parens.
function splitList(str) {
  const parts = [];
  let depth = 0;
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (inSingle) {
      cur += c;
      if (c === "'" && str[i + 1] !== "'") inSingle = false;
      else if (c === "'") { cur += str[++i]; }
      continue;
    }
    if (inDouble) {
      cur += c;
      if (c === '"' && str[i + 1] !== '"') inDouble = false;
      else if (c === '"') { cur += str[++i]; }
      continue;
    }
    if (c === "'") { inSingle = true; cur += c; continue; }
    if (c === '"') { inDouble = true; cur += c; continue; }
    if (c === '(') { depth++; cur += c; continue; }
    if (c === ')') { depth--; cur += c; continue; }
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map(s => s.trim()).filter(Boolean);
}

function parseRoleList(str) {
  return splitList(str.replace(/\s+with\s+grant\s+option\s*$/i, '').replace(/\s+granted\s+by\s+\S+\s*$/i, ''))
    .map(unquoteIdent);
}

const IDENT_CHAR = /[A-Za-z0-9_$]/;

// Splits raw SQL text into individual statement strings (no trailing `;`,
// no comments). Tracks '...' and E'...' strings, "..." identifiers, $$ /
// $tag$ bodies and comments so `;` inside them doesn't split a statement.
export function splitStatements(input) {
  const sql = input.replace(/^﻿/, '');
  const statements = [];
  let buf = '';
  let i = 0;
  const n = sql.length;
  let state = 'normal';
  let dollarTag = null;

  while (i < n) {
    const c = sql[i];
    const c2 = sql[i + 1];

    if (state === 'normal') {
      if (c === '-' && c2 === '-') { state = 'line_comment'; i += 2; continue; }
      if (c === '/' && c2 === '*') { state = 'block_comment'; i += 2; continue; }
      if (c === "'") {
        const isEscapeString = /[Ee]/.test(sql[i - 1] || '') && !IDENT_CHAR.test(sql[i - 2] || '');
        state = isEscapeString ? 'escape_string' : 'single_quote';
        buf += c; i++; continue;
      }
      if (c === '"') { state = 'double_quote'; buf += c; i++; continue; }
      if (c === '$' && !IDENT_CHAR.test(sql[i - 1] || '')) {
        const m = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(sql.slice(i, i + 64));
        if (m) { dollarTag = m[0]; state = 'dollar'; buf += dollarTag; i += dollarTag.length; continue; }
      }
      if (c === ';') { statements.push(buf); buf = ''; i++; continue; }
      buf += c;
      i++;
      continue;
    }
    if (state === 'line_comment') { if (c === '\n') { state = 'normal'; buf += ' '; } i++; continue; }
    if (state === 'block_comment') { if (c === '*' && c2 === '/') { state = 'normal'; buf += ' '; i += 2; continue; } i++; continue; }
    if (state === 'single_quote') {
      if (c === "'") { if (c2 === "'") { buf += "''"; i += 2; continue; } state = 'normal'; buf += c; i++; continue; }
      buf += c; i++; continue;
    }
    if (state === 'escape_string') {
      if (c === '\\' && i + 1 < n) { buf += c + c2; i += 2; continue; }
      if (c === "'") { if (c2 === "'") { buf += "''"; i += 2; continue; } state = 'normal'; buf += c; i++; continue; }
      buf += c; i++; continue;
    }
    if (state === 'double_quote') {
      if (c === '"') { if (c2 === '"') { buf += '""'; i += 2; continue; } state = 'normal'; buf += c; i++; continue; }
      buf += c; i++; continue;
    }
    if (state === 'dollar') {
      if (sql.startsWith(dollarTag, i)) { buf += dollarTag; i += dollarTag.length; state = 'normal'; dollarTag = null; continue; }
      buf += c; i++; continue;
    }
  }
  if (buf.trim()) statements.push(buf);
  return statements.map(s => s.trim()).filter(Boolean);
}

function extractBalancedParen(text, openIndex) {
  let depth = 0;
  let state = 'normal';
  const start = openIndex + 1;
  for (let i = openIndex; i < text.length; i++) {
    const c = text[i];
    if (state === 'normal') {
      if (c === "'") { state = 'single_quote'; continue; }
      if (c === '"') { state = 'double_quote'; continue; }
      if (c === '(') { depth++; continue; }
      if (c === ')') { depth--; if (depth === 0) return { content: text.slice(start, i), endIndex: i }; continue; }
    } else if (state === 'single_quote') {
      if (c === "'") { if (text[i + 1] === "'") { i++; continue; } state = 'normal'; }
    } else if (state === 'double_quote') {
      if (c === '"') { if (text[i + 1] === '"') { i++; continue; } state = 'normal'; }
    }
  }
  return null;
}

// Finds `keywordRe` in `text`, then the balanced-paren group that follows it
// (skipping whitespace). Returns the inner content, or null if not found.
function parenAfterKeyword(text, keywordRe) {
  const m = keywordRe.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length;
  while (i < text.length && /\s/.test(text[i])) i++;
  if (text[i] !== '(') return null;
  const paren = extractBalancedParen(text, i);
  return paren ? paren.content.trim() : null;
}

// Removes $$ / $tag$ bodies so keyword checks on a function header don't see
// what the body happens to contain.
function stripDollarBodies(text) {
  return text.replace(/\$([A-Za-z_][A-Za-z0-9_]*)?\$[\s\S]*?\$\1\$/g, ' ');
}

function parseSearchPathValue(value) {
  return splitList(value)
    .map(s => s.trim().replace(/^'(.*)'$/, '$1'))
    .flatMap(s => splitList(s))
    .map(s => (s.startsWith('"') ? unquoteIdent(s) : s.trim().toLowerCase()))
    .map(s => (s === 'default' ? 'public' : s))
    .filter(s => s && s !== '$user' && s !== 'pg_catalog' && s !== 'pg_temp');
}

function classifySetSearchPath(raw) {
  const setM = /^set\s+(?:session\s+|local\s+)?search_path\s*(?:=|to)\s*(.*)$/i.exec(raw);
  if (setM) return { type: 'set_search_path', schemas: parseSearchPathValue(setM[1]) };
  const configM = /^select\s+(?:pg_catalog\s*\.\s*)?set_config\s*\(\s*'search_path'\s*,\s*'((?:[^']|'')*)'/i.exec(raw);
  if (configM) return { type: 'set_search_path', schemas: parseSearchPathValue(configM[1].replace(/''/g, "'")) };
  return null;
}

function classifyCreateTable(raw, ctx) {
  const m = /^create\s+(?:(?:global|local)\s+)?(temp\s+|temporary\s+|unlogged\s+)?table\s+(if\s+not\s+exists\s+)?/i.exec(raw);
  if (!m) return null;
  if (m[1] && !/^unlogged/i.test(m[1])) return { type: 'other', raw }; // session-local temp table
  const rest = raw.slice(m[0].length);
  const q = parseQualifiedName(rest, ctx);
  if (!q) return null;
  const stmt = { type: 'create_table', schema: q.schema, name: q.name, ifNotExists: !!m[2] };
  const partM = /^\s*partition\s+of\s+/i.exec(rest.slice(q.matchLength));
  if (partM) {
    const parent = parseQualifiedName(rest.slice(q.matchLength + partM[0].length), ctx);
    if (parent) stmt.partitionOf = ref(parent);
  }
  return stmt;
}

// Views and materialized views aren't analyzed statically, but replay needs to
// know they exist so grants on them aren't reported as targeting an unknown
// relation.
function classifyCreateView(raw, ctx) {
  const m = /^create\s+(?:or\s+replace\s+)?(?:temp\s+|temporary\s+)?(?:recursive\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?/i.exec(raw);
  if (!m) return null;
  const q = parseQualifiedName(raw.slice(m[0].length), ctx);
  if (!q) return null;
  return { type: 'create_view', schema: q.schema, name: q.name, materialized: !!m[1] };
}

function classifyDropView(raw, ctx) {
  const m = /^drop\s+(materialized\s+)?view\s+(if\s+exists\s+)?/i.exec(raw);
  if (!m) return null;
  const rest = raw.slice(m[0].length).replace(/\b(cascade|restrict)\s*$/i, '');
  const names = splitList(rest).map(s => parseQualifiedName(s, ctx)).filter(Boolean);
  if (!names.length) return null;
  return { type: 'drop_view', views: names.map(ref) };
}

function classifyDropTable(raw, ctx) {
  const m = /^drop\s+table\s+(if\s+exists\s+)?/i.exec(raw);
  if (!m) return null;
  const rest = raw.slice(m[0].length).replace(/\b(cascade|restrict)\s*$/i, '');
  const names = splitList(rest).map(s => parseQualifiedName(s, ctx)).filter(Boolean);
  if (!names.length) return null;
  return { type: 'drop_table', ifExists: !!m[1], tables: names.map(ref) };
}

function classifyDropSchema(raw) {
  const m = /^drop\s+schema\s+(if\s+exists\s+)?(.*?)(\s+(cascade|restrict))?$/i.exec(raw);
  if (!m) return null;
  const schemas = splitList(m[2]).map(unquoteIdent);
  if (!schemas.length) return null;
  return { type: 'drop_schema', schemas, cascade: /cascade/i.test(m[4] || '') };
}

// ALTER TABLE [IF EXISTS] [ONLY] name <action>: RLS toggles, RENAME TO, SET
// SCHEMA. Any other action (add column, ...) is irrelevant here -> null.
function classifyAlterTable(raw, ctx) {
  const m = /^alter\s+table\s+(if\s+exists\s+)?(only\s+)?/i.exec(raw);
  if (!m) return null;
  const rest = raw.slice(m[0].length);
  const q = parseQualifiedName(rest, ctx);
  if (!q) return null;
  const tail = rest.slice(q.matchLength).replace(/^\s*\*/, '');
  const target = ref(q);

  if (/\benable\s+row\s+level\s+security\b/i.test(tail)) return { type: 'alter_table_rls', ...target, action: 'enable' };
  if (/\bdisable\s+row\s+level\s+security\b/i.test(tail)) return { type: 'alter_table_rls', ...target, action: 'disable' };
  if (/\bno\s+force\s+row\s+level\s+security\b/i.test(tail)) return { type: 'alter_table_rls', ...target, action: 'no_force' };
  if (/\bforce\s+row\s+level\s+security\b/i.test(tail)) return { type: 'alter_table_rls', ...target, action: 'force' };

  // Deliberately not "rename column ... to ..." — only a bare "rename to".
  const renameM = new RegExp(`^\\s*rename\\s+to\\s+(${IDENT_SRC})`, 'i').exec(tail);
  if (renameM) return { type: 'alter_table_rename', ...target, renameTo: unquoteIdent(renameM[1]) };

  const setSchemaM = new RegExp(`^\\s*set\\s+schema\\s+(${IDENT_SRC})`, 'i').exec(tail);
  if (setSchemaM) return { type: 'alter_table_set_schema', ...target, newSchema: unquoteIdent(setSchemaM[1]) };

  return null;
}

function parsePolicyClauses(text) {
  const permissiveM = /\bas\s+(permissive|restrictive)\b/i.exec(text);
  const permissive = permissiveM ? permissiveM[1].toLowerCase() === 'permissive' : true;

  const cmdM = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(text);
  const cmd = cmdM ? cmdM[1].toUpperCase() : 'ALL';

  const toM = /\bto\b/i.exec(text);
  let roles;
  if (toM) {
    let end = text.length;
    for (const re of [/\busing\s*\(/i, /\bwith\s+check\s*\(/i]) {
      const bm = re.exec(text.slice(toM.index));
      if (bm) end = Math.min(end, toM.index + bm.index);
    }
    roles = parseRoleList(text.slice(toM.index + toM[0].length, end));
    if (!roles.length) roles = ['public'];
  } else {
    roles = ['public'];
  }

  const using = parenAfterKeyword(text, /\busing\b/i);
  const withCheck = parenAfterKeyword(text, /\bwith\s+check\b/i);

  return { permissive, cmd, roles, using, withCheck };
}

// "<policy name> ON <table>" -> { name, table ref, tail } or null.
function parsePolicyTarget(rest, ctx) {
  const nameM = new RegExp(`^(${IDENT_SRC})`).exec(rest);
  if (!nameM) return null;
  const afterName = rest.slice(nameM[0].length);
  const onM = /^\s*on\s+/i.exec(afterName);
  if (!onM) return null;
  const afterOn = afterName.slice(onM[0].length);
  const q = parseQualifiedName(afterOn, ctx);
  if (!q) return null;
  const { schema, name, searchPath } = q;
  const target = searchPath ? { schema, table: name, searchPath } : { schema, table: name };
  return { name: unquoteIdent(nameM[1]), target, tail: afterOn.slice(q.matchLength) };
}

function classifyCreatePolicy(raw, ctx) {
  const m = /^create\s+policy\s+/i.exec(raw);
  if (!m) return null;
  const p = parsePolicyTarget(raw.slice(m[0].length), ctx);
  if (!p) return null;
  return { type: 'create_policy', name: p.name, ...p.target, ...parsePolicyClauses(p.tail) };
}

function classifyAlterPolicy(raw, ctx) {
  const m = /^alter\s+policy\s+/i.exec(raw);
  if (!m) return null;
  const p = parsePolicyTarget(raw.slice(m[0].length), ctx);
  if (!p) return null;
  const tail = p.tail;

  const renameMatch = new RegExp(`\\brename\\s+to\\s+(${IDENT_SRC})`, 'i').exec(tail);
  if (renameMatch) return { type: 'alter_policy', name: p.name, ...p.target, renameTo: unquoteIdent(renameMatch[1]) };

  const result = { type: 'alter_policy', name: p.name, ...p.target };
  if (/\bto\b/i.test(tail)) {
    const clauses = parsePolicyClauses(tail);
    result.roles = clauses.roles;
    if (clauses.using != null) result.using = clauses.using;
    if (clauses.withCheck != null) result.withCheck = clauses.withCheck;
  } else {
    const using = parenAfterKeyword(tail, /\busing\b/i);
    const withCheck = parenAfterKeyword(tail, /\bwith\s+check\b/i);
    if (using != null) result.using = using;
    if (withCheck != null) result.withCheck = withCheck;
  }
  return result;
}

function classifyDropPolicy(raw, ctx) {
  const m = /^drop\s+policy\s+(if\s+exists\s+)?/i.exec(raw);
  if (!m) return null;
  const p = parsePolicyTarget(raw.slice(m[0].length).replace(/\s+(cascade|restrict)\s*$/i, ''), ctx);
  if (!p) return null;
  return { type: 'drop_policy', name: p.name, ...p.target, ifExists: !!m[1] };
}

const PRIV_WORD = `select|insert|update|delete|truncate|references|trigger|maintain|usage|execute|create|connect|temporary|temp|all(?:\\s+privileges)?`;
// A privilege, optionally with a column list: select (a, b)
const PRIV_ITEM = `(?:${PRIV_WORD})(?:\\s*\\([^)]*\\))?`;
const PRIV_LIST_RE = new RegExp(`^(${PRIV_ITEM}(?:\\s*,\\s*${PRIV_ITEM})*)\\s+on\\s+`, 'i');

function parsePrivileges(str) {
  const items = splitList(str);
  return {
    privileges: items.map(p => {
      const w = p.trim().toUpperCase();
      return w.startsWith('ALL') ? 'ALL' : w.split(/[\s(]+/)[0];
    }),
    columnLevel: items.some(p => p.includes('(')),
  };
}

// Targets that are not tables/sequences/functions: schemas, databases, types...
const OTHER_OBJECT_RE = /^(schema|database|type|domain|language|foreign\s+data\s+wrapper|foreign\s+server|tablespace|large\s+object|parameter)\s+/i;

function classifyGrantRevoke(raw, ctx) {
  const m = /^(grant|revoke)\s+/i.exec(raw);
  if (!m) return null;
  const verb = m[1].toUpperCase();
  let rest = raw.slice(m[0].length).replace(/^grant\s+option\s+for\s+/i, '');

  const privM = PRIV_LIST_RE.exec(rest);
  if (!privM) return null;
  const { privileges, columnLevel } = parsePrivileges(privM[1]);
  rest = rest.slice(privM[0].length);

  const sepRe = verb === 'GRANT' ? /\bto\b/i : /\bfrom\b/i;
  const sepM = sepRe.exec(rest);
  if (!sepM) return null;
  const targetRaw = rest.slice(0, sepM.index).trim();
  const roles = parseRoleList(rest.slice(sepM.index + sepM[0].length).replace(/\b(cascade|restrict)\s*$/i, ''));

  let target;
  let allM;
  if ((allM = /^all\s+tables\s+in\s+schema\s+/i.exec(targetRaw))) {
    target = { kind: 'all_tables_in_schema', schemas: splitList(targetRaw.slice(allM[0].length)).map(unquoteIdent) };
  } else if ((allM = /^all\s+sequences\s+in\s+schema\s+/i.exec(targetRaw))) {
    target = { kind: 'all_sequences_in_schema', schemas: splitList(targetRaw.slice(allM[0].length)).map(unquoteIdent) };
  } else if ((allM = /^all\s+(functions|procedures|routines)\s+in\s+schema\s+/i.exec(targetRaw))) {
    target = { kind: 'all_functions_in_schema', schemas: splitList(targetRaw.slice(allM[0].length)).map(unquoteIdent) };
  } else if (/^sequence\s+/i.test(targetRaw)) {
    const names = splitList(targetRaw.replace(/^sequence\s+/i, '')).map(s => parseQualifiedName(s, ctx)).filter(Boolean);
    target = { kind: 'sequence', tables: names.map(ref) };
  } else if (/^(function|procedure|routine)\s+/i.test(targetRaw)) {
    target = { kind: 'function', raw: targetRaw.replace(/^(function|procedure|routine)\s+/i, '').trim() };
  } else if (OTHER_OBJECT_RE.test(targetRaw)) {
    target = { kind: 'other_object', objectType: OTHER_OBJECT_RE.exec(targetRaw)[1].toLowerCase() };
  } else {
    const names = splitList(targetRaw.replace(/^table\s+/i, '').replace(/^only\s+/i, ''))
      .map(s => parseQualifiedName(s, ctx))
      .filter(Boolean);
    if (!names.length) return null;
    target = { kind: 'table', tables: names.map(ref) };
  }

  const stmt = { type: verb === 'GRANT' ? 'grant' : 'revoke', privileges, target, roles };
  if (columnLevel) stmt.columnLevel = true;
  return stmt;
}

function classifyAlterDefaultPrivileges(raw) {
  const m = /^alter\s+default\s+privileges\s+/i.exec(raw);
  if (!m) return null;
  let rest = raw.slice(m[0].length);

  if (/^for\s+(role|user)\s+/i.test(rest)) {
    const inOrAction = /\s+(in\s+schema|grant|revoke)\b/i.exec(rest);
    if (!inOrAction) return null;
    rest = rest.slice(inOrAction.index).trimStart();
  }

  let schemas = ['public'];
  const schemaM = /^in\s+schema\s+/i.exec(rest);
  if (schemaM) {
    const afterSchemaKw = rest.slice(schemaM[0].length);
    const grantSplit = /\b(grant|revoke)\b/i.exec(afterSchemaKw);
    if (!grantSplit) return null;
    schemas = splitList(afterSchemaKw.slice(0, grantSplit.index)).map(unquoteIdent);
    rest = afterSchemaKw.slice(grantSplit.index);
  }

  const gvM = /^(grant|revoke)\s+(grant\s+option\s+for\s+)?/i.exec(rest);
  if (!gvM) return null;
  const action = gvM[1].toLowerCase();
  rest = rest.slice(gvM[0].length);

  const privM = PRIV_LIST_RE.exec(rest);
  if (!privM) return null;
  const { privileges } = parsePrivileges(privM[1]);
  rest = rest.slice(privM[0].length);

  const objM = /^(tables|sequences|functions|routines|types|schemas)\s+/i.exec(rest);
  if (!objM) return null;
  const objectType = objM[1].toLowerCase();
  rest = rest.slice(objM[0].length);

  const sepM = (action === 'grant' ? /^to\s+/i : /^from\s+/i).exec(rest);
  if (!sepM) return null;
  const roles = parseRoleList(rest.slice(sepM[0].length).replace(/\b(cascade|restrict)\s*$/i, ''));

  return { type: 'alter_default_privileges', schemas, action, privileges, objectType, roles };
}

function classifyCreateFunction(raw, ctx) {
  const m = /^create\s+(or\s+replace\s+)?(function|procedure)\s+/i.exec(raw);
  if (!m) return null;
  const q = parseQualifiedName(raw.slice(m[0].length), ctx);
  if (!q) return null;
  const header = stripDollarBodies(raw);
  return {
    type: 'create_function',
    routine: m[2].toLowerCase(),
    schema: q.schema,
    name: q.name,
    securityDefiner: /\bsecurity\s+definer\b/i.test(header),
    searchPathSet: /\bset\s+search_path\b/i.test(header),
    isTrigger: /\breturns\s+(pg_catalog\s*\.\s*)?trigger\b/i.test(header),
  };
}

// ALTER FUNCTION/PROCEDURE/ROUTINE name[(args)] <actions>. Only the actions
// that matter here are reported; anything else (owner to, rename) -> other.
function classifyAlterFunction(raw, ctx) {
  const m = /^alter\s+(function|procedure|routine)\s+/i.exec(raw);
  if (!m) return null;
  const rest = raw.slice(m[0].length);
  const q = parseQualifiedName(rest, ctx);
  if (!q) return null;
  let tail = rest.slice(q.matchLength);
  if (/^\s*\(/.test(tail)) {
    const paren = extractBalancedParen(tail, tail.indexOf('('));
    if (!paren) return null;
    tail = tail.slice(paren.endIndex + 1);
  }
  const stmt = { type: 'alter_function', ...ref(q) };
  if (/\bset\s+search_path\b/i.test(tail)) stmt.searchPathSet = true;
  if (/\breset\s+(search_path|all)\b/i.test(tail)) stmt.searchPathSet = false;
  if (/\bsecurity\s+definer\b/i.test(tail)) stmt.securityDefiner = true;
  if (/\bsecurity\s+invoker\b/i.test(tail)) stmt.securityDefiner = false;
  if (!('searchPathSet' in stmt) && !('securityDefiner' in stmt)) return { type: 'other', raw };
  return stmt;
}

const CLASSIFIERS = [
  classifySetSearchPath,
  classifyCreateTable,
  classifyCreateView,
  classifyDropView,
  classifyDropTable,
  classifyDropSchema,
  classifyAlterTable,
  classifyCreatePolicy,
  classifyAlterPolicy,
  classifyDropPolicy,
  classifyGrantRevoke,
  classifyAlterDefaultPrivileges,
  classifyCreateFunction,
  classifyAlterFunction,
];

// Statements that could change grants/RLS/policies but that no classifier
// could interpret: DO blocks and top-level EXECUTE (dynamic SQL), and grant/
// policy/table/function statements in a shape we don't understand.
const RELEVANT_BUT_UNPARSED_RE = new RegExp(
  [
    '^do\\b',
    '^execute\\b',
    '^(grant|revoke)\\b.*\\bon\\b',
    '^(create|alter|drop)\\s+(or\\s+replace\\s+)?policy\\b',
    '^alter\\s+default\\s+privileges\\b',
    '^create\\s+(or\\s+replace\\s+)?(function|procedure)\\b',
    '^create\\s+(unlogged\\s+)?table\\b',
  ].join('|'),
  'i'
);

// Classifies one already-split statement (no trailing `;`). ctx.searchPath is
// the file's current search_path. Unrecognized statements come back as
// `{ type: 'other' }`, relevant-but-uninterpretable ones as `{ type: 'unparsed' }`.
export function classifyStatement(rawStatement, ctx = {}) {
  const raw = rawStatement.trim().replace(/\s+/g, ' ');
  for (const classify of CLASSIFIERS) {
    const result = classify(raw, ctx);
    if (result) return result.type === 'other' ? { type: 'other', raw: rawStatement.trim() } : result;
  }
  if (RELEVANT_BUT_UNPARSED_RE.test(raw)) return { type: 'unparsed', raw: rawStatement.trim() };
  return { type: 'other', raw: rawStatement.trim() };
}

// Split + classify a whole file's SQL text, in order, tracking `set
// search_path` for the rest of the file.
export function parseMigration(sql) {
  let searchPath = DEFAULT_SEARCH_PATH;
  return splitStatements(sql).map(text => {
    const stmt = classifyStatement(text, { searchPath });
    if (stmt.type === 'set_search_path') searchPath = stmt.schemas.length ? stmt.schemas : DEFAULT_SEARCH_PATH;
    return stmt;
  });
}
