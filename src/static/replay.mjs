// Replays classified statements (see parse.mjs) in file order to build the
// effective per-table state a migration set produces: does the table exist,
// is RLS on, what policies apply, and who has been granted what.
//
// Files are replayed in filename order using plain string comparison (not a
// locale-aware sort), which matches the Supabase CLI for its
// `<timestamp>_<name>.sql` naming.
//
// A statement that targets a table replay has never seen (created in the
// dashboard, in a DO block, or by a statement we couldn't parse) is not
// applied and is recorded as a warning instead.

import { parseMigration } from './parse.mjs';

const ALL_TABLE_PRIVS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

function tableKey(schema, name) {
  return `${schema}.${name}`;
}

// Schemas whose tables the Supabase platform creates (storage.objects,
// auth.users, ...). Migrations routinely add policies to them without creating
// them, so that is not worth a warning.
const PLATFORM_SCHEMAS = new Set([
  'auth', 'storage', 'realtime', 'supabase_functions', 'supabase_migrations', 'vault',
  'extensions', 'graphql', 'graphql_public', 'net', 'cron', 'pgsodium', 'pgbouncer',
]);

export function compareFileNames(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function ensureGrantSet(grants, role) {
  if (!grants.has(role)) grants.set(role, new Set());
  return grants.get(role);
}

function expandPrivileges(privileges) {
  return privileges.includes('ALL') ? [...ALL_TABLE_PRIVS] : privileges;
}

function newTable(schema, name) {
  return {
    schema,
    name,
    rlsEnabled: false,
    rlsForced: false,
    partitionOf: null,
    policies: new Map(),
    grants: new Map(), // role -> Set<privilege>
    // Roles the migrations explicitly revoked something from on this table.
    // The static scan can't see platform default grants, but an explicit
    // revoke tells us the author already stripped them.
    revokedFrom: new Set(),
  };
}

function applyGrantToTable(table, verb, privileges, roles) {
  const privs = expandPrivileges(privileges);
  for (const role of roles) {
    const set = ensureGrantSet(table.grants, role);
    if (verb === 'grant') {
      privs.forEach(p => set.add(p));
    } else {
      privs.forEach(p => set.delete(p));
      table.revokedFrom.add(role);
    }
  }
}

function applyDefaultPrivileges(table, defaultPrivileges) {
  for (const rule of defaultPrivileges) {
    if (rule.objectType !== 'tables') continue;
    if (!rule.schemas.includes(table.schema)) continue;
    applyGrantToTable(table, rule.action, rule.privileges, rule.roles);
  }
}

class Replay {
  constructor() {
    this.tables = new Map();
    this.views = new Set(); // "schema.name" of views/matviews: known, not analyzed
    this.functions = new Map();
    this.defaultPrivileges = [];
    this.warnings = [];
    this.unparsedByFile = {};
    this.file = null;
    // For the study's "lower bound" check: did we ever see an actual GRANT
    // statement (however it was interpreted), or the word "grant" inside a
    // statement we couldn't parse (a DO block, dynamic SQL, ...)?
    this.sawGrantStatement = false;
    this.unparsedContainsGrantKeyword = false;
  }

  // An unqualified reference resolves to the first schema on its search path
  // that has a table of that name, like Postgres does.
  resolve({ schema, name, searchPath }) {
    if (searchPath) {
      for (const s of searchPath) {
        const key = tableKey(s, name);
        if (this.tables.has(key) || this.views.has(key)) return key;
      }
    }
    return tableKey(schema, name);
  }

  tableFor(ref, stmtType) {
    const key = this.resolve(ref);
    const table = this.tables.get(key);
    const platform = PLATFORM_SCHEMAS.has(key.slice(0, -(ref.name.length + 1)));
    if (!table && !this.views.has(key) && !platform) this.warnings.push({ file: this.file, statement: stmtType, target: key, message: `${stmtType} on ${key}, which no earlier migration creates — not applied` });
    return table;
  }

  moveTable(oldKey, table) {
    this.tables.delete(oldKey);
    for (const policy of table.policies.values()) {
      policy.schema = table.schema;
      policy.table = table.name;
    }
    this.tables.set(tableKey(table.schema, table.name), table);
  }

  apply(stmt) {
    switch (stmt.type) {
      case 'unparsed':
        this.unparsedByFile[this.file] = (this.unparsedByFile[this.file] || 0) + 1;
        if (/grant/i.test(stmt.raw)) this.unparsedContainsGrantKeyword = true;
        return;
      case 'create_table': {
        const key = tableKey(stmt.schema, stmt.name);
        if (this.tables.has(key)) return; // already exists: never reset (covers plain re-create too)
        const table = newTable(stmt.schema, stmt.name);
        if (stmt.partitionOf) table.partitionOf = this.resolve(stmt.partitionOf);
        applyDefaultPrivileges(table, this.defaultPrivileges);
        this.tables.set(key, table);
        return;
      }
      case 'drop_table': {
        for (const t of stmt.tables) this.tables.delete(this.resolve(t));
        return;
      }
      case 'create_view':
        this.views.add(tableKey(stmt.schema, stmt.name));
        return;
      case 'drop_view':
        for (const v of stmt.views) this.views.delete(this.resolve(v));
        return;
      case 'drop_schema': {
        // Without CASCADE, Postgres refuses to drop a non-empty schema.
        if (!stmt.cascade) return;
        for (const [key, t] of [...this.tables]) if (stmt.schemas.includes(t.schema)) this.tables.delete(key);
        for (const key of [...this.views]) if (stmt.schemas.includes(key.split('.')[0])) this.views.delete(key);
        for (const [key, f] of [...this.functions]) if (stmt.schemas.includes(f.schema)) this.functions.delete(key);
        return;
      }
      case 'alter_table_rls': {
        const table = this.tableFor(stmt, stmt.type);
        if (!table) return;
        if (stmt.action === 'enable') table.rlsEnabled = true;
        else if (stmt.action === 'disable') table.rlsEnabled = false;
        else if (stmt.action === 'force') table.rlsForced = true;
        else if (stmt.action === 'no_force') table.rlsForced = false;
        return;
      }
      case 'alter_table_rename': {
        const oldKey = this.resolve(stmt);
        const table = this.tableFor(stmt, stmt.type);
        if (!table) return;
        table.name = stmt.renameTo;
        this.moveTable(oldKey, table);
        return;
      }
      case 'alter_table_set_schema': {
        const oldKey = this.resolve(stmt);
        const table = this.tableFor(stmt, stmt.type);
        if (!table) return;
        table.schema = stmt.newSchema;
        this.moveTable(oldKey, table);
        return;
      }
      case 'create_policy': {
        const table = this.tableFor({ ...stmt, name: stmt.table }, stmt.type);
        if (!table) return;
        table.policies.set(stmt.name, {
          name: stmt.name,
          schema: table.schema,
          table: table.name,
          permissive: stmt.permissive,
          roles: stmt.roles,
          cmd: stmt.cmd,
          using: stmt.using,
          withCheck: stmt.withCheck,
        });
        return;
      }
      case 'alter_policy': {
        const table = this.tableFor({ ...stmt, name: stmt.table }, stmt.type);
        if (!table) return;
        const existing = table.policies.get(stmt.name);
        if (!existing) return;
        if (stmt.renameTo) {
          table.policies.delete(stmt.name);
          table.policies.set(stmt.renameTo, { ...existing, name: stmt.renameTo });
          return;
        }
        if (stmt.roles) existing.roles = stmt.roles;
        if (stmt.using !== undefined) existing.using = stmt.using;
        if (stmt.withCheck !== undefined) existing.withCheck = stmt.withCheck;
        return;
      }
      case 'drop_policy': {
        const table = this.tableFor({ ...stmt, name: stmt.table }, stmt.type);
        if (table) table.policies.delete(stmt.name);
        return;
      }
      case 'grant':
      case 'revoke': {
        if (stmt.type === 'grant') this.sawGrantStatement = true;
        // A column-level revoke doesn't remove a table-level grant.
        if (stmt.type === 'revoke' && stmt.columnLevel) return;
        if (stmt.target.kind === 'table') {
          for (const t of stmt.target.tables) {
            const table = this.tableFor(t, stmt.type);
            if (table) applyGrantToTable(table, stmt.type, stmt.privileges, stmt.roles);
          }
        } else if (stmt.target.kind === 'all_tables_in_schema') {
          // Snapshot semantics: only tables that exist right now.
          for (const table of this.tables.values()) {
            if (stmt.target.schemas.includes(table.schema)) applyGrantToTable(table, stmt.type, stmt.privileges, stmt.roles);
          }
        }
        return;
      }
      case 'alter_default_privileges':
        this.defaultPrivileges.push(stmt);
        return;
      case 'create_function':
        this.functions.set(tableKey(stmt.schema, stmt.name), {
          schema: stmt.schema,
          name: stmt.name,
          routine: stmt.routine,
          securityDefiner: stmt.securityDefiner,
          searchPathSet: stmt.searchPathSet,
          isTrigger: stmt.isTrigger,
        });
        return;
      case 'alter_function': {
        const fn = this.functions.get(tableKey(stmt.schema, stmt.name));
        if (!fn) {
          this.warnings.push({ file: this.file, statement: stmt.type, target: tableKey(stmt.schema, stmt.name), message: `alter_function on ${tableKey(stmt.schema, stmt.name)}, which no earlier migration creates — not applied` });
          return;
        }
        if ('searchPathSet' in stmt) fn.searchPathSet = stmt.searchPathSet;
        if ('securityDefiner' in stmt) fn.securityDefiner = stmt.securityDefiner;
        return;
      }
      default:
        return;
    }
  }
}

// files: [{ name, sql }]. Caller need not pre-sort; replay sorts by name.
// Returns { tables, functions, warnings, unparsed: { total, byFile }, sawGrantStatement, unparsedContainsGrantKeyword }.
export function replayEffectiveState(files) {
  const sorted = [...files].sort((a, b) => compareFileNames(a.name, b.name));
  const replay = new Replay();
  for (const file of sorted) {
    replay.file = file.name;
    for (const stmt of parseMigration(file.sql)) replay.apply(stmt);
  }
  const byFile = replay.unparsedByFile;
  return {
    tables: replay.tables,
    functions: replay.functions,
    warnings: replay.warnings,
    unparsed: { total: Object.values(byFile).reduce((a, b) => a + b, 0), byFile },
    sawGrantStatement: replay.sawGrantStatement,
    unparsedContainsGrantKeyword: replay.unparsedContainsGrantKeyword,
  };
}

// Back-compat convenience: just the tables map (see replayEffectiveState).
export function replayFiles(files) {
  return replayEffectiveState(files).tables;
}

// Plain-object view of the effective state, convenient for tests/reports.
export function effectiveStateToArray(tables) {
  return [...tables.values()]
    .sort((a, b) => compareFileNames(tableKey(a.schema, a.name), tableKey(b.schema, b.name)))
    .map(t => ({
      schema: t.schema,
      name: t.name,
      rlsEnabled: t.rlsEnabled,
      rlsForced: t.rlsForced,
      partitionOf: t.partitionOf,
      policies: [...t.policies.values()],
      grants: Object.fromEntries([...t.grants.entries()].map(([role, set]) => [role, [...set].sort()])),
      revokedFrom: [...t.revokedFrom].sort(),
    }));
}

// Plain-object view of collected `create function` statements.
export function functionsToArray(functions) {
  return [...functions.values()].sort((a, b) => compareFileNames(tableKey(a.schema, a.name), tableKey(b.schema, b.name)));
}
