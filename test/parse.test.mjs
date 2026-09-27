import test from 'node:test';
import assert from 'node:assert/strict';
import { splitStatements, classifyStatement, parseMigration } from '../src/static/parse.mjs';

test('splitStatements: basic multi-statement split', () => {
  const stmts = splitStatements('select 1; select 2;');
  assert.deepEqual(stmts, ['select 1', 'select 2']);
});

test('splitStatements: trailing statement without final semicolon is kept', () => {
  const stmts = splitStatements('select 1;\nselect 2');
  assert.deepEqual(stmts, ['select 1', 'select 2']);
});

test('splitStatements: semicolon inside a single-quoted string does not split', () => {
  const stmts = splitStatements(`insert into t (a) values ('a;b'); select 1;`);
  assert.equal(stmts.length, 2);
  assert.match(stmts[0], /'a;b'/);
});

test("splitStatements: escaped '' quote inside a string is not a terminator", () => {
  const stmts = splitStatements(`insert into t (a) values ('it''s; fine'); select 1;`);
  assert.equal(stmts.length, 2);
});

test('splitStatements: semicolon inside a double-quoted identifier does not split', () => {
  const stmts = splitStatements(`select "weird;name" from t; select 2;`);
  assert.equal(stmts.length, 2);
});

test('splitStatements: line comment hides a semicolon', () => {
  const stmts = splitStatements('select 1; -- comment with ; inside\nselect 2;');
  assert.equal(stmts.length, 2);
});

test('splitStatements: block comment hides a semicolon', () => {
  const stmts = splitStatements('select 1; /* comment ; with ; semicolons */ select 2;');
  assert.equal(stmts.length, 2);
});

test('splitStatements: dollar-quoted function body with semicolons is one statement', () => {
  const sql = `create function f() returns int language sql as $$ select 1; select 2; $$; select 3;`;
  const stmts = splitStatements(sql);
  assert.equal(stmts.length, 2);
  assert.match(stmts[0], /select 1; select 2;/);
});

test('splitStatements: named dollar tag ($body$) is respected', () => {
  const sql = `create function f() returns int language sql as $body$ select 1; $body$; select 2;`;
  const stmts = splitStatements(sql);
  assert.equal(stmts.length, 2);
});

test('splitStatements: empty statements and whitespace-only input are dropped', () => {
  const stmts = splitStatements('  ;;  select 1;  ;  ');
  assert.deepEqual(stmts, ['select 1']);
});

test('classifyStatement: create table with default schema', () => {
  const stmt = classifyStatement('create table orders (id uuid)');
  assert.deepEqual(stmt, { type: 'create_table', schema: 'public', name: 'orders', ifNotExists: false });
});

test('classifyStatement: create table if not exists, schema-qualified', () => {
  const stmt = classifyStatement('create table if not exists app.orders (id uuid)');
  assert.deepEqual(stmt, { type: 'create_table', schema: 'app', name: 'orders', ifNotExists: true });
});

test('classifyStatement: create table with quoted, case-sensitive identifiers', () => {
  const stmt = classifyStatement('create table "Public"."Orders" ("Id" uuid)');
  assert.equal(stmt.type, 'create_table');
  assert.equal(stmt.schema, 'Public');
  assert.equal(stmt.name, 'Orders');
});

test('classifyStatement: drop table', () => {
  const stmt = classifyStatement('drop table if exists public.orders');
  assert.deepEqual(stmt, { type: 'drop_table', ifExists: true, tables: [{ schema: 'public', name: 'orders' }] });
});

test('classifyStatement: alter table enable/disable row level security', () => {
  assert.equal(classifyStatement('alter table public.orders enable row level security').action, 'enable');
  assert.equal(classifyStatement('alter table public.orders disable row level security').action, 'disable');
});

test('classifyStatement: alter table rename to', () => {
  const stmt = classifyStatement('alter table public.orders rename to purchase_orders');
  assert.deepEqual(stmt, { type: 'alter_table_rename', schema: 'public', name: 'orders', renameTo: 'purchase_orders' });
});

test('classifyStatement: alter table rename COLUMN is not mistaken for a table rename', () => {
  const stmt = classifyStatement('alter table public.orders rename column total to grand_total');
  assert.notEqual(stmt.type, 'alter_table_rename');
});

test('classifyStatement: create table ... as select is classified as create_table', () => {
  const stmt = classifyStatement('create table public.new_tbl as select * from public.old_tbl');
  assert.equal(stmt.type, 'create_table');
  assert.equal(stmt.name, 'new_tbl');
});

test('classifyStatement: create table ... (like ...) is classified as create_table', () => {
  const stmt = classifyStatement('create table public.new_tbl (like public.old_tbl including all)');
  assert.equal(stmt.type, 'create_table');
  assert.equal(stmt.name, 'new_tbl');
});

test('classifyStatement: create policy with TO, USING, WITH CHECK', () => {
  const stmt = classifyStatement(
    `create policy "orders_own" on public.orders for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id)`
  );
  assert.equal(stmt.type, 'create_policy');
  assert.equal(stmt.name, 'orders_own');
  assert.equal(stmt.table, 'orders');
  assert.equal(stmt.cmd, 'UPDATE');
  assert.deepEqual(stmt.roles, ['authenticated']);
  assert.equal(stmt.permissive, true);
  assert.equal(stmt.using, 'auth.uid() = user_id');
  assert.equal(stmt.withCheck, 'auth.uid() = user_id');
});

test('classifyStatement: create policy with no TO clause defaults roles to public', () => {
  const stmt = classifyStatement(`create policy p on public.orders for select using (true)`);
  assert.deepEqual(stmt.roles, ['public']);
});

test('classifyStatement: create policy AS RESTRICTIVE is flagged non-permissive', () => {
  const stmt = classifyStatement(`create policy p on public.orders as restrictive for select using (true)`);
  assert.equal(stmt.permissive, false);
});

test('classifyStatement: using expression with nested parens is balanced correctly', () => {
  const stmt = classifyStatement(
    `create policy p on public.orders for select to authenticated using (exists (select 1 from teams where teams.id = orders.team_id))`
  );
  assert.equal(stmt.using, 'exists (select 1 from teams where teams.id = orders.team_id)');
});

test('classifyStatement: drop policy', () => {
  const stmt = classifyStatement('drop policy if exists "p" on public.orders');
  assert.deepEqual(stmt, { type: 'drop_policy', name: 'p', schema: 'public', table: 'orders', ifExists: true });
});

test('classifyStatement: alter policy rename to', () => {
  const stmt = classifyStatement('alter policy old_name on public.orders rename to new_name');
  assert.deepEqual(stmt, { type: 'alter_policy', name: 'old_name', schema: 'public', table: 'orders', renameTo: 'new_name' });
});

test('classifyStatement: grant on table to multiple roles', () => {
  const stmt = classifyStatement('grant select, insert on public.orders to anon, authenticated');
  assert.equal(stmt.type, 'grant');
  assert.deepEqual(stmt.privileges, ['SELECT', 'INSERT']);
  assert.deepEqual(stmt.target, { kind: 'table', tables: [{ schema: 'public', name: 'orders' }] });
  assert.deepEqual(stmt.roles, ['anon', 'authenticated']);
});

test('classifyStatement: grant all privileges expands to ALL marker', () => {
  const stmt = classifyStatement('grant all privileges on public.orders to service_role');
  assert.deepEqual(stmt.privileges, ['ALL']);
});

test('classifyStatement: grant on all tables in schema', () => {
  const stmt = classifyStatement('grant select on all tables in schema public to authenticated');
  assert.deepEqual(stmt.target, { kind: 'all_tables_in_schema', schemas: ['public'] });
});

test('classifyStatement: revoke from role', () => {
  const stmt = classifyStatement('revoke delete on public.orders from anon');
  assert.equal(stmt.type, 'revoke');
  assert.deepEqual(stmt.roles, ['anon']);
});

test('classifyStatement: alter default privileges', () => {
  const stmt = classifyStatement(
    'alter default privileges in schema public grant select on tables to authenticated'
  );
  assert.deepEqual(stmt, {
    type: 'alter_default_privileges',
    schemas: ['public'],
    action: 'grant',
    privileges: ['SELECT'],
    objectType: 'tables',
    roles: ['authenticated'],
  });
});

test('classifyStatement: create function detects security definer and search_path', () => {
  const stmt = classifyStatement(
    `create function public.f() returns int language plpgsql security definer set search_path = public as $$ begin return 1; end; $$`
  );
  assert.equal(stmt.type, 'create_function');
  assert.equal(stmt.securityDefiner, true);
  assert.equal(stmt.searchPathSet, true);
});

test('classifyStatement: unrecognized statement falls back to other', () => {
  const stmt = classifyStatement('comment on table public.orders is \'hello\'');
  assert.equal(stmt.type, 'other');
});

test('parseMigration: split + classify a whole file', () => {
  const sql = `create table public.t (id uuid);\ngrant select on public.t to anon;`;
  const stmts = parseMigration(sql);
  assert.equal(stmts.length, 2);
  assert.equal(stmts[0].type, 'create_table');
  assert.equal(stmts[1].type, 'grant');
});
