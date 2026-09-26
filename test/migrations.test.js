// Tests for `supabase-security migrations`. Run: node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { lintMigrations, buildFixSql, lex, splitStatements, signatureTypes } from "../scripts/migrations.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures", "migrations");
const CLI = join(HERE, "..", "scripts", "cli.js");

function lintDir(name, opts) {
  const dir = join(FIX, name);
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()
    .map((f) => ({ path: `${name}/${f}`, sql: readFileSync(join(dir, f), "utf8") }));
  return lintMigrations(files, opts);
}
const lintSql = (sql, opts) => lintMigrations([{ path: "m.sql", sql }], opts);
const has = (r, check, target) => r.findings.some((f) => f.check === check && (!target || f.target === target));
const find = (r, check, target) => r.findings.find((f) => f.check === check && (!target || f.target === target));

// ---- positives -------------------------------------------------------------

test("table without any grant is unreachable after Oct 30, fix mirrors RLS policies", () => {
  const r = lintDir("basic");
  const f = find(r, "unreachable_after_oct30", "public.orders");
  assert.ok(f, "orders should be flagged");
  assert.equal(f.severity, "high");
  assert.match(f.fix_sql, /grant select, insert on table public\.orders to authenticated;/);
  assert.match(f.fix_sql, /to service_role;/);
  assert.doesNotMatch(f.fix_sql, /to anon/, "no anon policy → no anon grant");
  assert.doesNotMatch(f.fix_sql, /sequence/, "identity columns need no sequence grant");
});

test("grant to anon without RLS is CRITICAL and the fix enables RLS first", () => {
  const r = lintDir("basic");
  const f = find(r, "grant_without_rls", "public.leads");
  assert.ok(f);
  assert.equal(f.severity, "critical");
  assert.match(f.fix_sql.split("\n")[0], /^alter table public\.leads enable row level security;$/);
});

test("serial sequence not granted to roles that can INSERT", () => {
  const r = lintDir("basic");
  const f = find(r, "sequence_not_granted", "public.comments");
  assert.ok(f);
  assert.match(f.fix_sql, /grant usage, select on sequence public\.comments_id_seq to authenticated, service_role;/);
});

test("SECURITY DEFINER executable by anon is HIGH; trigger functions are skipped", () => {
  const r = lintDir("basic");
  assert.equal(find(r, "security_definer_anon", "public.get_all_emails").severity, "high");
  assert.ok(!r.findings.some((f) => f.target === "public.handle_new_user"), "returns trigger → not an RPC");
});

test("views: definer view granted → HIGH; security_invoker view granted → clean", () => {
  const r = lintDir("basic");
  assert.ok(has(r, "view_bypasses_rls", "public.order_totals"));
  assert.ok(!r.findings.some((f) => f.target === "public.safe_profiles"));
  assert.equal(find(r, "unreachable_after_oct30", "public.leaderboard").severity, "medium");
});

test("fully granted table with RLS + policies produces no finding", () => {
  const r = lintDir("basic");
  assert.ok(!r.findings.some((f) => f.target === "public.profiles"));
});

test("lazy fixes: blanket GRANT and ALTER DEFAULT PRIVILEGES to anon are HIGH", () => {
  const r = lintDir("lazy");
  const bulk = find(r, "lazy_bulk_grant", "ALL TABLES IN SCHEMA public");
  assert.equal(bulk.severity, "high");
  assert.match(bulk.fix_sql, /revoke all on all tables in schema public from anon, authenticated;/);
  assert.match(bulk.fix_sql, /grant select on table public\.posts to anon;/);
  assert.ok(!/public\.secrets to anon/.test(bulk.fix_sql), "no policy → no re-grant");
  assert.equal(find(r, "default_privileges_regrant").severity, "high");
  // the blanket grant exposed a table without RLS
  assert.ok(has(r, "grant_without_rls", "public.notes"));
  assert.match(find(r, "grant_without_rls", "public.notes").message, /GRANT \.\.\. ON ALL TABLES/);
});

test("bulk grant to authenticated only is MEDIUM", () => {
  const r = lintSql(`create table t (id int); alter table t enable row level security;
    grant select on all tables in schema public to authenticated;`);
  assert.equal(find(r, "lazy_bulk_grant").severity, "medium");
});

test("default privileges without IN SCHEMA are revoked globally (per-schema revoke can't undo them)", () => {
  const r = lintSql(`alter default privileges grant all on tables to anon;`);
  const f = find(r, "default_privileges_regrant");
  assert.match(f.fix_sql, /^alter default privileges revoke select, insert, update, delete on tables from anon;/);
});

test("objects created after ALTER DEFAULT PRIVILEGES GRANT are reachable (and critical without RLS)", () => {
  const r = lintSql(`alter default privileges in schema public grant select on tables to anon;
    create table later (id int);`);
  assert.ok(!has(r, "unreachable_after_oct30", "public.later"));
  assert.ok(has(r, "grant_without_rls", "public.later"));
});

test("GRANT ... TO PUBLIC counts as anon", () => {
  const r = lintSql(`create table t (id int); grant select on t to public;`);
  assert.ok(has(r, "grant_without_rls", "public.t"));
});

// ---- negatives / parser robustness ------------------------------------------

test("fully Oct-30-ready migrations produce zero findings (and exit 0)", () => {
  const r = lintDir("clean");
  assert.deepEqual(r.findings, []);
  const p = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "clean"), "--no-color"], { encoding: "utf8" });
  assert.equal(p.status, 0, p.stdout + p.stderr);
  assert.match(p.stdout, /Ready for Oct 30/);
});

test("comments, strings, dollar bodies, DO blocks and BEGIN ATOMIC never create ghost objects", () => {
  const r = lintDir("tricky");
  assert.deepEqual(r.findings.map((f) => `${f.check} ${f.target}`), []);
  assert.equal(r.counts.tables, 3); // Customers, invoices, tmp_new
  assert.equal(r.counts.functions, 2);
});

test("quoted mixed-case identifiers keep their case in fix SQL", () => {
  const r = lintSql(`CREATE TABLE "public"."Order Items" ("Id" int); ALTER TABLE "public"."Order Items" ENABLE ROW LEVEL SECURITY;`);
  const f = find(r, "unreachable_after_oct30");
  assert.equal(f.target, `public."Order Items"`);
  assert.match(f.fix_sql, /on table public\."Order Items" to service_role/);
});

test("uppercase keywords, IF NOT EXISTS and implicit public schema", () => {
  const r = lintSql(`CREATE TABLE IF NOT EXISTS Things (ID SERIAL PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS public.things (id int);   -- same table, no-op
    ALTER TABLE things ENABLE ROW LEVEL SECURITY;
    GRANT SELECT, INSERT ON things TO authenticated;
    GRANT USAGE ON SEQUENCE things_id_seq TO authenticated;
    GRANT ALL ON public.things TO service_role;
    GRANT USAGE ON SEQUENCE public.things_id_seq TO service_role;`);
  assert.deepEqual(r.findings, []);
  assert.equal(r.counts.tables, 1);
});

test("--schemas: objects outside exposed schemas are ignored; api schema is checked when exposed", () => {
  const sql = `create schema api; create table api.items (id int); create table private.x (id int); grant all on private.x to anon;`;
  assert.deepEqual(lintSql(sql).findings, []);
  const r = lintSql(sql, { schemas: ["public", "api"] });
  assert.ok(has(r, "unreachable_after_oct30", "api.items"));
  assert.ok(!r.findings.some((f) => f.target.startsWith("private.")));
});

test("dropped and renamed objects are tracked", () => {
  const r = lintSql(`create table a (id int); drop table a;
    create table b (id int); alter table b rename to c; grant select on c to service_role;`);
  assert.deepEqual(r.findings, []);
});

test("drop + re-create loses the old grants", () => {
  const r = lintSql(`create table a (id int); grant all on a to service_role; drop table if exists a cascade; create table a (id int);`);
  assert.ok(has(r, "unreachable_after_oct30", "public.a"));
});

test("REVOKE removes a grant", () => {
  const r = lintSql(`create table a (id int); grant select on a to anon; revoke all on table a from anon;`);
  assert.ok(!has(r, "grant_without_rls"));
  assert.ok(has(r, "unreachable_after_oct30", "public.a"));
});

test("function grants/revokes match by signature (named args, defaults, aliases) and pg_dump quoting", () => {
  const r = lintSql(`
    CREATE OR REPLACE FUNCTION "public"."search"("p_query" "text", "p_limit" integer DEFAULT 10) RETURNS SETOF "text"
      LANGUAGE "sql" STABLE SECURITY DEFINER SET "search_path" TO '' AS $$ select 'x' $$;
    REVOKE ALL ON FUNCTION "public"."search"("p_query" "text", "p_limit" int4) FROM PUBLIC, "anon";
    GRANT ALL ON FUNCTION "public"."search"("p_query" "text", "p_limit" int4) TO "authenticated";`);
  assert.deepEqual(r.findings, []);
  assert.deepEqual(signatureTypes(lex(`(a integer, out b text, variadic c text[], double precision)`).toks.slice(1, -1)),
    ["integer", "text[]", "double precision"]);
});

test("SECURITY DEFINER stays callable by anon via PUBLIC unless PUBLIC is revoked", () => {
  const base = `create function public.admin_stats() returns int language sql security definer set search_path = '' as $$ select 1 $$;`;
  const onlyAnon = lintSql(`${base} revoke execute on function public.admin_stats() from anon;`);
  const f = find(onlyAnon, "security_definer_anon", "public.admin_stats");
  assert.ok(f, "revoke from anon alone is not enough");
  assert.match(f.message, /anon inherits EXECUTE from PUBLIC/);
  assert.match(f.fix_sql, /^revoke execute on function public\.admin_stats from public, anon;/);
  assert.ok(has(lintSql(base), "security_definer_anon"), "no revoke at all → flagged");
  assert.ok(!has(lintSql(`${base} revoke execute on function public.admin_stats() from public, anon;`), "security_definer_anon"));
  // SECURITY INVOKER functions run with the caller's rights: PUBLIC execute is not a finding
  assert.deepEqual(lintSql(`create function public.f() returns int language sql as 'select 1';`).findings, []);
});

test("per-schema ALTER DEFAULT PRIVILEGES ... FROM PUBLIC has no effect; the global one does", () => {
  const fn = `create function public.g() returns int language sql security definer set search_path = '' as 'select 1';`;
  const perSchema = lintSql(`alter default privileges in schema public revoke execute on functions from public, anon; ${fn}`);
  assert.ok(has(perSchema, "security_definer_anon", "public.g"));
  assert.match(find(perSchema, "security_definer_anon").message, /PUBLIC/);
  const global = lintSql(`alter default privileges revoke execute on functions from public;
    alter default privileges in schema public revoke execute on functions from anon; ${fn}`);
  assert.ok(!has(global, "security_definer_anon"));
});

test("overloaded functions get a full signature in the fix", () => {
  const r = lintSql(`alter default privileges revoke execute on functions from public;
    alter default privileges in schema public revoke execute on functions from anon, authenticated, service_role;
    create function f(a int) returns int language sql as 'select 1';
    create function f(a text) returns int language sql as 'select 1';
    grant execute on function f(integer) to authenticated;`);
  const f = find(r, "unreachable_after_oct30", "public.f");
  assert.equal(f.severity, "low");
  assert.match(f.fix_sql, /function public\.f\(text\)/);
});

test("ignore directive silences a statement; --ignore silences a target", () => {
  const sql = `-- supabase-security: ignore
    create table internal (id int);
    create table other (id int);`;
  const r = lintSql(sql);
  assert.ok(!has(r, "unreachable_after_oct30", "public.internal"));
  assert.ok(has(r, "unreachable_after_oct30", "public.other"));
  assert.ok(!has(lintSql(sql, { ignore: ["public.other"] }), "unreachable_after_oct30", "public.other"));
});

test("lexer: E-strings, doubled quotes and nested block comments", () => {
  const { toks } = lex(`select E'a\\'b;c', 'it''s;', $x$ ; $x$ /* a /* b */ c */ ;`);
  assert.equal(splitStatements(toks).length, 1);
  assert.deepEqual(toks.filter((t) => t.t === "str").map((t) => t.v), ["a'b;c", "it's;", " ; "]);
});

// ---- CLI -------------------------------------------------------------------

test("CLI: --json, --fail-on and --fix-sql", () => {
  const out = mkdtempSync(join(tmpdir(), "sbsec-"));
  try {
    const fix = join(out, "grants.sql");
    const p = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "basic"), "--json", "--fix-sql", fix], { encoding: "utf8" });
    assert.equal(p.status, 1);
    const j = JSON.parse(p.stdout);
    assert.equal(j.summary.critical, 1);
    assert.ok(j.findings.every((f) => f.fix_sql && f.file && f.line));
    assert.ok(existsSync(fix));
    const sql = readFileSync(fix, "utf8");
    assert.match(sql, /REVIEW EVERY LINE/);
    assert.match(sql, /alter table public\.leads enable row level security;/);
    assert.equal(sql.split("\n").filter((l) => l === "grant select, insert, update, delete on table public.orders to service_role;").length, 1);

    const crit = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "tricky"), "--fail-on", "critical", "--json"], { encoding: "utf8" });
    assert.equal(crit.status, 0);
    const never = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "basic"), "--fail-on=never", "--json"], { encoding: "utf8" });
    assert.equal(never.status, 0);
  } finally { rmSync(out, { recursive: true, force: true }); }
});

test("CLI: --github emits annotations; missing dir exits 2", () => {
  const p = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "lazy"), "--github", "--no-color"], { encoding: "utf8" });
  assert.match(p.stdout, /^::error file=.*lazy\/20251031000000_fix_permission_denied\.sql,line=\d+,title=CRITICAL/m);
  assert.match(p.stdout, /perufitlife\.github\.io\/supabase-security-skill\/oct30\//);
  const miss = spawnSync(process.execPath, [CLI, "migrations", join(FIX, "does-not-exist")], { encoding: "utf8" });
  assert.equal(miss.status, 2);
});

test("buildFixSql puts blanket revokes before per-object grants", () => {
  const sql = buildFixSql(lintDir("lazy"));
  assert.ok(sql.indexOf("revoke all on all tables") < sql.indexOf("enable row level security"));
});
