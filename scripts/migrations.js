#!/usr/bin/env node
// Supabase Security — MIGRATIONS LINTER (v0.5). Keyless, offline, no deps.
//
// On Oct 30, 2026 Supabase stops auto-granting new objects in `public` to
// anon / authenticated / service_role on every existing project (new projects
// already work this way since May 30). Source:
// https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically
//
// This linter replays your migration files in order and reports, per object:
//   - tables/views/sequences/functions with no GRANT → unreachable via the Data API
//   - tables granted to anon/authenticated with RLS off → the lazy fix opens your data
//   - blanket GRANTs / ALTER DEFAULT PRIVILEGES to anon → the lazy fix reopens every hole
//   - SECURITY DEFINER functions executable by anon
// …and writes a least-privilege migration that mirrors your RLS policies.
//
// Usage:
//   supabase-security migrations [dir=supabase/migrations] [--schemas public,api]
//        [--json] [--fix-sql out.sql] [--fail-on high] [--github] [--ignore public.t1,public.t2]

import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from "node:fs";
import { join, relative, dirname, resolve } from "node:path";

const VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version; } catch { return "0.5.0"; }
})();

const LANDING = "https://perufitlife.github.io/supabase-security-skill/oct30/";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const API_ROLES = ["anon", "authenticated", "service_role"];
const ROW_PRIVS = ["select", "insert", "update", "delete"];
const SERIAL_TYPES = new Set(["serial", "serial4", "bigserial", "serial8", "smallserial", "serial2"]);

const CHECKS = {
  grant_without_rls: {
    severity: "critical",
    title: "Granted to anon/authenticated but RLS is OFF",
    explain: "Grants decide who can reach the table, RLS decides which rows. With RLS off, anyone holding the anon key reads (and writes) every row.",
  },
  unreachable_after_oct30: {
    severity: "high",
    title: "No Data API grant: 42501 for new objects after Oct 30",
    explain: "No GRANT to anon/authenticated/service_role anywhere in your migrations. Existing objects keep their grants, but new objects like this will be unreachable (42501 permission denied) after Oct 30, and already are on any new project/branch that replays these migrations.",
  },
  lazy_bulk_grant: {
    severity: "high",
    title: "Lazy fix reopens exposure: blanket GRANT",
    explain: "GRANT ... ON ALL TABLES/FUNCTIONS IN SCHEMA hands every object that exists at that point to the role, including the ones you never meant to expose. It's Supabase's own rollback snippet: safe only if EVERY table already has RLS and correct policies.",
  },
  default_privileges_regrant: {
    severity: "high",
    title: "Lazy fix reopens exposure: ALTER DEFAULT PRIVILEGES",
    explain: "Re-creates the auto-grant Supabase removes on Oct 30: every future table/function is exposed on creation, before anyone writes RLS for it.",
  },
  security_definer_anon: {
    severity: "high",
    title: "SECURITY DEFINER function executable by anon",
    explain: "Runs with the owner's privileges (bypasses RLS) and anyone with the anon key can call it via /rest/v1/rpc.",
  },
  sequence_not_granted: {
    severity: "high",
    title: "INSERT will fail: serial sequence not granted",
    explain: "serial/bigserial columns call nextval() as the caller. Without USAGE on the sequence, inserts fail with 'permission denied for sequence'. (Identity columns don't need this.)",
  },
  view_bypasses_rls: {
    severity: "high",
    title: "Exposed view runs as its owner (bypasses RLS)",
    explain: "Views are SECURITY DEFINER by default in Postgres: anon/authenticated see the underlying rows regardless of their RLS policies.",
  },
  matview_exposed: {
    severity: "high",
    title: "Materialized view / foreign table exposed (no RLS possible)",
    explain: "RLS cannot be enabled on materialized views or foreign tables, so a grant exposes every row.",
  },
  definer_no_search_path: {
    severity: "medium",
    title: "SECURITY DEFINER function without SET search_path",
    explain: "A mutable search_path lets a caller shadow objects the function uses and run code as its owner.",
  },
};

// ---------------------------------------------------------------------------
// Lexer: comments, strings, E-strings, quoted identifiers, dollar-quoting.
// ---------------------------------------------------------------------------
const ID_START = /[A-Za-z_\u0080-\uFFFF]/;
const ID_PART = /[A-Za-z0-9_$\u0080-\uFFFF]/;

export function lex(sql) {
  const toks = [];
  const comments = [];
  const n = sql.length;
  let i = 0, line = 1, lineStart = true;
  while (i < n) {
    const c = sql[i];
    if (c === "\n") { line++; i++; lineStart = true; continue; }
    if (c === " " || c === "\t" || c === "\r" || c === "\f" || c === "\v" || c === "﻿") { i++; continue; }
    if (c === "\\" && lineStart) { // psql meta-command (\c, \set ...)
      const e = sql.indexOf("\n", i); i = e === -1 ? n : e; continue;
    }
    lineStart = false;
    if (c === "-" && sql[i + 1] === "-") {
      const e = sql.indexOf("\n", i); const end = e === -1 ? n : e;
      comments.push({ text: sql.slice(i + 2, end), line });
      i = end; continue;
    }
    if (c === "/" && sql[i + 1] === "*") {
      let depth = 1, j = i + 2; const startLine = line;
      while (j < n && depth) {
        if (sql[j] === "/" && sql[j + 1] === "*") { depth++; j += 2; }
        else if (sql[j] === "*" && sql[j + 1] === "/") { depth--; j += 2; }
        else { if (sql[j] === "\n") line++; j++; }
      }
      comments.push({ text: sql.slice(i + 2, Math.max(i + 2, j - 2)), line: startLine });
      i = j; continue;
    }
    const lc = c.toLowerCase();
    const isStr = c === "'" ||
      ((lc === "e" || lc === "n" || lc === "b" || lc === "x") && sql[i + 1] === "'") ||
      (lc === "u" && sql[i + 1] === "&" && sql[i + 2] === "'");
    if (isStr) {
      const esc = lc === "e";
      let j = i; while (sql[j] !== "'") j++; j++;
      let val = ""; const startLine = line;
      while (j < n) {
        const d = sql[j];
        if (esc && d === "\\") { const nx = sql[j + 1] ?? ""; if (nx === "\n") line++; val += nx; j += 2; continue; }
        if (d === "'") { if (sql[j + 1] === "'") { val += "'"; j += 2; continue; } j++; break; }
        if (d === "\n") line++;
        val += d; j++;
      }
      toks.push({ t: "str", v: val, line: startLine });
      i = j; continue;
    }
    if (c === '"') {
      let j = i + 1, val = ""; const startLine = line;
      while (j < n) {
        if (sql[j] === '"') { if (sql[j + 1] === '"') { val += '"'; j += 2; continue; } j++; break; }
        if (sql[j] === "\n") line++;
        val += sql[j]; j++;
      }
      toks.push({ t: "id", v: val, q: true, line: startLine });
      i = j; continue;
    }
    if (c === "$") {
      const m = /^\$(?:[A-Za-z_\u0080-\uFFFF][A-Za-z0-9_\u0080-\uFFFF]*)?\$/.exec(sql.slice(i, i + 80));
      if (m) {
        const tag = m[0];
        const e = sql.indexOf(tag, i + tag.length);
        const end = e === -1 ? n : e;
        const body = sql.slice(i + tag.length, end);
        const startLine = line;
        for (let k = 0; k < body.length; k++) if (body.charCodeAt(k) === 10) line++;
        toks.push({ t: "str", v: body, dollar: true, line: startLine });
        i = e === -1 ? n : end + tag.length; continue;
      }
    }
    if (ID_START.test(c)) {
      let j = i + 1; while (j < n && ID_PART.test(sql[j])) j++;
      toks.push({ t: "id", v: sql.slice(i, j).toLowerCase(), q: false, line });
      i = j; continue;
    }
    if (c >= "0" && c <= "9") {
      let j = i + 1; while (j < n && /[0-9._eE]/.test(sql[j])) j++;
      toks.push({ t: "num", v: sql.slice(i, j), line });
      i = j; continue;
    }
    if (c === ":" && sql[i + 1] === ":") { toks.push({ t: "op", v: "::", line }); i += 2; continue; }
    toks.push({ t: c === ";" ? ";" : "op", v: c, line });
    i++;
  }
  return { toks, comments };
}

const isKw = (tk, w) => !!tk && tk.t === "id" && !tk.q && tk.v === w;
const isOp = (tk, v) => !!tk && tk.t === "op" && tk.v === v;
const isWord = (tk, w) => !!tk && tk.t === "id" && tk.v === w; // quoted or not (pg_dump quotes types)

// Split tokens into statements; SQL-standard bodies (BEGIN ATOMIC ... END) may contain ';'.
export function splitStatements(toks) {
  const stmts = [];
  let cur = [], atomic = 0;
  for (const tk of toks) {
    if (tk.t === ";" && atomic === 0) { if (cur.length) stmts.push(cur); cur = []; continue; }
    if (tk.t === "id" && !tk.q) {
      if (tk.v === "atomic" && isKw(cur[cur.length - 1], "begin") && isKw(cur[0], "create")) atomic = 1;
      else if (atomic > 0 && tk.v === "case") atomic++;
      else if (atomic > 0 && tk.v === "end") atomic--;
    }
    if (tk.t !== ";") cur.push(tk);
  }
  if (cur.length) stmts.push(cur);
  return stmts;
}

// ---------------------------------------------------------------------------
// Identifier helpers
// ---------------------------------------------------------------------------
const RESERVED = new Set(("all analyse analyze and any array as asc asymmetric authorization binary both case cast check collate column constraint create cross current_catalog current_date current_role current_schema current_time current_timestamp current_user default deferrable desc distinct do else end except false fetch for foreign freeze from full grant group having ilike in initially inner intersect into is isnull join lateral leading left like limit localtime localtimestamp natural not notnull null offset on only or order outer overlaps placing primary references returning right select session_user similar some symmetric system_user table tablesample then to trailing true union unique user using variadic verbose when where window with").split(" "));
export function qi(name) {
  return /^[a-z_][a-z0-9_$]*$/.test(name) && !RESERVED.has(name) ? name : `"${name.replace(/"/g, '""')}"`;
}
const qn = (o) => `${qi(o.schema)}.${qi(o.name)}`;
const keyOf = (schema, name) => `${schema}\u0000${name}`;

const TYPE_ALIASES = {
  int: "integer", int4: "integer", int8: "bigint", int2: "smallint", bool: "boolean",
  varchar: "character varying", "char varying": "character varying", char: "character", float8: "double precision",
  float4: "real", float: "double precision", decimal: "numeric", timestamptz: "timestamp with time zone",
  timestamp: "timestamp without time zone", timetz: "time with time zone", time: "time without time zone",
};
const MULTIWORD_TYPE_START = new Set(["double", "character", "bit", "timestamp", "time", "interval", "national", "char"]);
const ARG_MODES = new Set(["in", "out", "inout", "variadic"]);

// Tokens between the parens of a function signature → ["uuid", "text", ...] (input args only).
export function signatureTypes(argToks) {
  const types = [];
  for (const part of splitTopLevel(argToks)) {
    let t = part.slice();
    const cut = t.findIndex((x) => isKw(x, "default") || isOp(x, "="));
    if (cut !== -1) t = t.slice(0, cut);
    let mode = "in";
    if (t.length > 1 && t[0].t === "id" && !t[0].q && ARG_MODES.has(t[0].v)) { mode = t[0].v; t = t.slice(1); }
    if (mode === "out" || !t.length) continue;
    const first = t[0], second = t[1];
    const hasName = t.length >= 2 && first.t === "id" && !isOp(second, ".") && !isOp(second, "[") && !isOp(second, "(") &&
      !(!first.q && MULTIWORD_TYPE_START.has(first.v));
    if (hasName) t = t.slice(1);
    types.push(normType(t));
  }
  return types;
}
function normType(t) {
  const out = [];
  let depth = 0;
  for (const tk of t) {
    if (isOp(tk, "(")) { depth++; continue; }
    if (isOp(tk, ")")) { depth--; continue; }
    if (depth > 0) continue; // typmods: varchar(255), numeric(10,2)
    if (tk.t === "id") out.push(tk.v.toLowerCase()); else out.push(tk.v);
  }
  let s = out.join(" ").replace(/\s*\.\s*/g, ".").replace(/\s*\[\s*\]/g, "[]").replace(/^(pg_catalog|public)\./, "");
  const arr = s.endsWith("[]") ? "[]" : "";
  const base = arr ? s.slice(0, -2) : s;
  return (TYPE_ALIASES[base] || base) + arr;
}
function splitTopLevel(toks) {
  const parts = []; let cur = [], depth = 0;
  for (const tk of toks) {
    if (isOp(tk, "(") || isOp(tk, "[")) depth++;
    if (isOp(tk, ")") || isOp(tk, "]")) depth--;
    if (depth === 0 && isOp(tk, ",")) { parts.push(cur); cur = []; continue; }
    cur.push(tk);
  }
  if (cur.length) parts.push(cur);
  return parts;
}

// ---------------------------------------------------------------------------
// Statement cursor
// ---------------------------------------------------------------------------
class Cur {
  constructor(toks) { this.t = toks; this.p = 0; }
  peek(o = 0) { return this.t[this.p + o]; }
  next() { return this.t[this.p++]; }
  done() { return this.p >= this.t.length; }
  kw(...ws) { return ws.every((w, k) => isKw(this.t[this.p + k], w)); }
  eat(...ws) { if (this.kw(...ws)) { this.p += ws.length; return true; } return false; }
  // Qualified name: a.b.c → ["a","b","c"]
  qname() {
    const tk = this.peek();
    if (!tk || tk.t !== "id") return null;
    const parts = [this.next().v];
    while (isOp(this.peek(), ".") && this.peek(1)?.t === "id") { this.p++; parts.push(this.next().v); }
    if (isOp(this.peek(), ".") && isOp(this.peek(1), "*")) this.p += 2;
    if (isOp(this.peek(), "*")) this.p++; // ALTER TABLE ONLY x *
    return { parts, line: tk.line };
  }
  // Consume a balanced (...) group, return inner tokens.
  parens() {
    if (!isOp(this.peek(), "(")) return null;
    const start = ++this.p; let depth = 1;
    while (this.p < this.t.length && depth) {
      if (isOp(this.t[this.p], "(")) depth++;
      else if (isOp(this.t[this.p], ")")) depth--;
      this.p++;
    }
    return this.t.slice(start, this.p - 1);
  }
  rest() { return this.t.slice(this.p); }
}

function findSeq(toks, ...ws) {
  for (let i = 0; i + ws.length <= toks.length; i++) if (ws.every((w, k) => isKw(toks[i + k], w))) return i;
  return -1;
}

// ---------------------------------------------------------------------------
// Replay engine
// ---------------------------------------------------------------------------
function newGrants() { return new Map(); }
function addGrant(obj, role, privs, src) {
  if (!obj.grants.has(role)) obj.grants.set(role, new Set());
  for (const p of privs) obj.grants.get(role).add(p);
  if (src) (obj.grantSrc[role] ||= []).push(src);
}
function removeGrant(obj, role, privs) {
  const s = obj.grants.get(role); if (!s) return;
  for (const p of privs) s.delete(p);
  if (!s.size) { obj.grants.delete(role); delete obj.grantSrc[role]; }
}
function effective(obj, role) {
  const s = new Set(obj.grants.get(role) || []);
  for (const p of obj.grants.get("public") || []) s.add(p); // PUBLIC includes every role
  return s;
}
const hasAny = (set, privs) => privs.some((p) => set.has(p));

const ALL_PRIVS = {
  rel: ["select", "insert", "update", "delete", "truncate", "references", "trigger"],
  seq: ["usage", "select", "update"],
  func: ["execute"],
};

class Replay {
  constructor({ schemas }) {
    this.exposed = new Set(schemas);
    this.searchPath = ["public"];
    this.rels = new Map();   // table / view / matview / foreign / partition
    this.seqs = new Map();
    this.funcs = new Map();  // key → [overload]
    // `${objtype}|${schema|*}|${role}` → Set(privs). Tables/sequences start empty: that IS the Oct 30
    // change. Functions do not: Postgres grants EXECUTE to PUBLIC on every new function (only a
    // *global* ALTER DEFAULT PRIVILEGES ... REVOKE ... FROM PUBLIC removes it; a per-schema one has no
    // effect), and Supabase's default privileges in `public` still grant EXECUTE to the API roles.
    this.defaults = new Map([
      ["functions|*|public", new Set(["execute"])],
      ["functions|public|anon", new Set(["execute"])],
      ["functions|public|authenticated", new Set(["execute"])],
      ["functions|public|service_role", new Set(["execute"])],
    ]);
    this.builtinDefaults = new Set(this.defaults.keys());
    this.events = [];        // statement-level findings (bulk grants, default privileges)
    this.file = ""; this.ignore = null;
  }

  resolve(parts) {
    if (!parts) return null;
    if (parts.length >= 2) return { schema: parts[parts.length - 2], name: parts[parts.length - 1] };
    return { schema: this.searchPath[0] || "public", name: parts[0] };
  }
  loc(line) { return { file: this.file, line }; }

  applyDefaults(obj, objtype) {
    for (const role of [...API_ROLES, "public"]) {
      for (const sk of ["*", obj.schema]) {
        const key = `${objtype}|${sk}|${role}`;
        const s = this.defaults.get(key);
        if (s && s.size) addGrant(obj, role, s, { default: true, builtin: this.builtinDefaults.has(key), ...this.loc(obj.line) });
      }
    }
  }

  newRel(kind, id, line, extra = {}) {
    const obj = { kind, schema: id.schema, name: id.name, file: this.file, line, rls: false, grants: newGrants(), grantSrc: {},
      seqs: new Set(), policies: [], securityInvoker: false, ignore: this.ignore, ...extra };
    this.rels.set(keyOf(id.schema, id.name), obj);
    this.applyDefaults(obj, "tables");
    return obj;
  }
  newSeq(id, line, owner = null, implicit = false) {
    const obj = { kind: "sequence", schema: id.schema, name: id.name, file: this.file, line, grants: newGrants(), grantSrc: {},
      owner, implicit, ignore: owner ? owner.ignore : this.ignore };
    this.seqs.set(keyOf(id.schema, id.name), obj);
    this.applyDefaults(obj, "sequences");
    if (owner) owner.seqs.add(obj);
    return obj;
  }

  findFuncs(id, sig) {
    const list = this.funcs.get(keyOf(id.schema, id.name)) || [];
    if (sig) {
      const exact = list.filter((f) => f.sig.join(",") === sig.join(","));
      if (exact.length) return exact;
    }
    return list;
  }

  run(stmt) {
    const c = new Cur(stmt);
    const head = c.peek();
    if (!head || head.t !== "id") return;
    try {
      switch (head.v) {
        case "create": return this.create(c);
        case "alter": return this.alter(c);
        case "drop": return this.drop(c);
        case "grant": case "revoke": return this.grant(c);
        case "set": return this.setStmt(c);
        case "reset": if (isWord(c.peek(1), "search_path") || isKw(c.peek(1), "all")) this.searchPath = ["public"]; return;
        case "select": return this.selectStmt(c);
      }
    } catch { /* unparseable statement: skip, never crash the lint */ }
  }

  // ---- CREATE -----------------------------------------------------------
  create(c) {
    c.next();
    const mods = new Set();
    const MODS = new Set(["or", "replace", "temp", "temporary", "unlogged", "global", "local", "foreign", "recursive", "materialized", "constraint", "trusted", "procedural", "unique"]);
    while (c.peek()?.t === "id" && !c.peek().q && MODS.has(c.peek().v)) mods.add(c.next().v);
    const obj = c.next();
    if (!obj || obj.t !== "id") return;
    const temp = mods.has("temp") || mods.has("temporary");
    switch (obj.v) {
      case "table": return temp ? undefined : this.createTable(c, mods);
      case "view": return temp ? undefined : (mods.has("materialized") ? this.createMatview(c) : this.createView(c, mods));
      case "sequence": return temp ? undefined : this.createSequence(c);
      case "function": return this.createFunction(c, mods);
      case "policy": return this.createPolicy(c);
    }
  }

  createTable(c, mods) {
    const ifne = c.eat("if", "not", "exists");
    const qn_ = c.qname(); if (!qn_) return;
    const id = this.resolve(qn_.parts);
    const k = keyOf(id.schema, id.name);
    if (this.rels.has(k) && ifne) return;
    let kind = mods.has("foreign") ? "foreign" : "table";
    if (c.kw("partition", "of")) kind = "partition";
    const rel = this.newRel(kind, id, qn_.line);
    if (kind === "partition") return;
    const cols = c.parens();
    if (!cols) return; // CREATE TABLE AS / OF type
    for (const el of splitTopLevel(cols)) this.columnDef(rel, el);
  }

  columnDef(rel, el) {
    const first = el[0];
    if (!first) return;
    if (first.t === "id" && !first.q && ["constraint", "primary", "unique", "check", "foreign", "exclude", "like"].includes(first.v)) return;
    const col = first.v;
    const type = el[1];
    if (type && type.t === "id" && SERIAL_TYPES.has(type.v)) {
      const seqName = `${rel.name}_${col}_seq`.slice(0, 63);
      this.newSeq({ schema: rel.schema, name: seqName }, first.line, rel, true);
    }
    this.nextvalDefault(rel, el);
  }

  nextvalDefault(rel, toks) {
    for (let i = 0; i < toks.length - 2; i++) {
      if (isWord(toks[i], "nextval") && isOp(toks[i + 1], "(") && toks[i + 2].t === "str") {
        const parts = parseRegclass(toks[i + 2].v);
        const id = this.resolve(parts);
        const seq = this.seqs.get(keyOf(id.schema, id.name));
        if (seq) rel.seqs.add(seq);
      }
    }
  }

  createView(c, mods) {
    c.eat("if", "not", "exists");
    const qn_ = c.qname(); if (!qn_) return;
    const id = this.resolve(qn_.parts);
    const k = keyOf(id.schema, id.name);
    if (isOp(c.peek(), "(")) c.parens();
    let invoker = false;
    if (c.eat("with")) invoker = parseSecurityInvoker(c.parens() || []) ?? false;
    const existing = this.rels.get(k);
    if (existing && mods.has("replace") && existing.kind === "view") {
      existing.securityInvoker = invoker; // CREATE OR REPLACE resets reloptions, keeps grants
      return;
    }
    this.newRel("view", id, qn_.line, { securityInvoker: invoker });
  }

  createMatview(c) {
    const ifne = c.eat("if", "not", "exists");
    const qn_ = c.qname(); if (!qn_) return;
    const id = this.resolve(qn_.parts);
    if (this.rels.has(keyOf(id.schema, id.name)) && ifne) return;
    this.newRel("matview", id, qn_.line);
  }

  createSequence(c) {
    const ifne = c.eat("if", "not", "exists");
    const qn_ = c.qname(); if (!qn_) return;
    const id = this.resolve(qn_.parts);
    if (this.seqs.has(keyOf(id.schema, id.name)) && ifne) return;
    const seq = this.newSeq(id, qn_.line);
    const rest = c.rest();
    const at = findSeq(rest, "owned", "by");
    if (at !== -1) this.ownSequence(seq, new Cur(rest.slice(at + 2)));
  }

  ownSequence(seq, c) {
    const q = c.qname();
    if (!q || q.parts.length < 2) return;
    const id = this.resolve(q.parts.slice(0, -1));
    const rel = this.rels.get(keyOf(id.schema, id.name));
    if (rel) { seq.owner = rel; rel.seqs.add(seq); }
  }

  createFunction(c, mods) {
    const qn_ = c.qname(); if (!qn_) return;
    const id = this.resolve(qn_.parts);
    const args = c.parens() || [];
    const sig = signatureTypes(args);
    const rest = c.rest();
    let returnsTrigger = false, definer = false, searchPath = false;
    for (let i = 0; i < rest.length; i++) {
      if (isKw(rest[i], "returns") && (isWord(rest[i + 1], "trigger") || isWord(rest[i + 1], "event_trigger"))) returnsTrigger = true;
      if (isKw(rest[i], "security") && isKw(rest[i + 1], "definer")) definer = true;
      if (isKw(rest[i], "set") && isWord(rest[i + 1], "search_path")) searchPath = true;
    }
    const k = keyOf(id.schema, id.name);
    const list = this.funcs.get(k) || [];
    const prev = list.find((f) => f.sig.join(",") === sig.join(","));
    if (prev && mods.has("replace")) { // keeps grants
      Object.assign(prev, { returnsTrigger, definer, searchPath });
      return;
    }
    const fn = { kind: "function", schema: id.schema, name: id.name, sig, file: this.file, line: qn_.line, returnsTrigger, definer, searchPath,
      grants: newGrants(), grantSrc: {}, ignore: this.ignore };
    this.funcs.set(k, [...list.filter((f) => f !== prev), fn]);
    this.applyDefaults(fn, "functions");
  }

  createPolicy(c) {
    const nameTok = c.next(); if (!nameTok) return;
    if (!c.eat("on")) return;
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const rel = this.rels.get(keyOf(id.schema, id.name));
    if (!rel) return;
    const pol = { name: nameTok.v, cmd: "all", roles: ["public"], authOnly: false };
    while (!c.done()) {
      if (c.eat("for")) { const t = c.next(); if (t) pol.cmd = t.v; continue; }
      if (c.eat("to")) { pol.roles = readRoles(c, ["using", "with"]); continue; }
      if (c.kw("using") || c.kw("with")) break;
      c.next();
    }
    // `auth.uid() = user_id` never matches for anon (auth.uid() is null), so don't grant anon for it.
    const expr = c.rest();
    const usesUid = expr.some((t, i) => isWord(t, "auth") && isOp(expr[i + 1], ".") && isWord(expr[i + 2], "uid"));
    pol.authOnly = usesUid && !expr.some((t) => isKw(t, "null") || isKw(t, "or"));
    rel.policies = rel.policies.filter((p) => p.name !== pol.name).concat(pol);
  }

  // ---- ALTER ------------------------------------------------------------
  alter(c) {
    c.next();
    if (c.eat("default", "privileges")) return this.defaultPrivileges(c);
    if (c.eat("materialized", "view") || c.eat("foreign", "table")) return this.alterRel(c, false);
    if (c.eat("table")) return this.alterRel(c, true);
    if (c.eat("view")) return this.alterRel(c, false);
    if (c.eat("sequence")) return this.alterSequence(c);
    if (c.eat("function")) return this.alterFunction(c);
    if (c.eat("policy")) return this.alterPolicy(c);
  }

  alterRel(c, isTable) {
    c.eat("if", "exists"); c.eat("only");
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const k = keyOf(id.schema, id.name);
    const rel = this.rels.get(k);
    const seq = !rel && isTable ? this.seqs.get(k) : null; // ALTER TABLE works on sequences too
    const rest = c.rest();
    const target = rel || seq;
    if (!target) return;
    const ren = findSeq(rest, "rename", "to");
    if (ren !== -1 && rest[ren + 2]) return this.move(target, { schema: target.schema, name: rest[ren + 2].v });
    const ss = findSeq(rest, "set", "schema");
    if (ss !== -1 && rest[ss + 2]) return this.move(target, { schema: rest[ss + 2].v, name: target.name });
    if (!rel) return;
    if (findSeq(rest, "enable", "row", "level", "security") !== -1) rel.rls = true;
    if (findSeq(rest, "disable", "row", "level", "security") !== -1) rel.rls = false;
    for (let i = 0; i < rest.length; i++) {
      if (isKw(rest[i], "set") && isOp(rest[i + 1], "(")) {
        const inner = new Cur(rest.slice(i + 1)).parens() || [];
        const v = parseSecurityInvoker(inner); if (v !== null) rel.securityInvoker = v;
      }
      if (isKw(rest[i], "reset") && isOp(rest[i + 1], "(")) {
        const inner = new Cur(rest.slice(i + 1)).parens() || [];
        if (inner.some((t) => isWord(t, "security_invoker"))) rel.securityInvoker = false;
      }
    }
    // ADD [COLUMN] [IF NOT EXISTS] col serial ...
    for (const part of splitTopLevel(rest)) {
      const pc = new Cur(part);
      if (!pc.eat("add")) continue;
      pc.eat("column"); pc.eat("if", "not", "exists");
      this.columnDef(rel, pc.rest());
    }
    this.nextvalDefault(rel, rest);
  }

  move(obj, to) {
    const map = obj.kind === "sequence" ? this.seqs : this.rels;
    map.delete(keyOf(obj.schema, obj.name));
    obj.schema = to.schema; obj.name = to.name;
    map.set(keyOf(to.schema, to.name), obj);
  }

  alterSequence(c) {
    c.eat("if", "exists");
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const seq = this.seqs.get(keyOf(id.schema, id.name)); if (!seq) return;
    const rest = c.rest();
    const ren = findSeq(rest, "rename", "to");
    if (ren !== -1 && rest[ren + 2]) return this.move(seq, { schema: seq.schema, name: rest[ren + 2].v });
    const ss = findSeq(rest, "set", "schema");
    if (ss !== -1 && rest[ss + 2]) return this.move(seq, { schema: rest[ss + 2].v, name: seq.name });
    const ob = findSeq(rest, "owned", "by");
    if (ob !== -1) this.ownSequence(seq, new Cur(rest.slice(ob + 2)));
  }

  alterFunction(c) {
    c.eat("if", "exists");
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const args = c.parens();
    const fns = this.findFuncs(id, args ? signatureTypes(args) : null);
    const rest = c.rest();
    for (const fn of fns) {
      if (findSeq(rest, "security", "definer") !== -1) fn.definer = true;
      if (findSeq(rest, "security", "invoker") !== -1) fn.definer = false;
      for (let i = 0; i < rest.length; i++) if (isKw(rest[i], "set") && isWord(rest[i + 1], "search_path")) fn.searchPath = true;
      if (findSeq(rest, "reset", "all") !== -1) fn.searchPath = false;
      const ren = findSeq(rest, "rename", "to");
      const ss = findSeq(rest, "set", "schema");
      if (ren !== -1 || ss !== -1) {
        const oldK = keyOf(fn.schema, fn.name);
        this.funcs.set(oldK, (this.funcs.get(oldK) || []).filter((f) => f !== fn));
        if (ren !== -1 && rest[ren + 2]) fn.name = rest[ren + 2].v;
        if (ss !== -1 && rest[ss + 2]) fn.schema = rest[ss + 2].v;
        const nk = keyOf(fn.schema, fn.name);
        this.funcs.set(nk, [...(this.funcs.get(nk) || []), fn]);
      }
    }
  }

  alterPolicy(c) {
    const nameTok = c.next(); if (!nameTok || !c.eat("on")) return;
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const rel = this.rels.get(keyOf(id.schema, id.name)); if (!rel) return;
    const pol = rel.policies.find((p) => p.name === nameTok.v); if (!pol) return;
    if (c.eat("rename", "to")) { const t = c.next(); if (t) pol.name = t.v; return; }
    if (c.eat("to")) pol.roles = readRoles(c, ["using", "with"]);
  }

  // ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s] GRANT|REVOKE privs ON TABLES|SEQUENCES|FUNCTIONS TO|FROM roles
  defaultPrivileges(c) {
    const line = c.peek()?.line;
    let forRoles = null, schemas = null;
    for (;;) {
      if (c.eat("for", "role") || c.eat("for", "user")) { forRoles = readList(c); continue; }
      if (c.eat("in", "schema")) { schemas = readList(c); continue; }
      break;
    }
    const isGrant = c.eat("grant");
    if (!isGrant && !c.eat("revoke")) return;
    if (!isGrant && c.eat("grant", "option", "for")) return;
    const privs = readPrivs(c);
    if (!c.eat("on")) return;
    const ot = c.next()?.v;
    const objtype = ot === "tables" ? "tables" : ot === "sequences" ? "sequences" : (ot === "functions" || ot === "routines") ? "functions" : null;
    if (!objtype) return;
    if (!c.eat(isGrant ? "to" : "from")) return;
    const roles = readRoles(c, ["with", "cascade", "restrict"]).filter((r) => r === "public" || API_ROLES.includes(r));
    const kind = objtype === "tables" ? "rel" : objtype === "sequences" ? "seq" : "func";
    const pset = privs.includes("all") ? ALL_PRIVS[kind] : privs;
    const affectsMigrations = !forRoles || forRoles.includes("postgres");
    if (affectsMigrations) {
      for (const role of roles) for (const s of schemas || ["*"]) {
        const key = `${objtype}|${s}|${role}`;
        if (!this.defaults.has(key)) this.defaults.set(key, new Set());
        for (const p of pset) isGrant ? this.defaults.get(key).add(p) : this.defaults.get(key).delete(p);
      }
    }
    if (!isGrant || objtype === "sequences") return;
    const inExposed = !schemas || schemas.some((s) => this.exposed.has(s));
    if (!inExposed) return;
    const exposing = objtype === "tables" ? hasAny(new Set(pset), ROW_PRIVS) : pset.includes("execute");
    if (!exposing) return;
    const anonLike = roles.filter((r) => r === "anon" || r === "public");
    const authLike = roles.filter((r) => r === "authenticated");
    const who = [...anonLike, ...authLike];
    if (!who.length) return;
    this.events.push({
      check: "default_privileges_regrant", severity: anonLike.length ? "high" : "medium",
      objtype, roles: who, forRoles, schemas, privs: pset,
      file: this.file, line, ignore: this.ignore,
    });
  }

  // ---- DROP -------------------------------------------------------------
  drop(c) {
    c.next();
    let kind = null;
    if (c.eat("materialized", "view") || c.eat("foreign", "table") || c.eat("table") || c.eat("view")) kind = "rel";
    else if (c.eat("sequence")) kind = "seq";
    else if (c.eat("function")) kind = "func";
    else if (c.eat("policy")) return this.dropPolicy(c);
    else return;
    c.eat("if", "exists");
    while (!c.done()) {
      const q = c.qname(); if (!q) break;
      const id = this.resolve(q.parts);
      const k = keyOf(id.schema, id.name);
      if (kind === "rel") {
        const rel = this.rels.get(k);
        if (rel) { for (const s of rel.seqs) if (s.owner === rel) this.seqs.delete(keyOf(s.schema, s.name)); this.rels.delete(k); }
      } else if (kind === "seq") this.seqs.delete(k);
      else {
        const args = c.parens();
        const drop = new Set(this.findFuncs(id, args ? signatureTypes(args) : null));
        const left = (this.funcs.get(k) || []).filter((f) => !drop.has(f));
        left.length ? this.funcs.set(k, left) : this.funcs.delete(k);
      }
      if (!isOp(c.peek(), ",")) break;
      c.next();
    }
  }
  dropPolicy(c) {
    c.eat("if", "exists");
    const nameTok = c.next(); if (!nameTok || !c.eat("on")) return;
    const q = c.qname(); if (!q) return;
    const id = this.resolve(q.parts);
    const rel = this.rels.get(keyOf(id.schema, id.name));
    if (rel) rel.policies = rel.policies.filter((p) => p.name !== nameTok.v);
  }

  // ---- GRANT / REVOKE ---------------------------------------------------
  grant(c) {
    const isGrant = c.next().v === "grant";
    const line = c.peek()?.line;
    if (!isGrant && c.eat("grant", "option", "for")) return;
    const privs = readPrivs(c);
    if (!c.eat("on")) return; // role membership grant
    let target = "rel", bulk = false, schemas = null;
    if (c.eat("all")) {
      const w = c.next()?.v;
      if (w === "tables") target = "rel"; else if (w === "sequences") target = "seq"; else if (w === "functions" || w === "routines") target = "func"; else return;
      if (!c.eat("in", "schema")) return;
      schemas = readList(c); bulk = true;
    } else if (c.eat("table")) target = "rel";
    else if (c.eat("sequence")) target = "seq";
    else if (c.eat("function") || c.eat("routine")) target = "func";
    else if (["schema", "database", "type", "domain", "language", "tablespace", "large", "foreign", "procedure", "parameter"].includes(c.peek()?.v) && !c.peek().q && !isOp(c.peek(1), ".")) return;
    const objs = [];
    if (!bulk) {
      while (!c.done() && !c.kw("to") && !c.kw("from")) {
        const q = c.qname(); if (!q) { c.next(); continue; }
        const id = this.resolve(q.parts);
        if (target === "func") {
          const args = c.parens();
          objs.push(...this.findFuncs(id, args ? signatureTypes(args) : null));
        } else {
          const k = keyOf(id.schema, id.name);
          const o = this.rels.get(k) || this.seqs.get(k);
          if (o) objs.push(o);
        }
        if (isOp(c.peek(), ",")) c.next();
      }
    } else {
      for (const s of schemas) {
        if (target === "rel") for (const r of this.rels.values()) { if (r.schema === s) objs.push(r); }
        else if (target === "seq") for (const q of this.seqs.values()) { if (q.schema === s) objs.push(q); }
        else for (const list of this.funcs.values()) for (const f of list) if (f.schema === s) objs.push(f);
      }
    }
    if (!c.eat(isGrant ? "to" : "from")) return;
    const roles = readRoles(c, ["with", "granted", "cascade", "restrict"]).filter((r) => r === "public" || API_ROLES.includes(r));
    if (!roles.length) return;
    const src = { bulk, ...this.loc(line) };
    for (const o of objs) {
      const kind = o.kind === "sequence" ? "seq" : o.kind === "function" ? "func" : "rel";
      const pset = privs.includes("all") ? ALL_PRIVS[kind] : privs;
      for (const r of roles) {
        if (isGrant) addGrant(o, r, pset, src); else removeGrant(o, r, pset);
        if (!isGrant && kind === "func" && r === "anon") o.revokedAnon = { ...this.loc(line) };
      }
    }
    if (!isGrant || !bulk || target === "seq") return;
    if (!schemas.some((s) => this.exposed.has(s))) return;
    const pset = privs.includes("all") ? ALL_PRIVS[target] : privs;
    const exposing = target === "rel" ? hasAny(new Set(pset), ROW_PRIVS) : pset.includes("execute");
    if (!exposing) return;
    const anonLike = roles.filter((r) => r === "anon" || r === "public");
    const authLike = roles.filter((r) => r === "authenticated");
    const who = [...anonLike, ...authLike];
    if (!who.length) return;
    this.events.push({
      check: "lazy_bulk_grant", severity: anonLike.length ? "high" : "medium", target, roles: who, schemas,
      privs: pset, covered: objs, file: this.file, line, ignore: this.ignore,
    });
  }

  // ---- SET search_path --------------------------------------------------
  setStmt(c) {
    c.next(); c.eat("session"); c.eat("local");
    if (!isWord(c.peek(), "search_path")) return;
    c.next();
    if (!c.eat("to") && isOp(c.peek(), "=")) c.next();
    const vals = [];
    while (!c.done()) {
      const t = c.next();
      if (t.t === "str") vals.push(...t.v.split(",").map((s) => s.trim().replace(/^"|"$/g, "")).filter(Boolean));
      else if (t.t === "id" && t.v !== "default") vals.push(t.v);
    }
    this.searchPath = vals.filter((v) => v !== "$user" && v !== "pg_catalog");
  }
  selectStmt(c) {
    const toks = c.rest();
    for (let i = 0; i < toks.length - 4; i++) {
      if (isWord(toks[i], "set_config") && isOp(toks[i + 1], "(") && toks[i + 2].t === "str" && toks[i + 2].v === "search_path" && toks[i + 4]?.t === "str") {
        this.searchPath = toks[i + 4].v.split(",").map((s) => s.trim().replace(/^"|"$/g, "")).filter((v) => v && v !== "$user" && v !== "pg_catalog");
      }
    }
  }
}

function parseRegclass(s) {
  // 'public.my_seq' | '"My Seq"' | 'my_seq'
  const parts = [];
  const re = /"((?:[^"]|"")*)"|([^.]+)/g; let m;
  while ((m = re.exec(s))) parts.push(m[1] !== undefined ? m[1].replace(/""/g, '"') : m[2].trim().toLowerCase());
  return parts.filter(Boolean);
}
function parseSecurityInvoker(toks) {
  for (let i = 0; i < toks.length; i++) {
    if (isWord(toks[i], "security_invoker")) {
      if (!isOp(toks[i + 1], "=")) return true;
      const v = String(toks[i + 2]?.v ?? "").toLowerCase();
      return ["true", "on", "1", "yes", "t", "y"].includes(v);
    }
  }
  return null;
}
function readList(c) {
  const out = [];
  while (c.peek()?.t === "id") {
    out.push(c.next().v);
    if (!isOp(c.peek(), ",")) break;
    c.next();
  }
  return out;
}
function readRoles(c, stop) {
  const out = [];
  while (!c.done()) {
    const t = c.peek();
    if (t.t === "id" && !t.q && stop.includes(t.v)) break;
    c.next();
    if (t.t === "id" && !(isKw(t, "group"))) out.push(t.v);
  }
  return out;
}
function readPrivs(c) {
  const out = [];
  while (!c.done() && !c.kw("on")) {
    const t = c.next();
    if (t.t === "id") { if (t.v !== "privileges") out.push(t.v); }
    if (isOp(c.peek(), "(")) c.parens(); // column list
  }
  return out;
}

// ---------------------------------------------------------------------------
// Findings + least-privilege fix SQL
// ---------------------------------------------------------------------------
const orderPrivs = (s) => ROW_PRIVS.filter((p) => s.has(p));

function policyGrants(rel) {
  const out = { anon: new Set(), authenticated: new Set() };
  for (const p of rel.policies) {
    const privs = p.cmd === "all" ? ROW_PRIVS : [p.cmd];
    const roles = new Set();
    for (const r of p.roles) {
      if (r === "public") { if (!p.authOnly) roles.add("anon"); roles.add("authenticated"); }
      else if (r === "anon" || r === "authenticated") roles.add(r);
    }
    for (const r of roles) for (const pr of privs) {
      if (!ROW_PRIVS.includes(pr)) continue;
      out[r].add(pr);
      if (pr === "update" || pr === "delete") out[r].add("select"); // WHERE clauses need SELECT privilege
    }
  }
  return out;
}

function seqGrantLines(rel, roles) {
  const lines = [];
  const serial = [...rel.seqs];
  if (!serial.length || !roles.length) return lines;
  for (const s of serial) lines.push(`grant usage, select on sequence ${qn(s)} to ${roles.join(", ")};`);
  return lines;
}

function leastPrivilegeTable(rel, { enableRls }) {
  const lines = [];
  const T = qn(rel);
  if (enableRls) lines.push(`alter table ${T} enable row level security;`);
  const pg = policyGrants(rel);
  const insertRoles = [];
  let any = false;
  for (const r of ["anon", "authenticated"]) {
    const privs = orderPrivs(pg[r]);
    if (privs.length) { any = true; lines.push(`grant ${privs.join(", ")} on table ${T} to ${r};  -- mirrors your RLS policies`); if (pg[r].has("insert")) insertRoles.push(r); }
  }
  if (!any) {
    lines.push(rel.policies.length
      ? `-- policies on ${T} target other roles: anon/authenticated get no grant`
      : `-- TODO: no RLS policy for anon/authenticated yet. Add one (create policy ... on ${T} to authenticated using (...)),\n--       then grant only what it allows, e.g.: grant select on table ${T} to authenticated;`);
  }
  lines.push(`grant select, insert, update, delete on table ${T} to service_role;`);
  insertRoles.push("service_role");
  lines.push(...seqGrantLines(rel, insertRoles));
  return lines;
}

function fnSig(fn, overloaded) {
  return overloaded ? `${qn(fn)}(${fn.sig.join(", ")})` : qn(fn);
}

function mkFinding(check, obj, message, fix, severity) {
  const def = CHECKS[check];
  return {
    check, severity: severity || def.severity, title: def.title, explain: def.explain,
    target: obj.target || (obj.schema ? qn(obj) : ""), kind: obj.kind, file: obj.file, line: obj.line,
    message, fix_sql: fix.join("\n"),
  };
}

const ignored = (obj, check) => obj.ignore && (obj.ignore === true || obj.ignore.has(check));

function analyze(rp, { ignoreTargets = new Set() } = {}) {
  const findings = [];
  const push = (obj, f) => { if (!ignored(obj, f.check) && !ignoreTargets.has(f.target)) findings.push(f); };
  const exposedObj = (o) => rp.exposed.has(o.schema);
  const counts = { tables: 0, views: 0, matviews: 0, functions: 0, sequences: 0 };

  for (const rel of rp.rels.values()) {
    if (!exposedObj(rel)) continue;
    counts[rel.kind === "view" ? "views" : rel.kind === "matview" ? "matviews" : "tables"]++;
    const client = ["anon", "authenticated"].filter((r) => hasAny(effective(rel, r), [...ROW_PRIVS, "truncate"]));
    const anyApi = [...API_ROLES, "public"].some((r) => hasAny(rel.grants.get(r) || new Set(), ROW_PRIVS));
    const T = qn(rel);
    const via = (role) => {
      const s = [...(rel.grantSrc[role] || []), ...(rel.grantSrc.public || [])].find((x) => x.bulk || x.default);
      return s ? ` (via ${s.bulk ? "GRANT ... ON ALL TABLES" : "ALTER DEFAULT PRIVILEGES"} at ${s.file}:${s.line})` : "";
    };

    if (rel.kind === "table" || rel.kind === "partition") {
      if (client.length && !rel.rls) {
        const fix = [`alter table ${T} enable row level security;`];
        fix.push(rel.policies.length
          ? `-- ${rel.policies.length} existing polic${rel.policies.length > 1 ? "ies" : "y"} take effect now`
          : `-- TODO: add a policy (create policy ... on ${T} to authenticated using (...)). Until then anon/authenticated see zero rows.`);
        const pg = policyGrants(rel);
        for (const r of client) {
          const extra = orderPrivs(effective(rel, r)).filter((p) => !pg[r].has(p));
          if (extra.length) fix.push(`-- least privilege (optional): revoke ${extra.join(", ")} on table ${T} from ${r};`);
        }
        const all = new Set(client.flatMap((r) => [...effective(rel, r)]));
        const verbs = [all.has("select") && "readable", hasAny(all, ["insert", "update", "delete", "truncate"]) && "writable"].filter(Boolean).join(" and ");
        const who = client.includes("anon") ? "anyone with the anon key" : "any signed-up user";
        push(rel, mkFinding("grant_without_rls", rel,
          `Granted to ${client.join(", ")}${via(client[0])} but RLS is OFF: every row is ${verbs} by ${who}.`, fix));
      } else if (!anyApi && rel.kind === "table") {
        const fix = leastPrivilegeTable(rel, { enableRls: !rel.rls });
        const note = rel.rls ? "" : " RLS is OFF too: the lazy fix (GRANT ... TO anon) would expose every row. Enable RLS first.";
        push(rel, mkFinding("unreachable_after_oct30", rel,
          `No GRANT to anon/authenticated/service_role. New tables like this will be unreachable (42501) after Oct 30, and on any new project/branch replaying this migration already.${note}`, fix));
      }
      if (anyApi && rel.kind === "table") {
        const missing = [];
        for (const r of API_ROLES) {
          if (!effective(rel, r).has("insert")) continue;
          for (const s of rel.seqs) {
            const e = effective(s, r);
            if (!e.has("usage") && !e.has("update")) missing.push({ r, s });
          }
        }
        if (missing.length) {
          const bySeq = new Map();
          for (const { r, s } of missing) { if (!bySeq.has(s)) bySeq.set(s, []); bySeq.get(s).push(r); }
          const fix = [...bySeq].map(([s, rs]) => `grant usage, select on sequence ${qn(s)} to ${rs.join(", ")};`);
          push(rel, mkFinding("sequence_not_granted", rel,
            `${[...new Set(missing.map((m) => m.r))].join(", ")} can INSERT but not use ${[...bySeq.keys()].map(qn).join(", ")}: inserts fail with 'permission denied for sequence' on new projects/branches.`, fix));
        }
      }
    } else if (rel.kind === "view") {
      if (client.length && !rel.securityInvoker) {
        push(rel, mkFinding("view_bypasses_rls", rel,
          `View granted to ${client.join(", ")}${via(client[0])} without security_invoker: callers see rows the underlying RLS would hide.`,
          [`alter view ${T} set (security_invoker = on);  -- enforce the caller's RLS on the base tables`]));
      } else if (!anyApi) {
        const fix = [];
        if (!rel.securityInvoker) fix.push(`alter view ${T} set (security_invoker = on);  -- otherwise the grant below bypasses RLS`);
        fix.push(`grant select on ${T} to authenticated, service_role;`, `-- add anon only if unauthenticated clients read it: grant select on ${T} to anon;`);
        push(rel, mkFinding("unreachable_after_oct30", rel,
          "View has no GRANT. New views like this will be unreachable (42501) after Oct 30, and on any new project/branch replaying this migration already.", fix));
      }
    } else { // matview / foreign
      const label = rel.kind === "matview" ? "Materialized view" : "Foreign table";
      if (client.length) {
        push(rel, mkFinding("matview_exposed", rel,
          `${label} granted to ${client.join(", ")}${via(client[0])}: RLS can't apply, every row is public to that role.`,
          [`revoke all on ${T} from ${client.join(", ")};`, `-- serve it through a security_invoker view or an RPC that checks auth.uid()`]));
      } else if (!anyApi) {
        push(rel, mkFinding("unreachable_after_oct30", rel,
          `${label} has no GRANT: unreachable (42501) for new ones after Oct 30, and on any new project/branch already.`,
          [`grant select on ${T} to service_role;  -- no RLS possible: keep anon/authenticated off`], "medium"));
      }
    }
  }

  for (const seq of rp.seqs.values()) {
    if (!exposedObj(seq)) continue;
    counts.sequences++;
    if (seq.owner) continue; // covered by its table (sequence_not_granted / unreachable fix)
    const anyApi = [...API_ROLES, "public"].some((r) => hasAny(seq.grants.get(r) || new Set(), ["usage", "select", "update"]));
    if (!anyApi) {
      const f = mkFinding("unreachable_after_oct30", seq,
        "Sequence has no GRANT: nextval() as an API role fails for new sequences after Oct 30, and on any new project/branch already.",
        [`grant usage, select on sequence ${qn(seq)} to service_role;  -- add authenticated only if clients insert rows that use it`]);
      f.severity = "low";
      push(seq, f);
    }
  }

  for (const list of rp.funcs.values()) {
    for (const fn of list) {
      if (!exposedObj(fn) || fn.returnsTrigger) continue;
      counts.functions++;
      const sig = fnSig(fn, list.length > 1);
      const hasExec = (r) => (fn.grants.get(r) || new Set()).has("execute");
      if (fn.definer && (hasExec("anon") || hasExec("public"))) {
        const srcs = [...(fn.grantSrc.anon || []), ...(fn.grantSrc.public || [])];
        const explicit = srcs.find((s) => !s.default);
        let how;
        if (explicit) how = `granted ${explicit.bulk ? "by GRANT ... ON ALL FUNCTIONS " : ""}at ${explicit.file}:${explicit.line}`;
        else if (fn.revokedAnon && hasExec("public")) how = `REVOKE ... FROM anon at ${fn.revokedAnon.file}:${fn.revokedAnon.line} is not enough: anon inherits EXECUTE from PUBLIC`;
        else if (hasExec("public")) how = "no REVOKE ... FROM PUBLIC: Postgres grants EXECUTE to PUBLIC on every new function and anon inherits it (the Oct 30 change does not touch functions)";
        else how = "via Supabase's default privileges on functions in public";
        push(fn, mkFinding("security_definer_anon", fn,
          `SECURITY DEFINER and executable by anon (${how}). Anyone with the anon key calls /rest/v1/rpc/${fn.name} with the owner's rights, bypassing RLS.`,
          [`revoke execute on function ${sig} from public, anon;`, `grant execute on function ${sig} to authenticated, service_role;  -- keep anon only for an intentional public endpoint`]));
      }
      if (fn.definer && !fn.searchPath) {
        push(fn, mkFinding("definer_no_search_path", fn, "SECURITY DEFINER without SET search_path.",
          [`alter function ${sig} set search_path = public, pg_temp;`]));
      }
      if (![...API_ROLES, "public"].some(hasExec)) {
        const f = mkFinding("unreachable_after_oct30", fn,
          "EXECUTE revoked from PUBLIC and never granted to an API role: /rpc calls (and RLS policies that call it) fail with 42501. Fine if it's internal.",
          [`grant execute on function ${sig} to authenticated, service_role;${fn.definer ? "  -- SECURITY DEFINER: don't add anon unless it's a public endpoint" : ""}`]);
        f.severity = "low";
        push(fn, f);
      }
    }
  }

  // Statement-level findings: the lazy fixes.
  const dp = new Map(); // aggregate ALTER DEFAULT PRIVILEGES per file+severity
  for (const ev of rp.events) {
    if (ev.ignore === true || (ev.ignore && ev.ignore.has(ev.check))) continue;
    if (ev.check === "lazy_bulk_grant") {
      const kindWord = ev.target === "rel" ? "TABLES" : "FUNCTIONS";
      const fix = [`revoke ${ev.target === "rel" ? "all" : "execute"} on all ${kindWord.toLowerCase()} in schema ${ev.schemas.map(qi).join(", ")} from ${ev.roles.join(", ")};`];
      if (ev.target === "func") fix.push(`-- then re-grant only the RPCs meant for them, e.g.: grant execute on function public.my_rpc() to authenticated;`);
      let n = 0;
      if (ev.target === "rel") {
        for (const o of ev.covered) {
          if (!rp.rels.has(keyOf(o.schema, o.name)) || !exposedObj(o) || (o.kind !== "table" && o.kind !== "partition")) continue;
          n++;
          const pg = policyGrants(o);
          for (const r of ev.roles.flatMap((x) => (x === "public" ? ["anon", "authenticated"] : [x]))) {
            const privs = orderPrivs(pg[r] || new Set());
            if (privs.length) fix.push(`grant ${privs.join(", ")} on table ${qn(o)} to ${r};  -- what its RLS policies actually use`);
          }
        }
      } else n = ev.covered.filter((o) => (rp.funcs.get(keyOf(o.schema, o.name)) || []).includes(o) && !o.returnsTrigger).length;
      if (!n) continue; // covered nothing that is still exposed
      const f =mkFinding("lazy_bulk_grant", { target: `ALL ${kindWord} IN SCHEMA ${ev.schemas.join(", ")}`, kind: "grant", file: ev.file, line: ev.line },
        `GRANT ${ev.privs.length > 4 ? "ALL" : ev.privs.join(", ").toUpperCase()} ON ALL ${kindWord} ... TO ${ev.roles.join(", ")} hands ${n} existing object(s) to ${ev.roles.length === 1 && ev.roles[0] === "authenticated" ? "every signed-up user" : "anyone with the anon key"}, RLS or not. The lazy fix reopens every hole${ev.target === "rel" ? " (it's Supabase's own rollback snippet: safe only if every table has RLS + correct policies)" : ""}.`,
        fix, ev.severity);
      if (!ignoreTargets.has(f.target)) findings.push(f);
    } else {
      if (!dp.has(ev.file)) dp.set(ev.file, { ...ev, objtypes: new Set(), roles: new Set(), stmts: [] });
      const agg = dp.get(ev.file);
      if (SEVERITY_ORDER[ev.severity] < SEVERITY_ORDER[agg.severity]) agg.severity = ev.severity;
      agg.objtypes.add(ev.objtype); ev.roles.forEach((r) => agg.roles.add(r)); agg.stmts.push(ev);
    }
  }
  for (const agg of dp.values()) {
    const fix = agg.stmts.map((ev) => `alter default privileges${ev.forRoles ? ` for role ${ev.forRoles.map(qi).join(", ")}` : ""}${ev.schemas ? ` in schema ${ev.schemas.map(qi).join(", ")}` : ""} revoke ${ev.objtype === "functions" ? "execute" : ROW_PRIVS.join(", ")} on ${ev.objtype} from ${ev.roles.join(", ")};`);
    fix.push("-- then GRANT per object, in the same migration that creates it (see the other findings)");
    const f = mkFinding("default_privileges_regrant", { target: `DEFAULT PRIVILEGES ON ${[...agg.objtypes].join(", ").toUpperCase()}`, kind: "grant", file: agg.file, line: agg.line },
      `Grants every future ${[...agg.objtypes].map((t) => t.slice(0, -1)).join("/")} to ${[...agg.roles].join(", ")} on creation, before any RLS exists (${agg.stmts.length} statement${agg.stmts.length > 1 ? "s" : ""}).${agg.objtypes.has("tables") ? " This undoes the Oct 30 protection (it's Supabase's own rollback snippet)." : ""}`,
      [...new Set(fix)], agg.severity);
    if (!ignoreTargets.has(f.target)) findings.push(f);
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || String(a.file).localeCompare(String(b.file)) || a.line - b.line);
  return { findings, counts };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
const IGNORE_RE = /supabase-security:\s*ignore(?:[ \t]+([a-z_, \t]+))?/i;

// files: [{ path, sql }] in apply order.
export function lintMigrations(files, { schemas = ["public"], ignore = [] } = {}) {
  const rp = new Replay({ schemas });
  for (const f of files) {
    rp.file = f.path;
    rp.searchPath = ["public"];
    const { toks, comments } = lex(f.sql);
    const stmts = splitStatements(toks);
    const directives = comments.map((cm) => ({ line: cm.line, m: IGNORE_RE.exec(cm.text) })).filter((d) => d.m);
    for (const st of stmts) {
      const last = st[st.length - 1].line;
      rp.ignore = null;
      // A directive applies to the statement that contains it, or else the next one.
      for (const d of directives) {
        if (d.used || d.line > last) continue;
        d.used = true;
        const list = (d.m[1] || "").split(/[\s,]+/).filter(Boolean);
        rp.ignore = list.length ? new Set(list) : true;
      }
      rp.run(st);
    }
  }
  rp.ignore = null;
  const { findings, counts } = analyze(rp, { ignoreTargets: new Set(ignore) });
  const summary = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), { critical: 0, high: 0, medium: 0, low: 0 });
  return { findings, summary, counts, schemas };
}

export function buildFixSql(result, { dir } = {}) {
  const out = [];
  out.push(`-- Proposed by supabase-security v${VERSION} (\`supabase-security migrations\`) on ${new Date().toISOString().slice(0, 10)}`);
  out.push(`-- Least-privilege grants for Supabase's Oct 30, 2026 Data API change. Grants mirror your RLS policies.`);
  out.push(`-- REVIEW EVERY LINE before applying. Test on a branch first (supabase db reset / preview branch).`);
  if (dir) out.push(`-- Source: ${dir}`);
  out.push("");
  const seen = new Set();
  const order = ["lazy_bulk_grant", "default_privileges_regrant"];
  const sorted = [...result.findings].sort((a, b) => {
    const ia = order.includes(a.check) ? 0 : 1, ib = order.includes(b.check) ? 0 : 1;
    return ia - ib || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  });
  for (const f of sorted) {
    const lines = f.fix_sql.split("\n").filter((l) => {
      if (l.startsWith("--")) return true;
      if (seen.has(l)) return false;
      seen.add(l); return true;
    });
    if (!lines.some((l) => !l.startsWith("--"))) { if (!lines.length) continue; }
    out.push(`-- [${f.severity.toUpperCase()}] ${f.target}: ${f.title} (${f.file}:${f.line})`);
    out.push(...lines, "");
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Files + config
// ---------------------------------------------------------------------------
function collectSqlFiles(root) {
  const st = statSync(root);
  if (st.isFile()) return [root];
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith(".") || e.name === "node_modules") continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.toLowerCase().endsWith(".sql")) out.push(p);
    }
  };
  walk(root);
  return out.sort((a, b) => relative(root, a).replace(/\\/g, "/").localeCompare(relative(root, b).replace(/\\/g, "/")));
}

export function schemasFromConfig(dir) {
  for (const cand of [join(dir, "..", "config.toml"), join(dir, "config.toml"), join(dir, "supabase", "config.toml")]) {
    if (!existsSync(cand)) continue;
    const txt = readFileSync(cand, "utf8");
    const sec = /^\s*\[api\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(txt);
    if (!sec) continue;
    const m = /^\s*schemas\s*=\s*\[([\s\S]*?)\]/m.exec(sec[1]);
    if (!m) continue;
    // storage/graphql_public are Supabase-managed and not affected by the Oct 30 change
    const list = [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1]).filter((s) => s !== "graphql_public" && s !== "storage");
    if (list.length) return { schemas: list, from: relative(process.cwd(), cand).replace(/\\/g, "/") };
  }
  return null;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const opts = { dir: null, json: false, fixSql: null, failOn: "high", github: false, schemas: null, ignore: [], color: null };
  const val = (i, a) => (a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[i + 1]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const name = a.split("=")[0];
    const takes = ["--schemas", "--fix-sql", "--fail-on", "--ignore"].includes(name);
    const v = takes ? val(i, a) : null;
    if (takes && !a.includes("=")) i++;
    switch (name) {
      case "--json": opts.json = true; break;
      case "--github": opts.github = true; break;
      case "--no-color": opts.color = false; break;
      case "--color": opts.color = true; break;
      case "--schemas": opts.schemas = String(v || "").split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--fix-sql": opts.fixSql = v; break;
      case "--fail-on": opts.failOn = String(v || "").toLowerCase(); break;
      case "--ignore": opts.ignore = String(v || "").split(",").map((s) => s.trim()).filter(Boolean); break;
      case "-h": case "--help": opts.help = true; break;
      default:
        if (a.startsWith("--")) throw new Error(`Unknown flag ${a}`);
        opts.dir = a;
    }
  }
  if (!["critical", "high", "medium", "low", "never"].includes(opts.failOn)) throw new Error(`--fail-on must be critical|high|medium|low|never (got "${opts.failOn}")`);
  return opts;
}

const HELP = `supabase-security migrations — keyless lint of your SQL migrations for Supabase's Oct 30, 2026 Data API change

Usage:
  npx supabase-security migrations [dir]      dir defaults to supabase/migrations (a single .sql file works too)

Options:
  --schemas public,api   exposed schemas (default: [api].schemas from supabase/config.toml, else public)
  --fix-sql out.sql      write a proposed least-privilege migration
  --fail-on <sev>        exit 1 on findings >= critical|high|medium|low|never (default: high)
  --json                 machine-readable output
  --github               also emit GitHub Actions annotations (::error file=...)
  --ignore a.b,c.d       skip objects (or add "-- supabase-security: ignore [check]" above a statement)
`;

export async function main(argv = process.argv.slice(3)) {
  let opts;
  try { opts = parseArgs(argv); } catch (e) { console.error(e.message); console.error(HELP); return 2; }
  if (opts.help) { console.log(HELP); return 0; }

  let dir = opts.dir || "supabase/migrations";
  if (existsSync(dir) && statSync(dir).isDirectory() && existsSync(join(dir, "supabase", "migrations"))) dir = join(dir, "supabase", "migrations");
  if (!existsSync(dir)) {
    console.error(`No migrations found at ${dir}. Pass the path: npx supabase-security migrations path/to/migrations`);
    return 2;
  }
  const paths = collectSqlFiles(dir);
  if (!paths.length) { console.error(`No .sql files under ${dir}.`); return 2; }
  const cfg = opts.schemas ? null : schemasFromConfig(statSync(dir).isFile() ? dirname(dir) : dir);
  const schemas = opts.schemas || cfg?.schemas || ["public"];
  const files = paths.map((p) => ({ path: relative(process.cwd(), p).replace(/\\/g, "/") || p, sql: readFileSync(p, "utf8") }));
  const result = lintMigrations(files, { schemas, ignore: opts.ignore });
  const failing = opts.failOn === "never" ? [] : result.findings.filter((f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[opts.failOn]);

  let fixPath = null;
  if (opts.fixSql && result.findings.length) {
    writeFileSync(opts.fixSql, buildFixSql(result, { dir: relative(process.cwd(), resolve(dir)).replace(/\\/g, "/") }));
    fixPath = opts.fixSql;
  }

  if (opts.json) {
    console.log(JSON.stringify({
      tool: "supabase-security migrations", version: VERSION, scanned_at: new Date().toISOString(),
      dir: dir.replace(/\\/g, "/"), files: files.length, schemas, schemas_from: cfg?.from || (opts.schemas ? "--schemas" : "default"),
      objects: result.counts, summary: result.summary, fail_on: opts.failOn, failing: failing.length, fix_sql_path: fixPath,
      findings: result.findings,
    }, null, 2));
  } else {
    printText(result, { dir, files, schemas, cfg, opts, failing, fixPath });
  }
  if (opts.github) {
    for (const f of result.findings) {
      const level = f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
      const esc = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
      const escP = (s) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
      console.log(`::${level} file=${escP(f.file)},line=${f.line},title=${escP(`${f.severity.toUpperCase()}: ${f.title}`)}::${esc(`${f.target}: ${f.message}\nFix:\n${f.fix_sql}`)}`);
    }
  }
  return failing.length ? 1 : 0;
}

function printText(result, { dir, files, schemas, cfg, opts, failing, fixPath }) {
  const useColor = opts.color ?? (process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== "0" : (process.stdout.isTTY && !process.env.NO_COLOR));
  const sgr = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
  const bold = sgr("1"), dim = sgr("2"), green = sgr("32");
  const SEV = { critical: sgr("1;37;41"), high: sgr("1;31"), medium: sgr("1;33"), low: sgr("36") };
  const { counts, findings, summary } = result;
  const w = (s = "") => console.log(s);

  w(`${bold("supabase-security migrations")} ${dim(`v${VERSION}`)} ${dim("·")} ${files.length} file${files.length === 1 ? "" : "s"} in ${dir.replace(/\\/g, "/")} ${dim("·")} schemas: ${schemas.join(", ")}${cfg ? dim(` (from ${cfg.from})`) : ""}`);
  w(dim(`${counts.tables} tables · ${counts.views} views · ${counts.matviews} matviews · ${counts.functions} functions · ${counts.sequences} sequences`));
  w();
  if (!findings.length) {
    w(green("✓ Every exposed object has explicit, RLS-backed grants. Ready for Oct 30."));
    return;
  }
  const MAX_FIX_LINES = 6;
  for (const f of findings) {
    const tag = SEV[f.severity](` ${f.severity.toUpperCase()} `.padEnd(10));
    w(`${tag} ${bold(f.target)}  ${dim(`${f.file}:${f.line}`)}`);
    w(`           ${f.message}`);
    const lines = f.fix_sql.split("\n");
    const show = f.severity === "low" ? lines.slice(0, 1) : lines.slice(0, MAX_FIX_LINES);
    for (const l of show) w(`           ${l.startsWith("--") ? dim(l) : green(l)}`);
    if (lines.length > show.length) w(dim(`           … ${lines.length - show.length} more line(s) in --fix-sql`));
    w();
  }
  const parts = ["critical", "high", "medium", "low"].map((s) => (summary[s] ? SEV[s](`${summary[s]} ${s}`) : dim(`0 ${s}`)));
  w(`${bold("Summary:")} ${parts.join(dim(" · "))}   ${dim(`fail-on ${opts.failOn}: ${failing.length ? `${failing.length} failing` : "passing"}`)}`);
  if (fixPath) w(`${bold("Proposed migration written to")} ${fixPath} ${dim("(review before applying)")}`);
  else {
    const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    w(dim(`Write a least-privilege migration: npx supabase-security migrations ${opts.dir ? `${opts.dir} ` : ""}--fix-sql supabase/migrations/${ts}_data_api_grants.sql`));
  }
  w(dim(`Want this done + reviewed for you? ${LANDING}`));
}
