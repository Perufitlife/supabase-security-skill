#!/usr/bin/env node
// Supabase Security Auditor — KEYLESS DISCOVER MODE (v0.2).
//
// Parses the user's repo statically (migrations + .ts/.js source) to figure out
// which tables, buckets, and RPC functions the app actually uses, then probes
// each one anonymously via the public anon key. No PAT, no admin access.
//
// Triggered by `supabase-security --discover [path]` (path defaults to cwd).
//
// Why: u/inlined (Firebase, Google) suggested making this a fully static agentic
// skill so users never have to expose backend creds. This is the implementation.

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Patterns to extract Supabase usage from source files.
const PATTERNS = {
  // Table refs: .from('users'), .from("users")
  table: /\.from\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g,
  // RPC fn refs: .rpc('fn_name', ...)
  rpc: /\.rpc\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g,
  // Storage bucket refs: .storage.from('bucket_name')
  bucket: /\.storage\.from\(\s*['"`]([a-zA-Z0-9._-]+)['"`]/g,
  // Project URL + anon key from .env / config files
  projectUrl: /https?:\/\/([a-z0-9-]+)\.supabase\.(co|in)/i,
  // anon JWT (role:anon)
  anonKey: /(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+)/g,
  // Migrations: CREATE TABLE foo (...)
  createTable: /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["`]?([a-zA-Z_][a-zA-Z0-9_]*)["`]?/gi,
  // ALTER TABLE foo ENABLE ROW LEVEL SECURITY
  enableRls: /ALTER\s+TABLE\s+(?:public\.)?["`]?([a-zA-Z_][a-zA-Z0-9_]*)["`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi,
  // CREATE POLICY ... ON foo
  createPolicy: /CREATE\s+POLICY\s+\S+\s+ON\s+(?:public\.)?["`]?([a-zA-Z_][a-zA-Z0-9_]*)["`]?/gi,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", ".turbo",
  "coverage", ".cache", ".vercel", "__pycache__"
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
  ".sql", ".env", ".env.local", ".env.example", ".env.production"
]);

function walk(dir, files = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, files);
    } else {
      const lower = e.name.toLowerCase();
      const hasExt = [...SCAN_EXTENSIONS].some(x => lower.endsWith(x));
      if (hasExt || lower.startsWith(".env")) files.push(p);
    }
  }
  return files;
}

function readSafe(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

export function staticScan(root) {
  const files = walk(root);
  const findings = {
    projectRef: null,
    projectUrl: null,
    anonKey: null,
    serviceRoleKeyLeak: null,
    tables: new Set(),
    rpcs: new Set(),
    buckets: new Set(),
    rlsEnabledTables: new Set(),
    policiedTables: new Set(),
    createdTables: new Set(),
    sourceFiles: 0,
    migrationFiles: 0,
    rootDir: root,
  };

  for (const file of files) {
    const content = readSafe(file);
    if (!content) continue;
    const lower = file.toLowerCase();
    const isSql = lower.endsWith(".sql");
    const isEnv = lower.includes(".env");
    if (isSql) findings.migrationFiles++;
    else findings.sourceFiles++;

    // Project URL
    if (!findings.projectUrl) {
      const m = PATTERNS.projectUrl.exec(content);
      if (m) {
        findings.projectUrl = m[0];
        findings.projectRef = m[1];
      }
    }

    // anon / service_role keys (env files only — we don't want to chase false positives)
    if (isEnv) {
      const keys = content.matchAll(PATTERNS.anonKey);
      for (const km of keys) {
        try {
          const parts = km[1].split(".");
          const payload = JSON.parse(Buffer.from(parts[1] + "==", "base64").toString());
          if (payload.role === "anon" && !findings.anonKey) {
            findings.anonKey = km[1];
          } else if (payload.role === "service_role") {
            findings.serviceRoleKeyLeak = { file: relative(root, file), key_preview: km[1].slice(0, 32) + "..." };
          }
        } catch {}
      }
    }

    // Source-side references
    for (const m of content.matchAll(PATTERNS.table)) findings.tables.add(m[1]);
    for (const m of content.matchAll(PATTERNS.rpc)) findings.rpcs.add(m[1]);
    for (const m of content.matchAll(PATTERNS.bucket)) findings.buckets.add(m[1]);

    // Migration-derived knowledge
    if (isSql) {
      for (const m of content.matchAll(PATTERNS.createTable)) findings.createdTables.add(m[1]);
      for (const m of content.matchAll(PATTERNS.enableRls)) findings.rlsEnabledTables.add(m[1]);
      for (const m of content.matchAll(PATTERNS.createPolicy)) findings.policiedTables.add(m[1]);
    }
  }

  return {
    ...findings,
    tables: [...findings.tables],
    rpcs: [...findings.rpcs],
    buckets: [...findings.buckets],
    rlsEnabledTables: [...findings.rlsEnabledTables],
    policiedTables: [...findings.policiedTables],
    createdTables: [...findings.createdTables],
  };
}

// Probe a table with the anon key. Distinguishes:
//   200 + non-empty body → DATA LEAK CONFIRMED (RLS allows public read)
//   200 + []             → table exists but RLS blocks all rows (safe)
//   401/403/404          → blocked or doesn't exist
async function probeTable(projectUrl, anonKey, table) {
  try {
    const r = await fetch(`${projectUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
      method: "GET",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
      },
    });
    const body = await r.text();
    let rowCount = 0;
    if (r.status === 200) {
      try { rowCount = JSON.parse(body).length || 0; } catch {}
    }
    return {
      status: r.status,
      table_exists: r.status === 200,
      rls_blocking: r.status === 200 && rowCount === 0,
      leaks_data: r.status === 200 && rowCount > 0,
      body_preview: body.slice(0, 120),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

// Probe a bucket. 200 + non-empty array → bucket is public AND has objects.
async function probeBucket(projectUrl, anonKey, bucket) {
  try {
    const r = await fetch(`${projectUrl}/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ prefix: "", limit: 1 }),
    });
    const body = await r.text();
    let listed = 0;
    if (r.status === 200) {
      try { listed = JSON.parse(body).length || 0; } catch {}
    }
    return {
      status: r.status,
      bucket_exists: r.status === 200,
      listable_by_anon: r.status === 200 && listed > 0,
      body_preview: body.slice(0, 120),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

// Probe an RPC. 200 = executed successfully as anon (REAL exposure).
// 404 with PGRST202 message = function exists but anon lacks EXECUTE (safe).
// 400 = function exists, signature mismatch — anon CAN call it (exposure).
async function probeRpc(projectUrl, anonKey, fn) {
  try {
    const r = await fetch(`${projectUrl}/rest/v1/rpc/${encodeURIComponent(fn)}`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    const body = await r.text();
    // 404 + "Could not find" or "PGRST202" = function not exposed to anon (safe)
    const notExposed = r.status === 404 && /PGRST202|Could not find/i.test(body);
    return {
      status: r.status,
      callable_by_anon: !notExposed && (r.status === 200 || r.status === 400),
      executed_successfully: r.status === 200,
      body_preview: body.slice(0, 200),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

export async function discover({ root = process.cwd(), projectUrl = null, anonKey = null } = {}) {
  const scan = staticScan(root);

  const effectiveUrl = projectUrl || scan.projectUrl;
  const effectiveKey = anonKey || scan.anonKey;

  const findings = [];

  // Static-only finding: service_role key in .env files
  if (scan.serviceRoleKeyLeak) {
    findings.push({
      check: "service_role_key_in_env_committed",
      severity: "critical",
      title: "service_role key found in .env file (verify it's gitignored)",
      explain: "If this file is tracked by git, the key bypasses RLS and grants admin access. Rotate immediately and add to .gitignore.",
      target: scan.serviceRoleKeyLeak.file,
      details: scan.serviceRoleKeyLeak,
      fix_sql: `-- 1. https://supabase.com/dashboard/project/${scan.projectRef || '<ref>'}/settings/api -> Generate new service_role key
-- 2. Update env vars wherever deployed (Vercel/Railway/etc)
-- 3. echo '.env' >> .gitignore && git rm --cached .env && git commit -m "Stop tracking .env"`,
    });
  }

  // Static-only: tables created without ENABLE ROW LEVEL SECURITY
  for (const t of scan.createdTables) {
    if (!scan.rlsEnabledTables.includes(t)) {
      findings.push({
        check: "migration_missing_enable_rls",
        severity: "high",
        title: `Migration creates \`${t}\` but never enables RLS`,
        explain: "Public anon role has SELECT/INSERT/UPDATE/DELETE on new tables by default (via API). Without RLS, anyone with the anon key reads/writes every row.",
        target: t,
        fix_sql: `ALTER TABLE public.${t} ENABLE ROW LEVEL SECURITY;\n-- Then add policies, e.g.:\nCREATE POLICY "${t}_select_own" ON public.${t} FOR SELECT USING (auth.uid() = user_id);`,
      });
    }
  }

  // Static-only: RLS enabled but no policies = locked DOWN (false-positive guard)
  for (const t of scan.rlsEnabledTables) {
    if (!scan.policiedTables.includes(t)) {
      findings.push({
        check: "rls_enabled_no_policies",
        severity: "low",
        title: `RLS enabled on \`${t}\` but no policies defined — table is fully blocked`,
        explain: "This is safe (no anon access) but probably not intended. Either drop RLS or add policies. Common dev mistake.",
        target: t,
        fix_sql: `-- Define the access policy you want, or drop RLS:\n-- CREATE POLICY "${t}_read_all" ON public.${t} FOR SELECT USING (true);`,
      });
    }
  }

  // Active probes — only if we have a project URL + anon key
  const probes = { tables: [], buckets: [], rpcs: [] };
  if (effectiveUrl && effectiveKey) {
    for (const t of scan.tables) {
      const p = await probeTable(effectiveUrl, effectiveKey, t);
      probes.tables.push({ table: t, ...p });
      if (p.leaks_data) {
        findings.push({
          check: "table_leaks_via_anon",
          severity: "critical",
          title: `Table \`${t}\` returns rows to anonymous callers`,
          explain: "Anonymous probe with the public anon key returned actual row data. Either RLS is disabled, or a policy allows public read. This is a confirmed leak.",
          target: t,
          details: { http_status: p.status, body_preview: p.body_preview },
          fix_sql: `-- Inspect current policies:\nSELECT * FROM pg_policies WHERE tablename = '${t}';\n-- If unintended, lock down:\nALTER TABLE public.${t} ENABLE ROW LEVEL SECURITY;\n-- And restrict access:\nDROP POLICY IF EXISTS "${t}_public_read" ON public.${t};\nCREATE POLICY "${t}_authenticated_read" ON public.${t} FOR SELECT TO authenticated USING (true);`,
          probe: { confirmed: true },
        });
      }
    }
    for (const b of scan.buckets) {
      const p = await probeBucket(effectiveUrl, effectiveKey, b);
      probes.buckets.push({ bucket: b, ...p });
      if (p.listable_by_anon) {
        findings.push({
          check: "bucket_listable_by_anon",
          severity: "high",
          title: `Storage bucket \`${b}\` is listable by anon (returned filenames)`,
          explain: "Anonymous LIST returned at least one filename. Bucket is effectively public — anyone can enumerate objects.",
          target: b,
          details: { http_status: p.status, body_preview: p.body_preview },
          fix_sql: `UPDATE storage.buckets SET public = false WHERE id = '${b}';\n-- Then add a SELECT policy on storage.objects to control read access:\nCREATE POLICY "${b}_owner_read" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = '${b}' AND owner = auth.uid());`,
          probe: { confirmed: true },
        });
      }
    }
    for (const fn of scan.rpcs) {
      const p = await probeRpc(effectiveUrl, effectiveKey, fn);
      probes.rpcs.push({ fn, ...p });
      if (p.executed_successfully) {
        findings.push({
          check: "rpc_executes_for_anon",
          severity: "critical",
          title: `Function \`${fn}\` executed successfully for anonymous caller`,
          explain: "Anonymous POST to /rpc returned 200. The function actually ran as anon. If SECURITY DEFINER, it ran with the owner's privileges — anon just got admin-flavored output.",
          target: fn,
          details: { http_status: p.status, body_preview: p.body_preview },
          fix_sql: `REVOKE EXECUTE ON FUNCTION public.${fn}() FROM anon, public;\nGRANT EXECUTE ON FUNCTION public.${fn}() TO authenticated;`,
          probe: { confirmed: true },
        });
      } else if (p.callable_by_anon) {
        findings.push({
          check: "rpc_callable_signature_mismatch",
          severity: "medium",
          title: `Function \`${fn}\` is reachable by anon (signature mismatch on probe)`,
          explain: "Anonymous POST returned 400 — the function exists and anon has EXECUTE, the probe just didn't match the argument signature. With the right args, anon could call it.",
          target: fn,
          details: { http_status: p.status, body_preview: p.body_preview },
          fix_sql: `REVOKE EXECUTE ON FUNCTION public.${fn} FROM anon, public;\nGRANT EXECUTE ON FUNCTION public.${fn} TO authenticated;`,
          probe: { reachable: true },
        });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    mode: "discover",
    scanned_at: new Date().toISOString(),
    scanned_by: "supabase-security v0.4 (discover)",
    root_dir: root,
    project_ref: scan.projectRef,
    project_url: effectiveUrl,
    has_anon_key: !!effectiveKey,
    files_scanned: { source: scan.sourceFiles, migrations: scan.migrationFiles },
    references_found: {
      tables: scan.tables,
      rpcs: scan.rpcs,
      buckets: scan.buckets,
      migrations_created: scan.createdTables,
      migrations_rls_enabled: scan.rlsEnabledTables,
      migrations_with_policies: scan.policiedTables,
    },
    probes,
    summary,
    findings,
  };
}
