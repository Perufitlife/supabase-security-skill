#!/usr/bin/env node
// Supabase Security Auditor — pure Node.js, no deps.
//
// Usage:
//   SUPABASE_ACCESS_TOKEN=sbp_xxx node audit.js <project-ref>
//   node audit.js <project-ref> --token sbp_xxx --json
//   node audit.js <project-ref> --token sbp_xxx --html report.html
//
// Output: JSON findings to stdout (default) or HTML file.

import { writeFileSync } from "node:fs";

const API = "https://api.supabase.com/v1";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  rls_disabled: {
    severity: "critical",
    title: "RLS disabled on table accessible via anon",
    explain: "Without RLS, anon role with default CRUD grants can read/insert/delete any row.",
  },
  rls_no_policies_with_anon_grants: {
    severity: "low",
    title: "RLS-locked table still has direct anon grants (defense-in-depth)",
    explain: "Currently safe — RLS blocks all access. But if RLS is ever disabled by mistake, data leaks instantly. Best practice: revoke grants too.",
  },
  function_security_definer_anon_executable: {
    severity: "high",
    title: "SECURITY DEFINER function executable by anon",
    explain: "Function runs with creator privileges. If buggy, escalates to admin.",
  },
  default_privileges_not_revoked: {
    severity: "medium",
    title: "Default privileges not revoked from anon/authenticated",
    explain: "New tables you create will be auto-exposed. Supabase enforces this by Oct 30, 2026.",
  },
  storage_bucket_public: {
    severity: "high",
    title: "Storage bucket is public",
    explain: "Anyone can list and download all files in the bucket.",
  },
  auth_signups_enabled_no_confirm: {
    severity: "medium",
    title: "Signups enabled without email confirmation",
    explain: "Anyone can create accounts and bypass email-gated logic.",
  },
};

async function sql(token, ref, query) {
  const r = await fetch(`${API}/projects/${ref}/database/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "supabase-security/0.1",
    },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${await r.text()}`);
  return r.json();
}

async function getProjectMeta(token, ref) {
  const r = await fetch(`${API}/projects/${ref}`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": "supabase-security/0.1" },
  });
  if (!r.ok) return { name: ref, region: "unknown" };
  return r.json();
}

async function getStorageBuckets(token, ref) {
  // Buckets are stored in storage.buckets; query via SQL
  try {
    return await sql(token, ref, "SELECT id, name, public FROM storage.buckets ORDER BY name;");
  } catch {
    return [];
  }
}

async function getAuthConfig(token, ref) {
  const r = await fetch(`${API}/projects/${ref}/config/auth`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": "supabase-security/0.1" },
  });
  if (!r.ok) return null;
  return r.json();
}

async function audit(token, ref) {
  const findings = [];
  const meta = await getProjectMeta(token, ref);

  // 1. Tables: RLS status + policy count + anon grants
  const tables = await sql(
    token,
    ref,
    `SELECT
       c.relname AS table_name,
       c.relrowsecurity AS rls_enabled,
       (SELECT COUNT(*) FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) AS n_policies,
       has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'SELECT') AS anon_select,
       has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'INSERT') AS anon_insert,
       has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'DELETE') AS anon_delete,
       has_table_privilege('authenticated', 'public.'||quote_ident(c.relname), 'SELECT') AS auth_select
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r'
     ORDER BY c.relname;`
  );

  for (const t of tables) {
    if (!t.rls_enabled && (t.anon_select || t.anon_insert || t.anon_delete)) {
      findings.push({
        check: "rls_disabled",
        ...CHECKS.rls_disabled,
        target: t.table_name,
        details: {
          anon_select: t.anon_select,
          anon_insert: t.anon_insert,
          anon_delete: t.anon_delete,
        },
        fix_sql: `ALTER TABLE public.${t.table_name} ENABLE ROW LEVEL SECURITY;`,
      });
    } else if (t.rls_enabled && t.n_policies === 0 && (t.anon_select || t.auth_select)) {
      findings.push({
        check: "rls_no_policies_with_anon_grants",
        ...CHECKS.rls_no_policies_with_anon_grants,
        target: t.table_name,
        details: { policies: 0, anon_select: t.anon_select, auth_select: t.auth_select },
        fix_sql: `-- Optional hardening: revoke direct grants to make leak impossible even if RLS is disabled.\nREVOKE ALL ON public.${t.table_name} FROM anon, authenticated;`,
      });
    }
  }

  // 2. SECURITY DEFINER functions executable by anon
  const funcs = await sql(
    token,
    ref,
    `SELECT
       p.proname AS function_name,
       p.prosecdef AS security_definer,
       pg_get_function_result(p.oid) AS return_type,
       has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute
     FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prosecdef = true;`
  );

  for (const f of funcs) {
    // Trigger functions (return trigger) are not exploitable via PostgREST
    if (f.return_type === "trigger") continue;
    if (f.anon_execute) {
      findings.push({
        check: "function_security_definer_anon_executable",
        ...CHECKS.function_security_definer_anon_executable,
        target: f.function_name,
        details: { returns: f.return_type },
        fix_sql: `REVOKE EXECUTE ON FUNCTION public.${f.function_name} FROM anon;`,
      });
    }
  }

  // 3. Default privileges still grant CRUD on future tables?
  // Supabase tables can be owned by either `postgres` (SQL/CLI migrations) or `supabase_admin` (Dashboard).
  // Check both. ACL string format: anon=arwdDxtm/owner — letters: a=insert r=select w=update d=delete D=truncate x=refs t=trigger m=maintain.
  const defaults = await sql(
    token,
    ref,
    `SELECT defaclrole::regrole::text AS owner_role, defaclacl::text AS acl
     FROM pg_default_acl d
     JOIN pg_namespace n ON n.oid = d.defaclnamespace
     WHERE n.nspname = 'public' AND d.defaclobjtype = 'r';`
  );

  const ownersWithLeak = [];
  for (const ownerRole of ["postgres", "supabase_admin"]) {
    const row = defaults.find((d) => d.owner_role === ownerRole);
    if (!row) {
      // No custom default ACL = system grants apply (Supabase auto-grants CRUD to anon)
      ownersWithLeak.push(ownerRole);
      continue;
    }
    // Look for anon or authenticated still having CRUD letters (a=insert r=select w=update d=delete)
    const m = row.acl.match(/anon=([a-zA-Z]*)/);
    const auth = row.acl.match(/authenticated=([a-zA-Z]*)/);
    const hasCrud = (s) => s && /[arwd]/.test(s.replace(/[DxtmU]/g, ""));
    if (hasCrud(m && m[1]) || hasCrud(auth && auth[1])) {
      ownersWithLeak.push(ownerRole);
    }
  }
  if (ownersWithLeak.length > 0) {
    const fixes = [];
    if (ownersWithLeak.includes("postgres")) {
      fixes.push(
        `-- Tables created via SQL editor / migrations / CLI (owner = postgres):`,
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon, authenticated, service_role;`,
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM anon, authenticated, service_role;`,
      );
    }
    if (ownersWithLeak.includes("supabase_admin")) {
      fixes.push(
        ``,
        `-- Tables created via Supabase Dashboard (owner = supabase_admin) cannot be revoked from postgres role.`,
        `-- Toggle this in: Dashboard -> Project Settings -> Data API -> "Automatically expose new tables" = OFF`,
        `-- Or via Management API: PATCH /v1/projects/${ref}/postgrest with {"db_extra_search_path":"public", ...} (see docs).`,
      );
    }
    findings.push({
      check: "default_privileges_not_revoked",
      ...CHECKS.default_privileges_not_revoked,
      target: `schema:public (leaky owners: ${ownersWithLeak.join(", ")})`,
      details: { leaky_owner_roles: ownersWithLeak, note: "Supabase enforces revoke for all projects by Oct 30, 2026." },
      fix_sql: fixes.join("\n"),
    });
  }

  // 4. Public storage buckets
  const buckets = await getStorageBuckets(token, ref);
  for (const b of buckets) {
    if (b.public) {
      findings.push({
        check: "storage_bucket_public",
        ...CHECKS.storage_bucket_public,
        target: `bucket:${b.name}`,
        details: { id: b.id },
        fix_sql: `UPDATE storage.buckets SET public = false WHERE id = '${b.id}'; -- only if you don't need public CDN-style access`,
      });
    }
  }

  // 5. Auth config: signups + email confirmation
  const authCfg = await getAuthConfig(token, ref);
  if (authCfg && authCfg.disable_signup === false && authCfg.mailer_autoconfirm === true) {
    findings.push({
      check: "auth_signups_enabled_no_confirm",
      ...CHECKS.auth_signups_enabled_no_confirm,
      target: "auth:signups",
      details: { signups_enabled: true, autoconfirm: true },
      fix_sql: `-- Update via Supabase dashboard: Auth → Providers → Email → enable "Confirm email"\n-- Or via Management API: PATCH /v1/projects/${ref}/config/auth { "mailer_autoconfirm": false }`,
    });
  }

  // Sort findings by severity
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    project_ref: ref,
    project_name: meta.name || ref,
    region: meta.region || "unknown",
    scanned_at: new Date().toISOString(),
    scanned_by: "supabase-security v0.1",
    summary,
    n_tables_scanned: tables.length,
    n_functions_scanned: funcs.length,
    n_buckets_scanned: buckets.length,
    findings,
  };
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.error(`Usage: SUPABASE_ACCESS_TOKEN=sbp_xxx supabase-security <project-ref> [--json|--html report.html]`);
    process.exit(1);
  }

  const ref = args[0];
  const token = process.env.SUPABASE_ACCESS_TOKEN || (args.includes("--token") ? args[args.indexOf("--token") + 1] : null);
  if (!token) {
    console.error("Error: provide SUPABASE_ACCESS_TOKEN env var or --token flag (Personal Access Token from supabase.com/dashboard/account/tokens)");
    process.exit(1);
  }

  const result = await audit(token, ref);

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` || import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}

export { audit };
