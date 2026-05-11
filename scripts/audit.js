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
  realtime_publication_no_rls: {
    severity: "critical",
    title: "Table in supabase_realtime publication WITHOUT RLS",
    explain: "Realtime sends row changes over WebSockets to anyone subscribed with the anon key. RLS policies are checked, but with RLS disabled there's nothing to check. Every INSERT/UPDATE is broadcast.",
  },
  anonymous_signins_enabled: {
    severity: "high",
    title: "Anonymous sign-ins enabled",
    explain: "Anyone can become an 'authenticated' user without email verification. Defeats `auth.uid() IS NOT NULL` style RLS policies.",
  },
  weak_password_policy: {
    severity: "medium",
    title: "Weak password policy",
    explain: "Minimum length below 8 characters. Use at least 8 + complexity requirements (digits/symbols).",
  },
  no_captcha_on_auth: {
    severity: "medium",
    title: "No CAPTCHA on auth endpoints",
    explain: "Without CAPTCHA, signup/login forms can be brute-forced or spammed by bots.",
  },
  function_no_search_path: {
    severity: "medium",
    title: "SECURITY DEFINER function without SET search_path",
    explain: "Function with mutable search_path can be hijacked: an attacker with CREATE on any schema in the path can shadow built-in functions and run arbitrary code as the function owner.",
  },
};

const UA = "supabase-security/0.3";

async function sql(token, ref, query) {
  const r = await fetch(`${API}/projects/${ref}/database/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": UA,
    },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${await r.text()}`);
  return r.json();
}

async function getProjectMeta(token, ref) {
  const r = await fetch(`${API}/projects/${ref}`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
  });
  if (!r.ok) return { name: ref, region: "unknown" };
  return r.json();
}

async function getStorageBuckets(token, ref) {
  try {
    return await sql(token, ref, "SELECT id, name, public FROM storage.buckets ORDER BY name;");
  } catch {
    return [];
  }
}

async function getAuthConfig(token, ref) {
  const r = await fetch(`${API}/projects/${ref}/config/auth`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
  });
  if (!r.ok) return null;
  return r.json();
}

// Pull project anon API key for active probing.
async function getAnonKey(token, ref) {
  try {
    const r = await fetch(`${API}/projects/${ref}/api-keys?reveal=true`, {
      headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
    });
    if (!r.ok) return null;
    const keys = await r.json();
    const anon = Array.isArray(keys) ? keys.find((k) => k.name === "anon") : null;
    return anon?.api_key || null;
  } catch {
    return null;
  }
}

// Active probe: hit PostgREST with the anon key to PROVE the leak (not just infer it from pg_class).
// Returns { confirmed, status, sample } so reports show evidence, not assumption.
async function probeAnonAccess(supabaseUrl, anonKey, tableName) {
  try {
    const r = await fetch(`${supabaseUrl}/rest/v1/${encodeURIComponent(tableName)}?limit=1`, {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        "User-Agent": UA,
      },
    });
    const status = r.status;
    if (!r.ok) {
      return { confirmed: false, status, reason: status === 401 ? "anon blocked" : status === 404 ? "table not in PostgREST schema" : `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed)) {
        row_count = parsed.length;
        if (parsed[0] && typeof parsed[0] === "object") columns = Object.keys(parsed[0]);
      }
    } catch { /* non-JSON */ }
    return {
      confirmed: true,
      status,
      sample: { row_count, columns: columns.slice(0, 8), bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}

async function audit(token, ref, opts = {}) {
  const { activeProbe = true } = opts;
  const findings = [];
  const meta = await getProjectMeta(token, ref);
  const supabaseUrl = `https://${ref}.supabase.co`;
  const anonKey = activeProbe ? await getAnonKey(token, ref) : null;
  const probeAvailable = !!anonKey;

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
      const finding = {
        check: "rls_disabled",
        ...CHECKS.rls_disabled,
        target: t.table_name,
        details: {
          anon_select: t.anon_select,
          anon_insert: t.anon_insert,
          anon_delete: t.anon_delete,
        },
        fix_sql: `ALTER TABLE public.${t.table_name} ENABLE ROW LEVEL SECURITY;`,
      };
      if (probeAvailable && t.anon_select) {
        finding.probe = await probeAnonAccess(supabaseUrl, anonKey, t.table_name);
      }
      findings.push(finding);
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

  // 2. SECURITY DEFINER functions: executable-by-anon AND missing search_path
  const funcs = await sql(
    token,
    ref,
    `SELECT
       p.proname AS function_name,
       p.prosecdef AS security_definer,
       pg_get_function_result(p.oid) AS return_type,
       has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
       p.proconfig AS config
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
    // SECURITY DEFINER without SET search_path = path-injection vector
    const hasSearchPath = Array.isArray(f.config) && f.config.some((c) => typeof c === "string" && c.toLowerCase().startsWith("search_path="));
    if (!hasSearchPath) {
      findings.push({
        check: "function_no_search_path",
        ...CHECKS.function_no_search_path,
        target: f.function_name,
        details: { returns: f.return_type, current_config: f.config },
        fix_sql: `ALTER FUNCTION public.${f.function_name} SET search_path = public, pg_temp;`,
      });
    }
  }

  // 2b. Realtime publication: tables exposed via supabase_realtime WebSocket
  let realtimeTables = [];
  try {
    realtimeTables = await sql(
      token,
      ref,
      `SELECT tablename FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public';`
    );
  } catch { /* publication may not exist */ }
  const tableRlsMap = new Map(tables.map((t) => [t.table_name, t.rls_enabled]));
  for (const rt of realtimeTables) {
    const rls = tableRlsMap.get(rt.tablename);
    if (rls === false) {
      const finding = {
        check: "realtime_publication_no_rls",
        ...CHECKS.realtime_publication_no_rls,
        target: rt.tablename,
        details: { in_publication: "supabase_realtime", rls_enabled: false },
        fix_sql: `ALTER TABLE public.${rt.tablename} ENABLE ROW LEVEL SECURITY;\n-- Or remove from publication: ALTER PUBLICATION supabase_realtime DROP TABLE public.${rt.tablename};`,
      };
      if (probeAvailable) {
        finding.probe = await probeAnonAccess(supabaseUrl, anonKey, rt.tablename);
      }
      findings.push(finding);
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

  // 5. Auth config — multiple checks
  const authCfg = await getAuthConfig(token, ref);
  if (authCfg) {
    if (authCfg.disable_signup === false && authCfg.mailer_autoconfirm === true) {
      findings.push({
        check: "auth_signups_enabled_no_confirm",
        ...CHECKS.auth_signups_enabled_no_confirm,
        target: "auth:signups",
        details: { signups_enabled: true, autoconfirm: true },
        fix_sql: `-- Dashboard: Auth -> Providers -> Email -> "Confirm email" = ON\n-- API: PATCH /v1/projects/${ref}/config/auth body {"mailer_autoconfirm": false}`,
      });
    }
    if (authCfg.external_anonymous_users_enabled === true) {
      findings.push({
        check: "anonymous_signins_enabled",
        ...CHECKS.anonymous_signins_enabled,
        target: "auth:anonymous",
        details: { external_anonymous_users_enabled: true },
        fix_sql: `-- Dashboard: Auth -> Providers -> Anonymous Sign-Ins = OFF\n-- API: PATCH /v1/projects/${ref}/config/auth body {"external_anonymous_users_enabled": false}`,
      });
    }
    if (typeof authCfg.password_min_length === "number" && authCfg.password_min_length < 8) {
      findings.push({
        check: "weak_password_policy",
        ...CHECKS.weak_password_policy,
        target: "auth:password",
        details: { password_min_length: authCfg.password_min_length, password_required_characters: authCfg.password_required_characters },
        fix_sql: `-- Dashboard: Auth -> Providers -> Email -> "Minimum password length" >= 8\n-- API: PATCH /v1/projects/${ref}/config/auth body {"password_min_length": 12, "password_required_characters": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"}`,
      });
    }
    if (authCfg.security_captcha_enabled === false && authCfg.disable_signup === false) {
      findings.push({
        check: "no_captcha_on_auth",
        ...CHECKS.no_captcha_on_auth,
        target: "auth:captcha",
        details: { security_captcha_enabled: false },
        fix_sql: `-- Dashboard: Auth -> Settings -> Enable CAPTCHA (hCaptcha or Cloudflare Turnstile)\n-- API: PATCH /v1/projects/${ref}/config/auth body {"security_captcha_enabled": true, "security_captcha_provider": "hcaptcha", "security_captcha_secret": "<your_secret>"}`,
      });
    }
  }

  // Sort findings by severity
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const probed = findings.filter((f) => f.probe).length;
  const confirmed = findings.filter((f) => f.probe?.confirmed).length;

  return {
    project_ref: ref,
    project_name: meta.name || ref,
    region: meta.region || "unknown",
    scanned_at: new Date().toISOString(),
    scanned_by: "supabase-security v0.3",
    active_probe: { enabled: probeAvailable, probed, confirmed },
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
  if (args.includes("--help") || args.includes("-h") || (args.length === 0)) {
    console.error(`Usage:
  Full audit (needs Personal Access Token):
    SUPABASE_ACCESS_TOKEN=sbp_xxx supabase-security <project-ref> [--json|--html report.html] [--no-probe]

  Keyless discover (parses local repo, probes only with public anon key — no admin):
    supabase-security --discover [path]            # path defaults to cwd
    supabase-security --discover . --json
    supabase-security --discover . --html discover-report.html

--no-probe    skip the active anon probe (default ON in full mode)
--discover    static repo scan + anon-only probe; no PAT required`);
    process.exit(1);
  }

  // --discover mode (v0.4): no PAT required, parses repo + probes anonymously.
  if (args.includes("--discover")) {
    const { discover } = await import("./discover.js");
    const idx = args.indexOf("--discover");
    const path = args[idx + 1] && !args[idx + 1].startsWith("--") ? args[idx + 1] : process.cwd();
    const result = await discover({ root: path });

    const htmlIdx = args.indexOf("--html");
    if (htmlIdx !== -1) {
      const out = args[htmlIdx + 1] || "discover-report.html";
      const { renderHtml } = await import("./report.js");
      writeFileSync(out, renderHtml(result));
      console.error(`Discover report written to ${out}`);
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const ref = args[0];
  const token = process.env.SUPABASE_ACCESS_TOKEN || (args.includes("--token") ? args[args.indexOf("--token") + 1] : null);
  if (!token) {
    console.error("Error: provide SUPABASE_ACCESS_TOKEN env var or --token flag (Personal Access Token from supabase.com/dashboard/account/tokens)");
    console.error("\nTip: try --discover for a keyless scan of your local repo:");
    console.error("  supabase-security --discover .");
    process.exit(1);
  }
  const activeProbe = !args.includes("--no-probe");

  const result = await audit(token, ref, { activeProbe });

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
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

export { audit, sql, getAnonKey, probeAnonAccess, main };
