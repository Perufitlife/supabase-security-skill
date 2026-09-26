// POST /functions/v1/oct30-check — the free Oct 30 check.
// Reads a public GitHub repo's supabase/migrations (no credentials), runs the supabase-security linter,
// answers with a summary for the page and emails the full report. Saves the lead either way.
import { lintMigrations, buildFixSql } from "../_shared/migrations.js";
import { fetchMigrations, schemasFromToml, parseRepoUrl } from "../_shared/repo.ts";
import { clientIp, clip, cors, db, json, originAllowed, RENZO, sha256hex, unsubUrls } from "../_shared/util.ts";
import { budgetLeft, send } from "../_shared/mail.ts";
import { alertEmail, CheckResult, lightOf, noRepoEmail, plainLines, reportEmail } from "../_shared/emails.ts";

const RATE = { perIpHour: 6, perEmailDay: 5 };
const DISPOSABLE = /@(mailinator|guerrillamail|10minutemail|tempmail|temp-mail|yopmail|trashmail|sharklasers|getnada|dispostable|maildrop|throwawaymail|fakeinbox|mohmal|emailondeck|mintemail)\./i;

async function hasMx(domain: string): Promise<boolean> {
  for (const type of ["MX", "A"]) {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, { headers: { accept: "application/dns-json" } });
      const j = await r.json();
      if (j.Status === 0 && Array.isArray(j.Answer) && j.Answer.length) return true;
      if (j.Status === 3) return false; // NXDOMAIN
    } catch { return true; } // DNS provider down: don't block a real person
  }
  return false;
}

Deno.serve(async (req) => {
  const h = cors(req);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
  if (req.method !== "POST") return json({ ok: false, error: "POST only" }, 405, h);
  if (!originAllowed(req)) return json({ ok: false, error: "origin not allowed" }, 403, h);
  const t0 = Date.now();

  let b: any;
  try { b = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400, h); }

  // Honeypot: real people never see this field. Pretend success, store nothing personal.
  if (b.website || b.company_url) {
    await db().from("oct30_events").insert({ tipo: "bot_blocked", page: clip(b.page, 200), meta: { why: "honeypot" } });
    return json({ ok: true, status: "queued", emailed: true }, 200, h);
  }

  const email = clip(b.email, 200).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(email) || DISPOSABLE.test(email)) return json({ ok: false, error: "Please use a real email address: the report goes there." }, 400, h);
  if (b.consent !== true) return json({ ok: false, error: "Please tick the box so we can email you the report." }, 400, h);
  const rol = ["owner", "dev", "agency"].includes(b.role) ? b.role : "owner";
  const noRepo = b.no_repo === true || !String(b.repo ?? "").trim();
  const repoIn = clip(b.repo, 300);
  if (!noRepo && !parseRepoUrl(repoIn)) return json({ ok: false, error: "That doesn't look like a GitHub repo link. Paste something like https://github.com/you/your-app" }, 400, h);

  const salt = Deno.env.get("OCT30_IP_SALT") ?? "oct30";
  const ipHash = (await sha256hex(`${salt}:${clientIp(req)}`)).slice(0, 32);
  const emailHash = (await sha256hex(`${salt}:${email}`)).slice(0, 32);
  const hourAgo = new Date(Date.now() - 36e5).toISOString(), dayAgo = new Date(Date.now() - 864e5).toISOString();
  const [{ count: ipCount }, { count: emCount }] = await Promise.all([
    db().from("oct30_checks").select("id", { count: "exact", head: true }).eq("ip_hash", ipHash).gte("created_at", hourAgo),
    db().from("oct30_checks").select("id", { count: "exact", head: true }).eq("email_hash", emailHash).gte("created_at", dayAgo),
  ]);
  if ((ipCount ?? 0) >= RATE.perIpHour || (emCount ?? 0) >= RATE.perEmailDay) {
    return json({ ok: false, error: "Too many checks in a short time. Try again in an hour, or run it locally: npx supabase-security migrations" }, 429, h);
  }
  if (!(await hasMx(email.split("@")[1]))) return json({ ok: false, error: "That email domain can't receive mail. Check for a typo?" }, 400, h);

  // ---- lead (one row per email)
  const utm = typeof b.utm === "object" && b.utm ? Object.fromEntries(Object.entries(b.utm).slice(0, 8).map(([k, v]) => [clip(k, 30), clip(v, 120)])) : {};
  const isTest = /\+oct30test\d*@/i.test(email);
  const { data: existing } = await db().from("oct30_leads").select("*").eq("email", email).maybeSingle();
  const base = {
    email, rol, repo_url: noRepo ? null : repoIn, stack: clip(b.stack, 120) || null, descripcion: clip(b.description, 1000) || null,
    fuente: clip(b.source ?? utm.utm_source ?? "", 60) || "landing", utm, referrer: clip(b.referrer, 300) || null,
    ip_hash: ipHash, consent: true, is_test: isTest || existing?.is_test || false, unsubscribed: false,
    checks_count: (existing?.checks_count ?? 0) + 1, updated_at: new Date().toISOString(),
  };
  const { data: lead, error: le } = existing
    ? await db().from("oct30_leads").update(base).eq("id", existing.id).select("*").single()
    : await db().from("oct30_leads").insert(base).select("*").single();
  if (le || !lead) return json({ ok: false, error: "Couldn't save your request. Please try again." }, 500, h);

  // ---- the check
  let status: string, result: any = null, web: any = {};
  if (noRepo) {
    status = "no_repo";
    result = { reason: "no_repo", stack: base.stack, descripcion: base.descripcion };
  } else {
    const f = await fetchMigrations(repoIn);
    if (!f.ok) {
      status = f.reason === "no_migrations" ? "no_migrations" : f.reason === "timeout" || f.reason === "error" ? "repo_error" : "repo_unreadable";
      result = { reason: status, detail: f.detail ?? null, repo: repoIn, branch: f.branch ?? null };
    } else {
      const schemas = schemasFromToml(f.configToml) ?? ["public"];
      const lint = lintMigrations(f.files!, { schemas });
      let fixSql = lint.findings.length ? buildFixSql(lint, { dir: f.root }) : "";
      let truncated = false;
      if (fixSql.length > 14000) { fixSql = fixSql.slice(0, 14000).replace(/\n[^\n]*$/, "") + "\n-- …"; truncated = true; }
      const findings = lint.findings.map((x: any) => ({ severity: x.severity, check: x.check, title: x.title, target: x.target, file: x.file, line: x.line, message: x.message }));
      const r: CheckResult = {
        repo: `https://github.com/${f.owner}/${f.repo}`, branch: f.branch!, root: f.root!, files: f.files!.length, schemas,
        counts: lint.counts, summary: lint.summary, light: lightOf(findings), findings: findings.slice(0, 60), fixSql, truncated, source: f.source,
      };
      result = { ...r, sha: f.sha, total_files: f.total, partial: f.partial };
      status = "checked";
      web = {
        light: r.light, repo: `${f.owner}/${f.repo}`, branch: r.branch, root: r.root, files: r.files, partial: f.partial, total_files: f.total,
        counts: r.counts, summary: r.summary, findings: findings.length,
        top: plainLines(findings, 6),
      };
    }
  }

  const semaforo = status === "checked" ? result.light : "grey";
  const resumen = status === "checked"
    ? `${result.light.toUpperCase()} · ${result.findings.length} hallazgos (${result.summary.critical}C/${result.summary.high}H/${result.summary.medium}M/${result.summary.low}L) · ${result.files} ficheros · ${result.repo}`
    : `${status}${result.detail ? ` · ${result.detail}` : ""}${repoIn ? ` · ${repoIn}` : ""}`;
  await db().from("oct30_leads").update({ resultado: result, resumen, semaforo, estado: status }).eq("id", lead.id);
  await db().from("oct30_checks").insert({
    lead_id: lead.id, repo_url: repoIn || null, branch: result?.branch ?? null, estado: status, semaforo,
    files: result?.files ?? null, summary: result?.summary ?? null, ip_hash: ipHash, email_hash: emailHash, ms: Date.now() - t0,
  });

  // ---- email (report now if the daily budget allows, else nurture sends it on its next pass)
  const fresh = { ...lead, resultado: result, semaforo, estado: status };
  let emailed = false, queued = false;
  const reportKind = status === "checked" ? "report" : "no_repo";
  if ((await budgetLeft()) > 0) {
    const u = await unsubUrls(lead.id);
    const mail = status === "checked"
      ? reportEmail(fresh, result as CheckResult, u.page)
      : noRepoEmail(fresh, status === "no_repo" ? "no_repo" : status === "no_migrations" ? "no_migrations" : "repo_unreadable", u.page, result?.detail ?? "");
    const s = await send({ to: email, ...mail, kind: reportKind, leadId: lead.id, unsub: true });
    emailed = s.ok;
  }
  const now = Date.now();
  if (emailed) {
    const patch: Record<string, unknown> = { report_sent_at: lead.report_sent_at ?? new Date(now).toISOString() };
    if (!lead.report_sent_at) patch.next_email_at = new Date(now + 2 * 864e5).toISOString();
    await db().from("oct30_leads").update(patch).eq("id", lead.id);
  } else {
    queued = true;
    await db().from("oct30_leads").update({ next_email_at: new Date(now + 30 * 60e3).toISOString() }).eq("id", lead.id);
  }

  // ---- no repo = a person who needs help: tell Renzo
  if (status === "no_repo" || (status !== "checked" && rol === "agency")) {
    const a = alertEmail(`[oct30] Lead sin repo${rol === "agency" ? " (AGENCIA)" : ""}: ${email}`, [
      ["Email", email], ["Rol", rol], ["Estado", status], ["Repo", repoIn || "(ninguno)"], ["Stack", base.stack ?? ""],
      ["Descripcion", base.descripcion ?? ""], ["Fuente", base.fuente], ["UTM", utm], ["Email al lead", emailed ? "enviado" : "en cola"],
    ], `Abre Claude Code y di: revisa lead oct30 ${email}`);
    await send({ to: RENZO, ...a, kind: "alert", leadId: lead.id });
  }

  return json({
    ok: true, status, emailed, queued, ...web,
    detail: status !== "checked" ? (result?.detail ?? null) : undefined,
    ms: Date.now() - t0,
  }, 200, h);
});
