// POST /functions/v1/oct30-nurture — called by pg_cron every 15 min (header x-cron-secret).
// 1) syncs Brevo opens/clicks/bounces/spam, 2) sends queued reports, 3) sends checkout recoveries,
// 4) sends the next nurture email to every due lead, stopping on purchase, unsubscribe, bounce or reply.
// Test hooks (same secret): {"force_lead": "<uuid>", "force_step": "d2"} sends one step now; {"dry_run": true}.
import { db, json, PAYMENT_LINKS, RENZO, safeEqual, unsubUrls } from "../_shared/util.ts";
import { budgetLeft, send } from "../_shared/mail.ts";
import { CheckResult, LeadLike, MIN_GAP_MS, noRepoEmail, nurtureEmail, recoveryEmail, reportEmail, SEQUENCE } from "../_shared/emails.ts";
import { Imap } from "../_shared/imap.ts";

type Lead = LeadLike & Record<string, any>;

function steps(lead: Lead) {
  const t0 = Date.parse(lead.report_sent_at);
  return SEQUENCE.filter((s) => !(lead.seq_sent ?? []).includes(s.key))
    .filter((s) => !(lead.semaforo === "green" && s.key === "d7"))
    .filter((s) => !(s.calendar && s.due(t0) <= t0))
    .map((s) => ({ s, due: s.due(t0), stale: s.due(t0) + s.staleMs }));
}
function pickNow(lead: Lead, now: number) {
  const last = lead.last_email_at ? Date.parse(lead.last_email_at) : 0;
  if (now < last + MIN_GAP_MS) return null;
  const ready = steps(lead).filter((x) => x.due <= now && now < x.stale);
  if (!ready.length) return null;
  return (ready.find((x) => x.s.calendar) ?? ready.sort((a, b) => a.due - b.due)[0]).s;
}
function nextAt(lead: Lead, now: number): string | null {
  const last = lead.last_email_at ? Date.parse(lead.last_email_at) : 0;
  let best = Infinity;
  for (const x of steps(lead)) {
    const t = Math.max(x.due, last + MIN_GAP_MS, now);
    if (t < x.stale && t < best) best = t;
  }
  return Number.isFinite(best) ? new Date(best).toISOString() : null;
}

async function syncBrevo(log: string[]) {
  const key = Deno.env.get("BREVO_API_KEY") ?? "";
  for (const ev of ["opened", "clicks", "hardBounces", "spam", "unsubscribed"]) {
    try {
      const r = await fetch(`https://api.brevo.com/v3/smtp/statistics/events?limit=500&days=3&tags=oct30&event=${ev}`, { headers: { "api-key": key, accept: "application/json" } });
      if (!r.ok) { log.push(`brevo ${ev} ${r.status}`); continue; }
      const events: any[] = (await r.json()).events ?? [];
      for (const e of events) {
        if (!e.messageId) continue;
        if (ev === "opened" || ev === "clicks") {
          const col = ev === "opened" ? "opened_at" : "clicked_at";
          await db().from("oct30_emails").update({ [col]: e.date }).eq("message_id", e.messageId).is(col, null);
        } else {
          const patch = ev === "hardBounces" ? { bounced: true, estado: "bounced" } : { unsubscribed: true, unsubscribed_at: new Date().toISOString() };
          await db().from("oct30_leads").update({ ...patch, next_email_at: null }).eq("email", String(e.email).toLowerCase());
        }
      }
      if (events.length) log.push(`brevo ${ev}: ${events.length}`);
    } catch (e) { log.push(`brevo ${ev} error ${String(e).slice(0, 80)}`); }
  }
}

async function sendStep(lead: Lead, key: string, dry: boolean): Promise<boolean> {
  const u = await unsubUrls(lead.id);
  const mail = nurtureEmail(key, lead, u.page);
  if (dry) return true;
  const s = await send({ to: lead.email, ...mail, kind: key, leadId: lead.id, unsub: true });
  if (!s.ok) return false;
  const now = Date.now();
  const updated = { ...lead, seq_sent: [...(lead.seq_sent ?? []), key], last_email_at: new Date(now).toISOString() };
  await db().from("oct30_leads").update({
    seq_sent: updated.seq_sent, seq_step: updated.seq_sent.length, last_email_at: updated.last_email_at,
    next_email_at: nextAt(updated, now), updated_at: new Date(now).toISOString(),
  }).eq("id", lead.id);
  return true;
}

Deno.serve(async (req) => {
  const secret = Deno.env.get("OCT30_CRON_SECRET") ?? "";
  if (req.method !== "POST" || !secret || !safeEqual(req.headers.get("x-cron-secret") ?? "", secret)) return json({ ok: false }, 401);
  const body = await req.json().catch(() => ({}));
  const dry = body.dry_run === true;
  const log: string[] = [];
  const now = Date.now();

  // ---- test hook: force one step for one lead
  if (body.force_lead && body.force_step) {
    const { data: lead } = await db().from("oct30_leads").select("*").eq("id", body.force_lead).single();
    if (!lead) return json({ ok: false, error: "lead not found" }, 404);
    if (!lead.report_sent_at) lead.report_sent_at = new Date().toISOString();
    const ok = await sendStep(lead, body.force_step, dry);
    return json({ ok, forced: body.force_step });
  }

  await syncBrevo(log);
  let budget = await budgetLeft();
  const stats = { reports: 0, recoveries: 0, nurture: 0, replied: 0, skipped_budget: 0 };

  // ---- 1) reports queued by oct30-check when the daily budget was used up
  const { data: queued } = await db().from("oct30_leads").select("*")
    .is("report_sent_at", null).not("resultado", "is", null).lte("next_email_at", new Date(now).toISOString())
    .eq("unsubscribed", false).eq("bounced", false).limit(50);
  for (const lead of queued ?? []) {
    if (budget <= 0) { stats.skipped_budget++; continue; }
    const u = await unsubUrls(lead.id);
    const r = lead.resultado;
    const mail = lead.estado === "checked"
      ? reportEmail(lead, r as CheckResult, u.page)
      : noRepoEmail(lead, lead.estado === "no_repo" ? "no_repo" : lead.estado === "no_migrations" ? "no_migrations" : "repo_unreadable", u.page, r?.detail ?? "");
    if (dry) { stats.reports++; continue; }
    const s = await send({ to: lead.email, ...mail, kind: lead.estado === "checked" ? "report" : "no_repo", leadId: lead.id, unsub: true });
    if (s.ok) {
      budget--; stats.reports++;
      await db().from("oct30_leads").update({ report_sent_at: new Date().toISOString(), next_email_at: new Date(Date.now() + 2 * 864e5).toISOString() }).eq("id", lead.id);
    }
  }

  // ---- 2) abandoned checkout recovery (one email, 1 h after Stripe reports the session expired)
  const { data: rec } = await db().from("oct30_orders").select("*")
    .eq("status", "expired").is("recovery_sent_at", null).lte("recovery_due_at", new Date(now).toISOString()).limit(20);
  for (const o of rec ?? []) {
    if (budget <= 0) { stats.skipped_budget++; continue; }
    const email = String(o.email ?? "").toLowerCase();
    const [{ count: paid }, { data: lead }] = await Promise.all([
      db().from("oct30_orders").select("id", { count: "exact", head: true }).eq("status", "paid").eq("email", email),
      db().from("oct30_leads").select("*").eq("email", email).maybeSingle(),
    ]);
    if ((paid ?? 0) > 0 || lead?.unsubscribed || lead?.purchased || lead?.bounced) {
      await db().from("oct30_orders").update({ recovery_sent_at: new Date().toISOString(), recovery_due_at: null }).eq("id", o.id);
      continue;
    }
    const pl = PAYMENT_LINKS[o.payment_link] ?? { tier: o.tier, name: "Oct 30 order", usd: 0 };
    const url = { fixpack: "https://buy.stripe.com/3cI28rc24ef05qp5v4cAo0v", hardening: "https://buy.stripe.com/6oUfZh7LOgn85qp9LkcAo0w", fleet: "https://buy.stripe.com/aFa00j0jm9YKf0Z6z8cAo0x" }[pl.tier as "fixpack"] ?? "https://perufitlife.github.io/supabase-security-skill/oct30/#plans";
    const unsubPage = lead ? (await unsubUrls(lead.id)).page : undefined;
    const mail = recoveryEmail({ tier: pl.tier, tierName: pl.name, url, nombre: o.nombre }, unsubPage);
    if (dry) { stats.recoveries++; continue; }
    const s = await send({ to: email, ...mail, kind: "recovery", leadId: lead?.id ?? null, unsub: !!lead });
    if (s.ok) {
      budget--; stats.recoveries++;
      await db().from("oct30_orders").update({ recovery_sent_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", o.id);
    }
  }

  // ---- 3) the sequence
  const { data: due } = await db().from("oct30_leads").select("*")
    .not("report_sent_at", "is", null).lte("next_email_at", new Date(now).toISOString())
    .eq("unsubscribed", false).eq("purchased", false).eq("replied", false).eq("bounced", false).eq("consent", true)
    .order("next_email_at", { ascending: true }).limit(Math.max(0, Math.min(budget, 40)));

  let imap: Imap | null = null;
  const pass = Deno.env.get("GMAIL_APP_PASSWORD");
  if ((due ?? []).length && pass) {
    try { imap = new Imap(); await imap.open(RENZO, pass); } catch (e) { log.push(`imap ${String(e).slice(0, 80)}`); imap = null; }
  }
  for (const lead of due ?? []) {
    if (budget <= 0) { stats.skipped_budget++; break; }
    if (imap && !lead.is_test) {
      try {
        if (await imap.hasMailFrom(lead.email, new Date(Date.parse(lead.created_at) - 864e5))) {
          stats.replied++;
          await db().from("oct30_leads").update({ replied: true, replied_at: new Date().toISOString(), next_email_at: null }).eq("id", lead.id);
          continue;
        }
      } catch (e) { log.push(`imap search ${String(e).slice(0, 60)}`); }
    }
    const step = pickNow(lead, now);
    if (!step) {
      await db().from("oct30_leads").update({ next_email_at: nextAt(lead, now) }).eq("id", lead.id);
      continue;
    }
    if (await sendStep(lead, step.key, dry)) { budget--; stats.nurture++; }
  }
  if (imap) await imap.close();

  return json({ ok: true, dry, budget_left: budget, ...stats, log });
});
