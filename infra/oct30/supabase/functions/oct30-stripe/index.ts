// POST /functions/v1/oct30-stripe — Stripe webhook (checkout.session.completed / .expired).
// Reacts ONLY to the 3 Oct 30 payment links; everything else on the account (Rotatepilot...) is ignored.
import { db, hmacHex, json, PAYMENT_LINKS, RENZO, safeEqual } from "../_shared/util.ts";
import { send } from "../_shared/mail.ts";
import { alertEmail, onboardingEmail } from "../_shared/emails.ts";

async function verify(raw: string, header: string, secret: string): Promise<boolean> {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")).filter((p) => p.length === 2).map(([k, v]) => [k.trim(), v]));
  const t = Number(parts.t);
  if (!t || Math.abs(Date.now() / 1000 - t) > 300) return false;
  const expected = await hmacHex(secret, `${t}.${raw}`);
  return header.split(",").filter((p) => p.startsWith("v1=")).some((p) => safeEqual(p.slice(3), expected));
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ ok: false }, 405);
  const raw = await req.text();
  const secret = Deno.env.get("OCT30_STRIPE_WEBHOOK_SECRET") ?? "";
  if (!secret || !(await verify(raw, req.headers.get("stripe-signature") ?? "", secret))) return json({ ok: false, error: "bad signature" }, 400);
  const ev = JSON.parse(raw);
  const s = ev?.data?.object ?? {};
  const pl = PAYMENT_LINKS[s.payment_link as string];
  if (!pl || !["checkout.session.completed", "checkout.session.expired"].includes(ev.type)) return json({ ok: true, ignored: true });

  const email = String(s.customer_details?.email ?? s.customer_email ?? "").toLowerCase() || null;
  const nombre = s.customer_details?.name ?? null;
  const isTest = ev.livemode === false || /\+oct30test@/i.test(email ?? "") || s.metadata?.oct30_test === "1";
  const { data: prev } = await db().from("oct30_orders").select("*").eq("stripe_session_id", s.id).maybeSingle();

  // ---------------------------------------------------------------- paid
  if (ev.type === "checkout.session.completed") {
    if (prev?.status === "paid") return json({ ok: true, duplicate: true });
    const status = s.payment_status === "paid" || s.payment_status === "no_payment_required" ? "paid" : "pending";

    let { data: lead } = email ? await db().from("oct30_leads").select("*").eq("email", email).maybeSingle() : { data: null };
    if (!lead && email) {
      const ins = await db().from("oct30_leads").insert({
        email, nombre, rol: pl.tier === "fleet" ? "agency" : "owner", fuente: "stripe", estado: "customer", consent: false, is_test: isTest,
      }).select("*").single();
      lead = ins.data;
    }
    const row = {
      stripe_session_id: s.id, stripe_event_id: ev.id, payment_link: s.payment_link, tier: pl.tier, status,
      amount_total: s.amount_total ?? pl.usd * 100, currency: s.currency ?? "usd", email, nombre, lead_id: lead?.id ?? null,
      recovery_due_at: null, raw: { customer: s.customer, payment_intent: s.payment_intent, livemode: ev.livemode, created: s.created }, is_test: isTest,
      updated_at: new Date().toISOString(),
    };
    const { data: order } = prev
      ? await db().from("oct30_orders").update(row).eq("id", prev.id).select("*").single()
      : await db().from("oct30_orders").insert(row).select("*").single();
    if (status !== "paid" || !order) return json({ ok: true, status });

    if (lead) {
      await db().from("oct30_leads").update({ purchased: true, purchased_at: new Date().toISOString(), estado: "customer", next_email_at: null, nombre: lead.nombre ?? nombre, updated_at: new Date().toISOString() }).eq("id", lead.id);
    }
    // Any pending recovery for this buyer is moot.
    if (email) await db().from("oct30_orders").update({ recovery_due_at: null }).eq("email", email).eq("status", "expired").is("recovery_sent_at", null);

    const amount = Math.round((order.amount_total ?? 0) / 100);
    let onboarded = false;
    if (email) {
      const m = onboardingEmail({ short_id: order.short_id, tier: pl.tier, tierName: pl.name, amount, nombre });
      onboarded = (await send({ to: email, ...m, kind: "onboarding", leadId: lead?.id ?? null })).ok;
    }
    const r = lead?.resultado;
    const a = alertEmail(`[oct30] VENTA ${pl.name} $${amount} · pedido ${order.short_id}${isTest ? " (TEST)" : ""}`, [
      ["Pedido", order.short_id], ["Plan", `${pl.name} (${pl.tier})`], ["Importe", `$${amount} ${String(order.currency).toUpperCase()}`],
      ["Cliente", `${nombre ?? ""} <${email ?? "sin email"}>`], ["Stripe session", s.id], ["Payment intent", s.payment_intent ?? ""],
      ["Lead", lead ? `${lead.rol} · fuente ${lead.fuente} · ${lead.checks_count ?? 0} checks` : "no existia (compra directa)"],
      ["Ultimo check", lead?.resumen ?? "(ninguno)"], ["Repo", lead?.repo_url ?? "(pedirlo en onboarding)"],
      ["Semaforo", r?.light ?? lead?.semaforo ?? "-"], ["Email onboarding", onboarded ? "enviado" : "NO enviado"],
      ["Plazo", pl.tier === "fixpack" ? "48 h desde acceso" : pl.tier === "hardening" ? "5 dias habiles" : "10 dias habiles"],
    ], `Abre Claude Code y di: entrega pedido oct30 ${order.short_id}`);
    await send({ to: RENZO, ...a, kind: "alert", leadId: lead?.id ?? null });
    return json({ ok: true, order: order.short_id });
  }

  // ---------------------------------------------------------------- expired (abandoned)
  let recoveryDue: string | null = null;
  if (email) {
    const [{ count: paid }, { count: already }, { data: lead }] = await Promise.all([
      db().from("oct30_orders").select("id", { count: "exact", head: true }).eq("email", email).eq("status", "paid"),
      db().from("oct30_orders").select("id", { count: "exact", head: true }).eq("email", email).eq("status", "expired").or("recovery_due_at.not.is.null,recovery_sent_at.not.is.null"),
      db().from("oct30_leads").select("unsubscribed,purchased,bounced").eq("email", email).maybeSingle(),
    ]);
    if (!paid && !already && !lead?.unsubscribed && !lead?.purchased && !lead?.bounced) recoveryDue = new Date(Date.now() + 36e5).toISOString();
  }
  const row = {
    stripe_session_id: s.id, stripe_event_id: ev.id, payment_link: s.payment_link, tier: pl.tier, status: "expired",
    amount_total: s.amount_total ?? pl.usd * 100, currency: s.currency ?? "usd", email, nombre, recovery_due_at: recoveryDue,
    raw: { livemode: ev.livemode, created: s.created }, is_test: isTest, updated_at: new Date().toISOString(),
  };
  if (prev) await db().from("oct30_orders").update(row).eq("id", prev.id);
  else await db().from("oct30_orders").insert(row);
  return json({ ok: true, expired: true, recovery_due_at: recoveryDue });
});
