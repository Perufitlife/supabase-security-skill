// /functions/v1/oct30-unsub?l=<lead id>&t=<hmac>
// GET  -> redirect to the confirmation page on GitHub Pages (edge functions can't serve HTML).
// POST -> unsubscribe (RFC 8058 one-click from the mail client, or the button on that page).
import { cors, db, json, LANDING, safeEqual, unsubToken } from "../_shared/util.ts";

Deno.serve(async (req) => {
  const h = cors(req);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
  const url = new URL(req.url);
  let l = url.searchParams.get("l") ?? "", t = url.searchParams.get("t") ?? "";
  if (req.method === "GET") {
    return new Response(null, { status: 302, headers: { location: `${LANDING}unsubscribe.html?l=${encodeURIComponent(l)}&t=${encodeURIComponent(t)}` } });
  }
  if (req.method !== "POST") return json({ ok: false }, 405, h);
  if (!l || !t) {
    const b = await req.json().catch(() => ({}));
    l = String(b.l ?? ""); t = String(b.t ?? "");
  }
  if (!/^[0-9a-f-]{36}$/.test(l) || !safeEqual(t, await unsubToken(l))) return json({ ok: false, error: "Invalid link" }, 400, h);
  const { data } = await db().from("oct30_leads")
    .update({ unsubscribed: true, unsubscribed_at: new Date().toISOString(), next_email_at: null, updated_at: new Date().toISOString() })
    .eq("id", l).select("email").maybeSingle();
  await db().from("oct30_events").insert({ tipo: "unsubscribe", page: "email" });
  return json({ ok: true, found: !!data }, 200, h);
});
