// POST /functions/v1/oct30-event — anonymous page analytics (no IP, no email, no cookies).
// Body (JSON, sent as text/plain via sendBeacon to skip the CORS preflight):
// {tipo, page, target, sid, utm:{utm_source,...}, ref, meta}
import { clip, cors, db, json, originAllowed } from "../_shared/util.ts";

const TYPES = new Set(["page_view", "cta_click", "check_start", "check_submit", "check_result", "check_error", "scroll_50", "scroll_90", "faq_open", "copy_cmd", "thanks_view"]);

Deno.serve(async (req) => {
  const h = cors(req);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
  if (req.method !== "POST" || !originAllowed(req)) return new Response(null, { status: 204, headers: h });
  let b: any;
  try { b = JSON.parse(await req.text()); } catch { return new Response(null, { status: 204, headers: h }); }
  const list = Array.isArray(b) ? b.slice(0, 10) : [b];
  const rows = list.filter((e) => e && TYPES.has(e.tipo)).map((e) => {
    const u = e.utm && typeof e.utm === "object" ? e.utm : {};
    let ref = clip(e.ref, 300);
    try { if (ref) ref = new URL(ref).hostname; } catch { ref = ""; } // referrer host only
    const metaStr = e.meta && typeof e.meta === "object" ? JSON.stringify(e.meta) : "";
    const meta = metaStr ? (metaStr.length <= 600 ? e.meta : { truncated: true }) : null;
    return {
      tipo: e.tipo, page: clip(e.page, 120) || null, target: clip(e.target, 160) || null, session_id: clip(e.sid, 40) || null,
      utm_source: clip(u.utm_source, 80) || null, utm_medium: clip(u.utm_medium, 80) || null,
      utm_campaign: clip(u.utm_campaign, 80) || null, utm_content: clip(u.utm_content, 80) || null,
      referrer: ref || null, country: req.headers.get("cf-ipcountry") ?? req.headers.get("x-country") ?? null, meta,
    };
  });
  if (rows.length) {
    try { await db().from("oct30_events").insert(rows); } catch { /* never break the page */ }
  }
  return json({ ok: true, n: rows.length }, 200, h);
});
