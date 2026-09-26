// Brevo transactional send + log in oct30_emails + daily budget (the Brevo free plan's 300/day is shared with Rotatepilot).
import { db, DAILY_BUDGET, RENZO, unsubUrls } from "./util.ts";

const SENDER = { name: "Renzo · supabase-security", email: "security@rotatepilot.com" };

export async function sentLast24h(): Promise<number> {
  const since = new Date(Date.now() - 864e5).toISOString();
  const { count } = await db().from("oct30_emails").select("id", { count: "exact", head: true })
    .eq("status", "sent").gte("created_at", since);
  return count ?? 0;
}
export async function budgetLeft(): Promise<number> {
  return DAILY_BUDGET - (await sentLast24h());
}

export interface Mail {
  to: string;
  subject: string;
  html: string;
  text: string;
  kind: string;          // report | d2 | d4 | d7 | c1020 | ... | onboarding | alert | recovery | no_repo
  leadId?: string | null;
  unsub?: boolean;       // add List-Unsubscribe headers (marketing / nurture mail)
  replyTo?: string;
}

export async function send(m: Mail): Promise<{ ok: boolean; messageId?: string; error?: string }> {
  const key = Deno.env.get("BREVO_API_KEY");
  const headers: Record<string, string> = {};
  if (m.unsub && m.leadId) {
    const u = await unsubUrls(m.leadId);
    headers["List-Unsubscribe"] = `<${u.oneClick}>, <mailto:${RENZO}?subject=unsubscribe>`;
    headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
  }
  let ok = false, messageId: string | undefined, error: string | undefined;
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": key ?? "", "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender: SENDER,
        to: [{ email: m.to }],
        replyTo: { email: m.replyTo ?? RENZO, name: "Renzo" },
        subject: m.subject,
        htmlContent: m.html,
        textContent: m.text,
        tags: ["oct30", `oct30-${m.kind}`],
        ...(Object.keys(headers).length ? { headers } : {}), // Brevo rejects an empty headers object
      }),
    });
    const body = await r.json().catch(() => ({}));
    ok = r.ok;
    messageId = body.messageId;
    if (!ok) error = `${r.status} ${JSON.stringify(body).slice(0, 300)}`;
  } catch (e) {
    error = String(e).slice(0, 300);
  }
  await db().from("oct30_emails").insert({
    lead_id: m.leadId ?? null, to_email: m.to, kind: m.kind, subject: m.subject,
    status: ok ? "sent" : "failed", message_id: messageId ?? null, error: error ?? null,
  });
  if (ok && m.leadId && m.kind !== "alert") {
    await db().from("oct30_leads").update({ last_email_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", m.leadId);
  }
  return { ok, messageId, error };
}
