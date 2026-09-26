// Shared helpers for the oct30-* edge functions.
import { createClient, SupabaseClient } from "npm:@supabase/supabase-js@2";

export const PROJECT_URL = Deno.env.get("SUPABASE_URL") ?? "https://mknvxxhaatnqsrkcjydc.supabase.co";
export const FN_BASE = `${PROJECT_URL}/functions/v1`;
export const LANDING = "https://perufitlife.github.io/supabase-security-skill/oct30/";
export const RENZO = "renzomacar@gmail.com";
export const DAILY_BUDGET = Number(Deno.env.get("OCT30_DAILY_BUDGET") ?? "120");

export const LINKS = {
  fixpack: "https://buy.stripe.com/3cI28rc24ef05qp5v4cAo0v",
  hardening: "https://buy.stripe.com/6oUfZh7LOgn85qp9LkcAo0w",
  fleet: "https://buy.stripe.com/aFa00j0jm9YKf0Z6z8cAo0x",
};
// The ONLY payment links this engine reacts to (Stripe account also sells other products).
export const PAYMENT_LINKS: Record<string, { tier: string; name: string; usd: number }> = {
  plink_1UJlrAEHbkjS6yZv8ldGJ3AH: { tier: "fixpack", name: "Oct 30 Fix Pack", usd: 490 },
  plink_1UJlrCEHbkjS6yZvuDcDiLj5: { tier: "hardening", name: "Hardening + Proof Report", usd: 1490 },
  plink_1UJlrEEHbkjS6yZv8OJ3v1pd: { tier: "fleet", name: "Agency Fleet", usd: 4900 },
};

let _db: SupabaseClient | null = null;
export function db(): SupabaseClient {
  if (_db) return _db;
  let key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  if (!key) {
    try { key = Object.values(JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}"))[0] as string; } catch { /* */ }
  }
  _db = createClient(PROJECT_URL, key, { auth: { persistSession: false, autoRefreshToken: false } });
  return _db;
}

const ALLOWED_ORIGINS = [/^https:\/\/perufitlife\.github\.io$/, /^http:\/\/localhost(:\d+)?$/, /^http:\/\/127\.0\.0\.1(:\d+)?$/];
export function cors(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") ?? "";
  const ok = ALLOWED_ORIGINS.some((r) => r.test(origin));
  return {
    "Access-Control-Allow-Origin": ok ? origin : "https://perufitlife.github.io",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
export function originAllowed(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true; // server-to-server / curl (rate limits still apply)
  return ALLOWED_ORIGINS.some((r) => r.test(origin));
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
}

export async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacKey(secret: string) {
  return await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}
export async function hmacHex(secret: string, msg: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function unsubSecret(): string {
  return Deno.env.get("OCT30_UNSUB_SECRET") ?? "";
}
export async function unsubToken(leadId: string): Promise<string> {
  return (await hmacHex(unsubSecret(), `unsub:${leadId}`)).slice(0, 32);
}
export async function unsubUrls(leadId: string) {
  const t = await unsubToken(leadId);
  return {
    page: `${LANDING}unsubscribe.html?l=${leadId}&t=${t}`,
    oneClick: `${FN_BASE}/oct30-unsub?l=${leadId}&t=${t}`,
  };
}

export function clientIp(req: Request): string {
  return (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || req.headers.get("cf-connecting-ip") || "0.0.0.0";
}

export const esc = (s: unknown) =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const clip = (s: unknown, n: number) => {
  const v = String(s ?? "").trim();
  return v.length > n ? v.slice(0, n) : v;
};
