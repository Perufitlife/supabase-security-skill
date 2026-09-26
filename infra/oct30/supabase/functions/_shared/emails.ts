// Every email the Oct 30 engine sends. Plain English, short, honest: nothing breaks by itself on Oct 30.
import { esc, LANDING, LINKS } from "./util.ts";

export type Light = "red" | "amber" | "green" | "grey";
export interface Finding { severity: string; check: string; title: string; target: string; file: string; line: number; message: string }
export interface CheckResult {
  repo: string; branch: string; root: string; files: number; schemas: string[];
  counts: Record<string, number>; summary: Record<string, number>; light: Light;
  findings: Finding[]; fixSql: string; truncated?: boolean; source?: string;
}
export interface LeadLike { id: string; email: string; nombre?: string | null; rol: string; repo_url?: string | null; semaforo?: string | null; resultado?: any; stack?: string | null; descripcion?: string | null; report_sent_at?: string | null }

const LEGAL = "PMJ LIFE STORE LLC · 7901 4th St N Suite 4707, St. Petersburg, FL 33702, USA";
const CHANGELOG = "https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically";
const TECHCRUNCH = "https://techcrunch.com/2026/09/25/some-supabase-customers-are-publicly-exposing-reams-of-peoples-data-to-the-web/";

export const EXPOSURE = new Set(["grant_without_rls", "lazy_bulk_grant", "default_privileges_regrant", "security_definer_anon", "view_bypasses_rls", "matview_exposed"]);

export const PLAIN: Record<string, (t: string) => string> = {
  grant_without_rls: (t) => `Anyone with your app's public key can read, and possibly change, every row in ${t}.`,
  lazy_bulk_grant: () => `One migration hands every table to the public key at once. Any table without access rules becomes public.`,
  default_privileges_regrant: () => `One migration makes every future table public the moment it is created, before anyone writes access rules for it.`,
  security_definer_anon: (t) => `${t} is a database function that skips your access rules, and anyone with the public key can call it.`,
  view_bypasses_rls: (t) => `${t} is a view that shows rows your access rules would otherwise hide.`,
  matview_exposed: (t) => `${t} can't have access rules at all, and the public key can read it.`,
  unreachable_after_oct30: (t) => `${t} has no explicit access. New tables like it fail after Oct 30, and a fresh copy of your app built from these migrations fails today.`,
  sequence_not_granted: (t) => `Adding rows to ${t} will fail on a fresh setup (a missing permission on its ID counter).`,
  definer_no_search_path: (t) => `${t} is a privileged function with a loose setting that can be abused. Lower risk, easy fix.`,
};

const PLAIN_MANY: Record<string, (list: string, n: number) => string> = {
  grant_without_rls: (l, n) => `${n} tables (${l}) can be read, and possibly changed, row by row by anyone with your app's public key.`,
  lazy_bulk_grant: (_l, n) => `${n} migrations hand every table to the public key at once. Any table without access rules becomes public.`,
  default_privileges_regrant: (_l, n) => `${n} migrations make every future table public the moment it is created.`,
  security_definer_anon: (l, n) => `${n} database functions (${l}) skip your access rules, and anyone with the public key can call them.`,
  view_bypasses_rls: (l, n) => `${n} views (${l}) show rows your access rules would otherwise hide.`,
  matview_exposed: (l, n) => `${n} cached views (${l}) can't have access rules, and the public key can read them.`,
  unreachable_after_oct30: (l, n) => `${n} tables, views or functions (${l}) have no explicit access. New ones like them fail after Oct 30, and a fresh copy of your app built from these migrations fails today.`,
  sequence_not_granted: (l, n) => `Adding rows to ${n} tables (${l}) will fail on a fresh setup (missing permission on their ID counters).`,
  definer_no_search_path: (l, n) => `${n} privileged functions (${l}) have a loose setting that can be abused. Lower risk, easy fix.`,
};
const ORDER = ["grant_without_rls", "lazy_bulk_grant", "default_privileges_regrant", "security_definer_anon", "view_bypasses_rls", "matview_exposed", "unreachable_after_oct30", "sequence_not_granted", "definer_no_search_path"];

// Business-language lines, one per kind of problem (not one per table), worst first.
export function plainLines(findings: Finding[], max = 6): { severity: string; check: string; count: number; text: string }[] {
  const by = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.severity === "low") continue;
    if (!by.has(f.check)) by.set(f.check, []);
    by.get(f.check)!.push(f);
  }
  const out = [];
  for (const check of [...ORDER, ...[...by.keys()].filter((k) => !ORDER.includes(k))]) {
    const fs = by.get(check);
    if (!fs?.length) continue;
    const sev = fs.some((f) => f.severity === "critical") ? "critical" : fs.some((f) => f.severity === "high") ? "high" : "medium";
    let text: string;
    if (fs.length === 1) text = (PLAIN[check] ?? ((t: string) => `${t}: ${fs[0].title}`))(fs[0].target);
    else {
      const names = fs.slice(0, 4).map((f) => f.target).join(", ") + (fs.length > 4 ? ` and ${fs.length - 4} more` : "");
      text = (PLAIN_MANY[check] ?? ((l: string, n: number) => `${n} objects (${l}): ${fs[0].title}`))(names, fs.length);
    }
    out.push({ severity: sev, check, count: fs.length, text });
  }
  return out.slice(0, max);
}

export function lightOf(findings: Finding[]): Light {
  if (findings.some((f) => EXPOSURE.has(f.check) && (f.severity === "critical" || f.severity === "high"))) return "red";
  if (findings.some((f) => f.severity !== "low")) return "amber";
  return "green";
}

const firstName = (l: LeadLike) => {
  const n = (l.nombre ?? "").trim().split(/\s+/)[0];
  return n && n.length < 30 ? n : "there";
};
const repoShort = (u?: string | null) => (u ?? "").replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\/$/, "") || "your repo";
const fmtDate = (iso?: string | null) => new Date(iso ?? Date.now()).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

// ------------------------------------------------------------------ layout
function wrap(inner: string, unsubPage?: string, preheader = ""): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#f3f5f7">
<span style="display:none!important;opacity:0;color:transparent;height:0;width:0;overflow:hidden">${esc(preheader)}</span>
<div style="max-width:600px;margin:0 auto;padding:24px 18px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15.5px;line-height:1.55;color:#0f1b26;background:#ffffff">
${inner}
<p style="margin:28px 0 0;padding-top:14px;border-top:1px solid #d0d8df;font-size:12px;line-height:1.5;color:#66737f">
supabase-security is an independent open-source project, not affiliated with Supabase, Inc.<br>${LEGAL}<br>
${unsubPage ? `You got this because you ran the free check at ${esc(LANDING)}. <a href="${esc(unsubPage)}" style="color:#66737f">Unsubscribe</a>.` : ""}
</p></div></body></html>`;
}
const P = (s: string) => `<p style="margin:0 0 14px">${s}</p>`;
const H = (s: string) => `<h2 style="margin:22px 0 10px;font-size:17px;line-height:1.3">${s}</h2>`;
const A = (href: string, label: string) => `<a href="${esc(href)}" style="color:#0b6e5c;font-weight:600">${esc(label)}</a>`;
const BTN = (href: string, label: string) =>
  `<p style="margin:6px 0 16px"><a href="${esc(href)}" style="display:inline-block;background:#0f1b26;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 18px;border-radius:8px">${esc(label)}</a></p>`;
const CODE = (s: string) =>
  `<pre style="margin:0 0 14px;padding:12px 14px;background:#111c25;color:#d6dee5;border-radius:8px;font:12.5px/1.55 Consolas,Menlo,monospace;white-space:pre-wrap;word-break:break-word">${esc(s)}</pre>`;
const textFooter = (unsubPage?: string) =>
  `\n\n--\nsupabase-security is an independent open-source project, not affiliated with Supabase, Inc.\n${LEGAL}\n${unsubPage ? `You got this because you ran the free check at ${LANDING}\nUnsubscribe: ${unsubPage}\n` : ""}`;

const LIGHT = {
  red: { label: "RED: data may be exposed", color: "#c3301f", bg: "#fbe9e6" },
  amber: { label: "AMBER: new tables will fail after Oct 30", color: "#8a5a00", bg: "#fdf1d8" },
  green: { label: "GREEN: ready for Oct 30", color: "#0b6e5c", bg: "#e2f1ec" },
  grey: { label: "NOT CHECKED", color: "#3f4d59", bg: "#e3e8ed" },
};
const pill = (l: Light) => `<p style="margin:0 0 16px"><span style="display:inline-block;padding:6px 12px;border-radius:999px;font-weight:700;font-size:14px;color:${LIGHT[l].color};background:${LIGHT[l].bg}">${LIGHT[l].label}</span></p>`;

// ------------------------------------------------------------------ offer ladder
function offer(rol: string, light: Light): { html: string; text: string } {
  const fix = `Oct 30 Fix Pack, $490: one project, a pull request within 48 hours of access with per-table grants matched to your access rules, verified with real API calls, plus the CI check. Late = full refund.`;
  const hard = `Hardening + Proof Report, $1,490: the Fix Pack plus an audit of your access rules (RLS), storage and functions, a live test with your own public key (only with your written OK), and a report you can hand to customers who ask about security. 5 business days.`;
  const fleet = `Agency Fleet, $4,900: the Fix Pack on up to 10 client projects, white-label reports, CI in every repo, a re-test after Oct 30 and 90 days of weekly monitoring.`;
  if (light === "green" && rol !== "agency") {
    return {
      html: H("Keep it that way (free)") + P(`Add this to a GitHub workflow and every pull request gets the same check, so no future table ships without its grant:`) +
        CODE(`- uses: Perufitlife/supabase-security-skill@main\n  with:\n    mode: migrations`) +
        P(`Nothing to buy here. If a customer ever asks you to prove how their data is protected, that's what the ${A(LINKS.hardening, "Hardening + Proof Report")} is for.`),
      text: `KEEP IT THAT WAY (FREE)\nAdd to a GitHub workflow:\n- uses: Perufitlife/supabase-security-skill@main\n  with:\n    mode: migrations\n\nNothing to buy. If a customer ever asks you to prove how their data is protected: Hardening + Proof Report ${LINKS.hardening}`,
    };
  }
  if (rol === "agency") {
    return {
      html: H("If you'd rather have it done") + P(`You run Supabase for clients, so Oct 30 reaches all of their projects at once.`) +
        P(`<b>Recommended for you:</b> ${esc(fleet)}`) + BTN(LINKS.fleet, "Agency Fleet, $4,900") +
        P(`Just this one project? ${A(LINKS.fixpack, "Fix Pack, $490")}.`),
      text: `IF YOU'D RATHER HAVE IT DONE\nRecommended for you: ${fleet}\n${LINKS.fleet}\n\nJust this one project? Fix Pack, $490: ${LINKS.fixpack}`,
    };
  }
  if (light === "red") {
    return {
      html: H("If you'd rather have it done") + P(`<b>Recommended for you:</b> ${esc(hard)}`) + BTN(LINKS.hardening, "Hardening + Proof, $1,490") +
        P(`Only need the grants fixed? ${esc(fix)} ${A(LINKS.fixpack, "Fix Pack, $490")}.`),
      text: `IF YOU'D RATHER HAVE IT DONE\nRecommended for you: ${hard}\n${LINKS.hardening}\n\nOnly need the grants fixed? ${fix}\n${LINKS.fixpack}`,
    };
  }
  return {
    html: H("If you'd rather have it done") + P(`<b>Recommended for you:</b> ${esc(fix)}`) + BTN(LINKS.fixpack, "Fix Pack, $490") +
      P(`Customers asking how their data is protected? ${A(LINKS.hardening, "Hardening + Proof, $1,490")}.`),
    text: `IF YOU'D RATHER HAVE IT DONE\nRecommended for you: ${fix}\n${LINKS.fixpack}\n\nCustomers asking how their data is protected? Hardening + Proof, $1,490: ${LINKS.hardening}`,
  };
}

// ------------------------------------------------------------------ D0: the report
export function reportEmail(lead: LeadLike, r: CheckResult, unsubPage: string) {
  const repo = repoShort(r.repo);
  const n = r.findings.length;
  const exposure = r.findings.filter((f) => EXPOSURE.has(f.check));
  const subject = r.light === "red"
    ? `Your Supabase check: ${exposure.length} issue${exposure.length === 1 ? "" : "s"} that can expose data (${repo})`
    : r.light === "amber" ? `Your Supabase check: ${n} thing${n === 1 ? "" : "s"} to fix for Oct 30 (${repo})`
    : `Your Supabase check: ${repo} is ready for Oct 30`;

  const meaning = {
    red: `Based on the SQL in your repo, anyone who has your app's public key can reach data or database functions they shouldn't (the list below says exactly which). That key isn't secret: it ships inside your website's code.${exposure.some((f) => ["grant_without_rls", "lazy_bulk_grant", "default_privileges_regrant"].includes(f.check)) ? ` Tables open like this are the mistake behind the ~16,000 exposed Supabase databases ${A(TECHCRUNCH, "reported on Sept 25")}.` : ""} We read your code, not your live database, so confirm it before you panic, but treat it as urgent.`,
    amber: `Nothing we can see is exposed, and nothing breaks on Oct 30 by itself: your existing tables keep working. What changes is that Supabase stops giving new tables automatic access. The next table you (or your AI tool) add without an explicit grant fails with error 42501, from your app and also from server code using the service_role key (only direct Postgres connections, like an ORM or psql, are unaffected). A fresh copy of your app built from these migrations (a new project, a preview branch, a teammate's setup) fails already.`,
    green: `Every table and function your migrations expose has explicit grants backed by access rules (RLS). New tables will keep working after Oct 30 as long as they follow the same pattern.`,
    grey: "",
  }[r.light];
  const meaningText = meaning.replace(/<[^>]+>/g, "");

  const plainList = plainLines(r.findings, 8).map((x) => x.text);
  const moreN = 0;

  const off = offer(lead.rol, r.light);
  const shown = r.findings.slice(0, 30);
  const sev = (s: string) => ({ critical: "#c3301f", high: "#c3301f", medium: "#8a5a00", low: "#3f4d59" } as Record<string, string>)[s] ?? "#3f4d59";

  const html = wrap(
    P(`Hi ${esc(firstName(lead))},`) +
    P(`Here is the free check for <b>${esc(repo)}</b> (branch <code>${esc(r.branch)}</code>, ${r.files} SQL file${r.files === 1 ? "" : "s"} in <code>${esc(r.root)}</code>).`) +
    pill(r.light) +
    H("What this means for your business") + P(meaning) +
    (plainList.length ? `<ul style="margin:0 0 14px;padding-left:20px">${plainList.map((s) => `<li style="margin:0 0 6px">${esc(s)}</li>`).join("")}</ul>` +
      (moreN > 0 ? P(`…and ${moreN} more in the technical detail below.`) : "") : "") +
    off.html +
    H("Technical detail") +
    P(`${r.counts.tables ?? 0} tables · ${r.counts.views ?? 0} views · ${r.counts.functions ?? 0} functions in schema${r.schemas.length > 1 ? "s" : ""} ${esc(r.schemas.join(", "))}. ` +
      `Findings: ${r.summary.critical ?? 0} critical · ${r.summary.high ?? 0} high · ${r.summary.medium ?? 0} medium · ${r.summary.low ?? 0} low.`) +
    (shown.length ? shown.map((f) =>
      `<p style="margin:0 0 12px;font-size:14px"><b style="color:${sev(f.severity)}">${esc(f.severity.toUpperCase())}</b> <b>${esc(f.target)}</b> <span style="color:#66737f">${esc(f.file)}:${f.line}</span><br>${esc(f.message)}</p>`).join("") +
      (r.findings.length > shown.length ? P(`${r.findings.length - shown.length} more: run <code>npx supabase-security migrations</code> in the repo for the full list.`) : "") : "") +
    (r.fixSql ? H("Proposed SQL (review every line, test on a branch first)") + CODE(r.fixSql) +
      (r.truncated ? P(`Cut for length. Full file: <code>npx supabase-security migrations --fix-sql fix.sql</code>`) : "") : "") +
    P(`This check reads the SQL in your repo only. It never touched your database and used no credentials. The linter is open source: ${A("https://github.com/Perufitlife/supabase-security-skill", "github.com/Perufitlife/supabase-security-skill")}.`) +
    P(`Questions? Just reply, I read every one.<br>Renzo`),
    unsubPage, `${LIGHT[r.light].label}. ${meaningText.slice(0, 90)}`);

  const text = `Hi ${firstName(lead)},

Here is the free check for ${repo} (branch ${r.branch}, ${r.files} SQL files in ${r.root}).

${LIGHT[r.light].label}

WHAT THIS MEANS FOR YOUR BUSINESS
${meaningText}
${plainList.map((s) => `- ${s}`).join("\n")}${moreN > 0 ? `\n...and ${moreN} more below.` : ""}

${off.text}

TECHNICAL DETAIL
${r.counts.tables ?? 0} tables, ${r.counts.views ?? 0} views, ${r.counts.functions ?? 0} functions in ${r.schemas.join(", ")}.
Findings: ${r.summary.critical ?? 0} critical, ${r.summary.high ?? 0} high, ${r.summary.medium ?? 0} medium, ${r.summary.low ?? 0} low.

${shown.map((f) => `[${f.severity.toUpperCase()}] ${f.target} (${f.file}:${f.line})\n${f.message}`).join("\n\n")}
${r.fixSql ? `\nPROPOSED SQL (review every line, test on a branch first)\n${r.fixSql}${r.truncated ? "\n[cut for length: npx supabase-security migrations --fix-sql fix.sql]" : ""}` : ""}

This check reads the SQL in your repo only. It never touched your database and used no credentials.

Questions? Just reply, I read every one.
Renzo${textFooter(unsubPage)}`;
  return { subject, html, text };
}

// ------------------------------------------------------------------ no repo / unreadable / no migrations
const LIVE_SQL = `select c.relname as table_name,
       c.relrowsecurity as rls_on,
       has_table_privilege('anon', c.oid, 'select') as public_can_read
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r', 'p')
order by rls_on, table_name;`;

export function noRepoEmail(lead: LeadLike, reason: "no_repo" | "repo_unreadable" | "no_migrations", unsubPage: string, detail = "") {
  const repo = repoShort(lead.repo_url);
  const intro = {
    no_repo: `You asked for the check without a GitHub repo. That's fine, here is how to check it yourself in 2 minutes, and what I'd look at.`,
    repo_unreadable: `I couldn't read <b>${esc(repo)}</b>: it's private, renamed, or doesn't exist${detail ? ` (${esc(detail)})` : ""}. Nothing was stored from it.`,
    no_migrations: `I read <b>${esc(repo)}</b> but found no <code>supabase/migrations</code> folder or SQL files. That's common when tables were made in the Supabase dashboard (or by Lovable/Bolt). It means the repo can't tell who has access to your data; only the live database can.`,
  }[reason];
  const subject = {
    no_repo: "Your Supabase check: how to run it without a repo",
    repo_unreadable: `Your Supabase check: I couldn't read ${repo}`,
    no_migrations: `Your Supabase check: ${repo} has no migrations to read`,
  }[reason];
  const steps = reason === "repo_unreadable"
    ? [`Run the same check on your machine. No credentials, nothing leaves your computer: <code>npx supabase-security migrations</code> in the repo folder.`,
       `Or make the repo public for a minute and run the free check again: ${A(LANDING + "#check", "free check")}.`,
       `Built with Lovable? In Lovable, open your project, click the GitHub button (top right) and connect it; then paste that repo link in the check.`]
    : [`In your Supabase dashboard open <b>Advisors → Security Advisor</b>. It's free and lists the worst problems.`,
       `Then open the <b>SQL Editor</b> and run this read-only query. Any row with <code>rls_on = false</code> and <code>public_can_read = true</code> is a table anyone with your public key can read:`];
  const html = wrap(
    P(`Hi ${esc(firstName(lead))},`) + P(intro) + H("What to do (free)") +
    `<ol style="margin:0 0 14px;padding-left:20px">${steps.map((s) => `<li style="margin:0 0 8px">${s}</li>`).join("")}</ol>` +
    (reason !== "repo_unreadable" ? CODE(LIVE_SQL) + P(`Lovable Cloud projects don't give you a SQL editor; if that's you, ask Lovable's agent to "run the Supabase security scan and enable RLS on every table".`) : "") +
    H("Or have it done") +
    P(`If anything comes back open, or you'd rather not touch SQL, the ${A(LINKS.fixpack, "Fix Pack ($490, 48 hours)")} works without migrations too: we read your live schema (read-only) and deliver the fix ${reason === "no_repo" ? "as a reviewed SQL migration you apply (or a pull request, if you connect a repo)" : "as a pull request"}.${lead.rol === "agency" ? ` Several client projects? ${A(LINKS.fleet, "Agency Fleet")}.` : ""}`) +
    P(`Or just reply with what you found and I'll tell you what it means.<br>Renzo`),
    unsubPage);
  const text = `Hi ${firstName(lead)},

${intro.replace(/<[^>]+>/g, "")}

WHAT TO DO (FREE)
${steps.map((s, i) => `${i + 1}. ${s.replace(/<[^>]+>/g, "")}`).join("\n")}
${reason !== "repo_unreadable" ? `\n${LIVE_SQL}\n\nLovable Cloud has no SQL editor: ask Lovable's agent to run the security scan and enable RLS on every table.\n` : ""}
OR HAVE IT DONE
Fix Pack, $490, 48 hours, works without migrations (we read your live schema, read-only, and deliver the fix ${reason === "no_repo" ? "as a SQL migration you apply" : "as a pull request"}): ${LINKS.fixpack}${lead.rol === "agency" ? `\nAgency Fleet: ${LINKS.fleet}` : ""}

Or just reply with what you found and I'll tell you what it means.
Renzo${textFooter(unsubPage)}`;
  return { subject, html, text };
}

// ------------------------------------------------------------------ nurture
export interface Step { key: string; due: (t0: number) => number; staleMs: number; calendar: boolean }
const D = 864e5;
const at = (iso: string) => Date.parse(iso);
export const SEQUENCE: Step[] = [
  { key: "d2", due: (t0) => t0 + 2 * D, staleMs: 3 * D, calendar: false },
  { key: "d4", due: (t0) => t0 + 4 * D, staleMs: 3 * D, calendar: false },
  { key: "d7", due: (t0) => t0 + 7 * D, staleMs: 3 * D, calendar: false },
  { key: "c1020", due: () => at("2026-10-20T14:00:00Z"), staleMs: 2 * D, calendar: true },
  { key: "c1027", due: () => at("2026-10-27T14:00:00Z"), staleMs: 1 * D, calendar: true },
  { key: "c1031", due: () => at("2026-10-31T14:00:00Z"), staleMs: 2 * D, calendar: true },
  { key: "c1105", due: () => at("2026-11-05T14:00:00Z"), staleMs: 3 * D, calendar: true },
];
export const MIN_GAP_MS = 2 * D;

export function nurtureEmail(key: string, lead: LeadLike, unsubPage: string) {
  const name = firstName(lead);
  const repo = repoShort(lead.repo_url);
  const light = (lead.semaforo ?? "grey") as Light;
  const hadFindings = light === "red" || light === "amber";
  const grey = light === "grey";
  const reportLine = hadFindings
    ? `Your report from ${fmtDate(lead.report_sent_at)} already has that SQL for ${repo}, table by table.`
    : grey ? `The read-only query in my first email tells you in two minutes which of your tables are open today.`
    : `If you add tables later, the free check at ${LANDING} catches a missing grant in seconds.`;
  const buy = lead.rol === "agency"
    ? { label: "Agency Fleet, $4,900", url: LINKS.fleet, line: "Agency Fleet ($4,900): up to 10 client projects, each as a pull request, re-test after Oct 30 and 90 days of monitoring." }
    : light === "red"
    ? { label: "Hardening + Proof, $1,490", url: LINKS.hardening, line: "Hardening + Proof ($1,490): the fix as pull requests, plus an audit of RLS, storage and functions and a report for your customers." }
    : { label: "Fix Pack, $490", url: LINKS.fixpack, line: "Fix Pack ($490): per-table grants as a pull request within 48 hours, verified with real API calls, CI check included." };

  const T: Record<string, { subject: string; body: string[]; code?: string; cta?: boolean }> = {
    d2: {
      subject: "The Oct 30 fix most people paste reopens their data",
      body: [
        `Hi ${name}, a follow-up to your Supabase check.`,
        `When new tables start failing with 42501 after Oct 30, the fastest fix is the one Supabase lists as the rollback in its own changelog:`,
        `It works. It also hands every table in public to anyone holding your public (anon) key, and that key ships in your front-end code. It's safe only if every single table already has row level security and the right policies.`,
        `Functions are worse: Postgres lets PUBLIC execute every new function and anon inherits that, so the Oct 30 change doesn't protect them at all (supabase/supabase issue #49338).`,
        `The safe version is one grant per table, per role, matching your access rules. ${reportLine}`,
        `If you'd rather have it written, checked against your RLS with real API calls and merged as a pull request: ${buy.line}`,
      ],
      code: "grant select, insert, update, delete\n  on all tables in schema public\n  to anon, authenticated, service_role;",
      cta: true,
    },
    d4: {
      subject: "How a table nobody meant to publish ends up public",
      body: [
        `Hi ${name}, one pattern worth two minutes.`,
        `On Sept 25, UpGuard reported about 16,000 Supabase databases with tables anyone could read, many holding personal data (${TECHCRUNCH}). In 2025 the same mistake in Lovable-built apps became CVE-2025-48757.`,
        `It almost never starts with someone deciding to make data public. It goes like this: a table is created without access rules, something throws "permission denied", and the fix that makes the error go away is a grant to anon. We found exactly this while testing our linter on public repos, including a well-known open-source AI app whose migrations give anon full access to a table with RLS off.`,
        `After Oct 30 that moment happens a lot more often: every new table starts with no access, so every new table is a chance to paste the wrong fix.`,
        `The two lines that prevent it, in the same migration as the table: enable row level security, then grant only what your policies use.`,
        hadFindings ? `Your check found ${light === "red" ? "tables that already look exposed" : "tables that need explicit grants"} in ${repo}. ${buy.line}`
          : grey ? `We couldn't read migrations for your project, so we don't know yet. The query in my first email answers it; if anything comes back open, ${buy.line}`
          : `Your repo came back clean. To keep it that way, add the free CI check from your report.`,
      ],
      code: "alter table public.invoices enable row level security;\ngrant select on public.invoices to authenticated;",
      cta: hadFindings || grey,
    },
    d7: {
      subject: "What you'd get, exactly (and the guarantee)",
      body: [
        Date.now() < Date.parse("2026-10-30T00:00:00Z")
          ? `Hi ${name}, last note about the report, then I'll only write around Oct 30.`
          : `Hi ${name}, last note about the report.`,
        `If you want this off your plate, here is exactly what happens:`,
        `1) You buy, and invite the GitHub user Perufitlife to the repo (or send a read-only token) plus your Supabase project ref. We never need your service_role key or database password.\n2) Within 48 hours (Fix Pack) you get a pull request: per-table grants matched to your RLS, RLS checked on every exposed table, functions locked down, verified by replaying your migrations on a clean database and calling it as anon and as a signed-in user.\n3) CI check installed so the next migration can't regress.`,
        `Guarantee: late = 100% refund. And if a table we covered can't be reached after Oct 30, we fix it free.`,
        `Fix Pack $490: ${LINKS.fixpack}\nHardening + Proof $1,490: ${LINKS.hardening}\nAgency Fleet $4,900 (10 projects): ${LINKS.fleet}`,
        `Or reply with a question. I answer myself.`,
      ],
    },
    c1020: {
      subject: "10 days to Oct 30: what actually changes",
      body: [
        `Hi ${name}, Supabase applies its grants change to every existing project on Friday, Oct 30.`,
        `What does NOT happen: your app doesn't go down. Existing tables keep their grants.`,
        `What does: every new table, view or sequence in public starts with no access for the API roles: anon, authenticated and also service_role, so even server code using the service key gets 42501. Only direct Postgres connections (an ORM, psql) are unaffected. The first one you (or an AI tool) ship without a grant returns 42501. Migrations replayed on a new project or preview branch fail the same way.`,
        `What to avoid: the bulk "grant ... on all tables ... to anon" fix. It reopens every table without RLS.`,
        hadFindings ? `${repo} still had open items in your check. To have the pull request merged before Oct 30, order the Fix Pack by Tue, Oct 27: ${LINKS.fixpack}`
          : grey ? `Not sure where you stand? Run the free check on your repo (${LANDING}#check) or the query from my first email. To have a pull request merged before Oct 30, order the Fix Pack by Tue, Oct 27: ${LINKS.fixpack}`
          : `Your check came back clean. Nothing to do except keep new tables granted explicitly.`,
      ],
    },
    c1027: {
      subject: "3 days: the 3 things to check before Friday",
      body: [
        `Hi ${name}, Oct 30 is Friday. Three checks, 10 minutes:`,
        `1) Any migration with "on all tables in schema public to anon"? That's the lazy fix: replace it with per-table grants.\n2) Any "security definer" function without "revoke execute ... from public"? Anyone with your public key can call it.\n3) Does your next planned migration create a table? Put the grant, "enable row level security" and the policy in that same file.`,
        `Free check on any repo: ${LANDING}#check`,
        `Want it done by Friday? Fix Pack orders today still get a pull request before Oct 30: ${LINKS.fixpack}`,
      ],
    },
    c1031: {
      subject: "It's in effect: what to watch for",
      body: [
        `Hi ${name}, the change is live on every Supabase project since yesterday.`,
        `Watch for: "permission denied for table" (code 42501) on a table created from now on, in the browser and in server code or edge functions using the service_role key. HTTP 401 means anon, 403 means a signed-in user. An empty [] is a different problem: the grant is there and RLS hides the rows.`,
        `The right fix for one table, in a migration:`,
        `Don't paste the bulk grant to anon. It makes the error go away by opening every table without RLS.`,
        hadFindings ? `If you'd like it handled: ${buy.line} ${buy.url}` : `Stuck on one? Reply with the error and I'll tell you the exact grant.`,
      ],
      code: "grant select on public.my_table to authenticated;\ngrant select, insert, update, delete on public.my_table to service_role;\nalter table public.my_table enable row level security;\n-- plus a policy, e.g.:\ncreate policy \"own rows\" on public.my_table for select to authenticated using (user_id = auth.uid());",
    },
    c1105: {
      subject: "One week in: last note from me",
      body: [
        `Hi ${name}, a week since Oct 30. This is my last email about it.`,
        `If new tables have been failing, or someone pasted a bulk grant to make them work, the free check shows it in seconds: ${LANDING}#check`,
        `If you want it fixed and checked properly, the offer stands: ${buy.line} ${buy.url}`,
        `Thanks for reading. Reply anytime.`,
      ],
    },
  };
  const t = T[key];
  if (!t) throw new Error(`unknown step ${key}`);
  // Insert the code block after the paragraph that introduces it (ends with ":").
  const codeAfter = t.body.findIndex((b) => b.trim().endsWith(":"));
  const htmlParts: string[] = [];
  const textParts: string[] = [];
  t.body.forEach((b, i) => {
    htmlParts.push(P(esc(b).replace(/\n/g, "<br>").replace(/(https:\/\/[^\s<]+)/g, (u) => `<a href="${u}" style="color:#0b6e5c">${u}</a>`)));
    textParts.push(b);
    if (t.code && i === codeAfter) { htmlParts.push(CODE(t.code)); textParts.push(t.code); }
  });
  if (t.code && codeAfter === -1) { htmlParts.push(CODE(t.code)); textParts.push(t.code); }
  if (t.cta) htmlParts.push(BTN(buy.url, buy.label));
  htmlParts.push(P("Renzo"));
  textParts.push("Renzo");
  return { subject: t.subject, html: wrap(htmlParts.join(""), unsubPage, t.body[1]?.slice(0, 100) ?? ""), text: textParts.join("\n\n") + textFooter(unsubPage) };
}

// ------------------------------------------------------------------ Stripe: onboarding, recovery, alert
export function onboardingEmail(o: { short_id: string; tier: string; tierName: string; amount: number; nombre?: string | null }) {
  const days = o.tier === "fixpack" ? "48 hours" : o.tier === "hardening" ? "5 business days" : "10 business days";
  const extra = o.tier === "hardening"
    ? ["For the live test: a written OK (a reply saying \"you may test project <ref> with our anon key\") and the project's anon (public) key."]
    : o.tier === "fleet"
    ? ["The list of up to 10 client projects: for each one the repo, the Supabase project ref and the agency name to put on the report."]
    : [];
  const need = [
    "The GitHub repo (URL).",
    "Access: invite the GitHub user Perufitlife as a collaborator (read access is enough; we open the pull request from a fork if you prefer), or send a fine-grained personal access token with read-only access to that repo.",
    "Your Supabase project ref (Dashboard → Project Settings → General → Reference ID).",
    ...extra,
  ];
  const name = (o.nombre ?? "").trim().split(/\s+/)[0] || "there";
  const subject = `Order ${o.short_id}: what I need to start your ${o.tierName}`;
  const html = wrap(
    P(`Hi ${esc(name)},`) + P(`Thank you. Your ${esc(o.tierName)} order <b>${esc(o.short_id)}</b> ($${o.amount.toLocaleString("en-US")}) is confirmed. To start, reply to this email with:`) +
    `<ol style="margin:0 0 14px;padding-left:20px">${need.map((s) => `<li style="margin:0 0 8px">${esc(s)}</li>`).join("")}</ol>` +
    P(`We never need your service_role key or your database password, and we don't touch production: everything arrives as a pull request you review and merge.`) +
    P(`<b>Timing:</b> delivery within ${days}, counted from when we have access. If we're late, you get a full refund.`) +
    P(`I'll confirm as soon as I have access.<br>Renzo`));
  const text = `Hi ${name},

Thank you. Your ${o.tierName} order ${o.short_id} ($${o.amount.toLocaleString("en-US")}) is confirmed. To start, reply to this email with:

${need.map((s, i) => `${i + 1}. ${s}`).join("\n")}

We never need your service_role key or your database password, and we don't touch production: everything arrives as a pull request you review and merge.

Timing: delivery within ${days}, counted from when we have access. If we're late, you get a full refund.

I'll confirm as soon as I have access.
Renzo${textFooter()}`;
  return { subject, html, text };
}

export function recoveryEmail(o: { tier: string; tierName: string; url: string; nombre?: string | null }, unsubPage?: string) {
  const name = (o.nombre ?? "").trim().split(/\s+/)[0] || "there";
  const subject = `Your ${o.tierName} checkout: anything I can answer?`;
  const body = [
    `Hi ${name}, you started the ${o.tierName} checkout and didn't finish. No pressure, one email only.`,
    `If something stopped you (the price, what access we need, timing, an invoice for your company), reply and I'll answer myself. Common ones: we never need your service_role key or database password, everything arrives as a pull request, and late delivery means a full refund.`,
    `If you just got interrupted, here is the link again: ${o.url}`,
    `Renzo`,
  ];
  return {
    subject,
    html: wrap(body.map((b) => P(esc(b).replace(/(https:\/\/[^\s<]+)/g, (u) => `<a href="${u}" style="color:#0b6e5c">${u}</a>`))).join(""), unsubPage),
    text: body.join("\n\n") + textFooter(unsubPage),
  };
}

export function alertEmail(title: string, lines: [string, unknown][], footer = "") {
  const rows = lines.map(([k, v]) => `<tr><td style="padding:4px 10px 4px 0;color:#66737f;vertical-align:top;white-space:nowrap">${esc(k)}</td><td style="padding:4px 0">${esc(typeof v === "string" ? v : JSON.stringify(v))}</td></tr>`).join("");
  return {
    subject: title,
    html: `<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5;color:#0f1b26;max-width:680px"><h2 style="font-size:17px">${esc(title)}</h2><table style="border-collapse:collapse">${rows}</table>${footer ? `<p style="margin-top:16px;padding:10px 12px;background:#e2f1ec;border-radius:6px"><b>${esc(footer)}</b></p>` : ""}</div>`,
    text: `${title}\n\n${lines.map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n")}\n\n${footer}`,
  };
}
