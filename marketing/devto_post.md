---
title: "I scanned my own Supabase project and found 17 tables anyone could read with the anon key"
published: false
description: "I built a 250-line Node.js auditor after the May 2026 Supabase changelog. Ran it on my own apps. Discovered 17 publicly leaky tables I had no idea about. Here's what I learned, and the tool I wrote so you can do the same."
tags: supabase, security, postgres, opensource
canonical_url:
cover_image:
---

I run two SaaS products on Supabase. I've been on the platform for over a year. I'd like to think I know what I'm doing. Then Supabase published the [May 2026 update](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically) about tables in `public` no longer auto-exposing to the Data API.

Two deadlines:
- **May 30, 2026** — new behavior is the default for all *new* projects.
- **October 30, 2026** — enforced on *all existing projects*.

My first reaction: "ok cool, doesn't affect me, I have RLS on everything." Then I thought about it for a minute and went, "wait, do I?"

So I wrote a 250-line Node.js script to actually check.

## What it does

For a given Supabase project ref + Personal Access Token, it queries `pg_class`, `pg_policies`, `pg_proc`, `pg_default_acl`, and the storage/auth APIs to detect:

| Check | Severity |
|---|---|
| Table has RLS disabled and anon grants | **Critical** |
| `SECURITY DEFINER` function executable by anon | High |
| Public storage bucket | High |
| Default privileges still grant CRUD to anon (the Oct 30 thing) | Medium |
| Auth signups with autoconfirm | Medium |
| RLS-locked table with stale anon grants (defense-in-depth) | Low |

Output is a self-contained HTML report with copy-paste fix SQL on every finding plus an "apply all" bundle at the bottom. No SaaS, no upload, your token never leaves your machine. ~25KB single HTML file you can email to your team.

## The result on my own apps

| Project | Tables | Critical | High | Medium |
|---|---|---|---|---|
| Internal CRM (auth-only, never anon) | 55 | 0 | 11 | 2 |
| Public web app | 139 | **17** | 5 | 2 |

The public app had **seventeen tables with RLS disabled and anon CRUD grants**. Anyone who pulled the anon key out of the bundled JS could `SELECT *` them. The list included `b2b_leads`, `engagement_emails`, `winback_queue`, `growth_metrics`, `gsc_queries` — basically every internal table I'd added during the last six months of "move fast" iteration.

How? Two reasons.

**One:** Supabase's default for new tables created via the Dashboard or via SQL was, until this update, "auto-grant CRUD to `anon`." That's exactly the default behavior they're now changing. Every table I created relied on RLS to be the safety net, and on a small number of tables I forgot to flip it on.

**Two:** I never had a way to *see* this. The Supabase Dashboard advisor warns about RLS being off. It does not surface the combination of "RLS off **and** anon has direct grants." That combination is the actual leak.

## How I fixed it (and you can too)

```sql
ALTER TABLE public.b2b_leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.engagement_emails ENABLE ROW LEVEL SECURITY;
-- ... 15 more
```

Service role bypasses RLS, so backend crons keep working. With RLS enabled and zero policies, the table is locked to anything coming through PostgREST with the anon or authenticated keys. If specific rows need to be readable, you write a policy. Otherwise, RLS-on + zero-policies is the right state for internal-only tables.

I also adopted the new default behavior for future tables:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon, authenticated, service_role;
```

(Tables created via the Dashboard are owned by `supabase_admin` and need the dashboard toggle: *Project Settings → Data API → "Automatically expose new tables" = OFF*. The auditor flags this.)

## Why I wrote my own instead of using the existing scanners

There are good SaaS scanners — SupaExplorer, AuditYourApp, Vibe App Scanner. They work. But I wanted three things:

1. **My project ref and token never leave my machine.** SaaS scanners need both. I have no reason to distrust any of them, but a security tool that requires me to send credentials to a third party just to learn whether my doors are locked is a weird trade.
2. **CI-friendly.** I want to run this in a GitHub Action and fail builds when criticals appear.
3. **Auditable.** 250 lines of Node, no dependencies, on GitHub. Read it before you run it.

If those things matter to you, this might fit. If you'd rather click a button on a website and get a fancier report with subdomain discovery and team collab, the SaaS players have you covered.

## Try it

```bash
git clone https://github.com/Perufitlife/supabase-security-skill
cd supabase-security-skill
SUPABASE_ACCESS_TOKEN=sbp_xxx node scripts/audit.js YOUR_PROJECT_REF --html report.html
open report.html
```

(Get a token at `https://supabase.com/dashboard/account/tokens`. Read access is enough.)

## The honest pitch

This is alpha. It misses things. Edge functions, per-object storage RLS, `pg_cron` jobs, secrets in env vars — I want to add all of that. PRs welcome. False positives are real, especially for `SECURITY DEFINER` functions that are intentionally exposed to anon (your `get_public_stats()` RPC will appear as a finding — it's up to you to mark it intentional).

But on day one, before any of that, it found 17 holes in a project I thought was tight.

If you've been on Supabase for more than three months: run it. You will probably find at least one. October 30 is closer than it sounds.

Repo: [github.com/Perufitlife/supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill)
