# Hacker News Show post

**Title:** Show HN: Local Supabase security auditor (250 lines, no deps, no SaaS)

**URL:** https://github.com/Perufitlife/supabase-security-skill

**Comment (first reply by author):**

I built this after Supabase's May 2026 changelog announcing that tables in the public schema will stop being auto-exposed to the Data API — May 30 for new projects, October 30 enforced on all existing.

My reaction was "doesn't affect me, RLS is on" — but then I actually checked, and found 17 tables on a public web app of mine that had RLS disabled with default anon CRUD grants. Anyone could pull the anon key out of the JS bundle and read/write `b2b_leads`, `engagement_emails`, internal growth metrics, etc.

The script is plain Node.js, no dependencies, ~250 lines. Reads `pg_class`, `pg_policies`, `pg_proc`, `pg_default_acl`, and the Supabase Management API for storage/auth. Outputs JSON or a self-contained HTML report (Tailwind + Chart.js via CDN, ~25KB) with copy-paste SQL fix on every finding.

Why local instead of SaaS scanners (SupaExplorer, AuditYourApp, etc.):
- The token + project ref never leave your machine. Only network calls go to api.supabase.com.
- CI-friendly — drop into a GitHub Action.
- Audit the source before running. 250 lines of plain Node.

Honest limits: alpha, no per-object storage RLS, no edge function secret scanning yet, false positives for intentional `SECURITY DEFINER` exposed RPCs. Roadmap is in the README.

Curious what other Supabase users find when they run it. I'd guess most projects older than ~3 months have at least one critical finding.
