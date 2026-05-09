# LinkedIn post — versión A (la real, vulnerable)

Yesterday I scanned my own Supabase project for the first time.

Found 17 tables that anyone with the anon key from my bundled JS could read, write, or delete.

`b2b_leads`. `engagement_emails`. `winback_queue`. The kind of tables you do NOT want exposed.

How? Supabase's default has been to auto-grant CRUD on new public tables to the `anon` role. Most projects rely on Row Level Security as the safety net. On 17 of mine, I'd forgotten to enable it.

Supabase is changing this default — May 30, 2026 for new projects, October 30 for all existing projects. But that won't fix what's already there. Existing grants stay.

So I wrote a 250-line Node.js script to actually check. Open source, MIT, no SaaS, your token never leaves your machine. Generates an HTML report with copy-paste fix SQL.

If you've been on Supabase more than 3 months, run it. You'll probably find at least one.

→ github.com/Perufitlife/supabase-security-skill

#supabase #security #postgres #opensource

---

# LinkedIn post — versión B (más corta, sin admisión vulnerable)

The Supabase team announced two upcoming defaults changes:

→ May 30, 2026: new tables in `public` no longer auto-exposed to the Data API.
→ October 30, 2026: enforced on all existing projects.

For projects older than ~3 months, this likely means you have tables granted CRUD to `anon` by default that you never explicitly intended to expose. RLS catches most of it, but not all.

I wrote an open-source Node.js auditor to find these. Runs locally with a Personal Access Token. 250 lines, zero dependencies, MIT. Outputs an HTML report with copy-paste fix SQL.

→ github.com/Perufitlife/supabase-security-skill

#supabase #postgres #databasesecurity
