# supabase-security

> Harden any Supabase project. Local-only, no SaaS, MIT. Lint your migrations with **no credentials**, or audit a live project with an active anon-key probe that confirms each leak.

[![npm](https://img.shields.io/npm/v/supabase-security?color=red)](https://www.npmjs.com/package/supabase-security) [![downloads](https://img.shields.io/npm/dw/supabase-security)](https://www.npmjs.com/package/supabase-security) [![GitHub stars](https://img.shields.io/github/stars/Perufitlife/supabase-security-skill?style=social)](https://github.com/Perufitlife/supabase-security-skill) [![Glama](https://img.shields.io/badge/Glama-approved-blueviolet)](https://glama.ai/mcp/servers/) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue)

## Oct 30, 2026: will your next migration break?

On **October 30, 2026** Supabase stops auto-granting new tables, views and sequences in `public` to `anon`, `authenticated` and `service_role` on **every existing project** ([changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)). New projects already work this way. Your existing tables keep their grants. What changes:

- every **new** table after Oct 30 answers `42501 permission denied` until you `GRANT` it, from the browser and from server code using the `service_role` key (only direct Postgres connections are unaffected);
- replaying your migrations on a **new project, preview branch or `db reset`** already gives you tables nobody can reach.

> **No terminal? Built it with Lovable, Bolt or Cursor?** Paste your GitHub repo link in the **[free Oct 30 check](https://perufitlife.github.io/supabase-security-skill/oct30/#check)**: you see the result in the page (red / amber / green) and get the full report, in plain English plus the SQL to fix it, by email. Public repos, no credentials.

One command, no token, nothing leaves your machine:

```bash
npx supabase-security migrations            # reads supabase/migrations
```

It replays your SQL migrations in order and reports, per object:

| Severity | What it catches |
|---|---|
| **CRITICAL** | Table granted to `anon`/`authenticated` with **RLS off**: the grant you add to silence 42501 publishes every row |
| HIGH | Table/view with **no GRANT** at all: new ones like it are unreachable after Oct 30, and already are on any fresh project/branch |
| HIGH | **The lazy fix**: `grant ... on all tables in schema public to anon` / `alter default privileges ... to anon` (Supabase's own rollback snippet) |
| HIGH | `SECURITY DEFINER` function callable by `anon`, including via `PUBLIC` (a plain `revoke ... from anon` doesn't stop it, and Oct 30 doesn't touch functions) |
| HIGH | View granted to clients without `security_invoker` (bypasses RLS); `serial` sequence missing `USAGE` (inserts fail) |
| MEDIUM | Materialized view with no grant, `SECURITY DEFINER` without `search_path` |

**The lazy fix reopens every hole.** When a table suddenly returns 42501, the quickest fix is a blanket `GRANT ... ON ALL TABLES ... TO anon`. That grant also covers every table where RLS was never turned on. This tool writes the other fix: **least-privilege grants that mirror your RLS policies**.

```
$ npx supabase-security migrations
 CRITICAL  public.notes  supabase/migrations/20251031000000_fix_permission_denied.sql:2
           Granted to anon, authenticated (via GRANT ... ON ALL TABLES at ...:10) but RLS is OFF:
           every row is readable and writable by anyone with the anon key.
           alter table public.notes enable row level security;

 HIGH      public.orders  supabase/migrations/20250101000000_init.sql:16
           No GRANT to anon/authenticated/service_role. New tables like this will be unreachable (42501)
           after Oct 30, and on any new project/branch replaying this migration already.
           grant select, insert on table public.orders to authenticated;  -- mirrors your RLS policies
           grant select, insert, update, delete on table public.orders to service_role;

 HIGH      ALL TABLES IN SCHEMA public  supabase/migrations/20251031000000_fix_permission_denied.sql:10
           GRANT ALL ON ALL TABLES ... TO anon, authenticated hands 3 existing object(s) to anyone with
           the anon key, RLS or not. The lazy fix reopens every hole.
           revoke all on all tables in schema public from anon, authenticated;
           grant select on table public.posts to anon;  -- what its RLS policies actually use

Summary: 1 critical · 2 high · 0 medium · 0 low   fail-on high: 3 failing
```

```bash
npx supabase-security migrations --fix-sql supabase/migrations/20261001000000_data_api_grants.sql  # proposed migration, review it
npx supabase-security migrations path/to/migrations --schemas public,api --json                     # other dirs / exposed schemas
npx supabase-security migrations --fail-on critical                                                 # exit 1 only on critical
```

Exposed schemas come from `[api] schemas` in `supabase/config.toml` (else `public`). Mark intentional exceptions with `-- supabase-security: ignore` above the statement, or `--ignore public.my_table`.

### Add it to your PRs in 30 seconds (no secrets)

```yaml
# .github/workflows/supabase-grants.yml
name: Supabase grants lint
on:
  pull_request:
    paths: ['supabase/**']
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Perufitlife/supabase-security-skill@main
        with:
          mode: migrations        # no project-ref, no token
          fail-on: high
```

You get inline annotations on the migration lines, a job summary, and the proposed migration as an artifact.

> **Rather check it in the browser?** [Free check by repo URL](https://perufitlife.github.io/supabase-security-skill/oct30/#check), report by email.
>
> **Want this done + reviewed for you?** I'll apply least-privilege grants, fix the RLS gaps and verify it on a branch before Oct 30 → [perufitlife.github.io/supabase-security-skill/oct30](https://perufitlife.github.io/supabase-security-skill/oct30/)

---

## Live project audit (needs a Personal Access Token)

```
$ supabase-security <project-ref> --html report.html
HTML report written to report.html
Findings: 0 critical, 5 high, 2 medium
```

The migration linter reads your SQL. The live audit reads what is actually deployed, including anything changed in the Dashboard. It then hits PostgREST with your anon key to prove each leak.

### What it finds (real example)

I ran this against my own apps. Two projects, similar size:

| Project | Tables | Critical | High | Medium |
|---|---|---|---|---|
| Internal CRM (auth-only) | 55 | 0 | 11 | 2 |
| Public web app | 139 | **17** before fix | 5 | 2 |

The public app had **17 tables with RLS disabled** and full CRUD to anon. Anyone who pulled the anon key out of the JS bundle could read them. I fixed them in one SQL transaction generated by this tool.

### Install

No install needed:

```bash
SUPABASE_ACCESS_TOKEN=sbp_xxx npx supabase-security YOUR_PROJECT_REF --html report.html
```

Or clone and run: `git clone https://github.com/Perufitlife/supabase-security-skill && cd supabase-security-skill && SUPABASE_ACCESS_TOKEN=sbp_xxx node scripts/audit.js YOUR_PROJECT_REF --html report.html`.

Or as an [Agent Skill](https://agentskills.io/) for Claude Code, Cursor or Cline (when published to the skills marketplace): `npx skills add Perufitlife/supabase-security-skill`. Then say: "audit my Supabase project ref `xxx`" or "lint my migrations for Oct 30".

Keyless variant for a local repo: `supabase-security --discover .` parses your code and probes only with the public anon key.

### Get a Personal Access Token

`https://supabase.com/dashboard/account/tokens` → "Generate new token". Read access is sufficient.

### Checks performed

| # | Check | Severity |
|---|---|---|
| 1 | Table has RLS disabled and anon grants | **CRITICAL** |
| 2 | SECURITY DEFINER function (non-trigger) executable by anon | HIGH |
| 3 | Public storage bucket | HIGH |
| 4 | Default privileges still grant CRUD to anon (future-table risk) | MEDIUM |
| 5 | Auth signups enabled without email confirmation | MEDIUM |
| 6 | RLS-locked table still has direct anon grants (defense-in-depth) | LOW |

Every finding ships with copy-paste fix SQL. The HTML report has a "Copy all SQL" button to apply everything in one go.

### Live audit in GitHub Actions

```yaml
- uses: Perufitlife/supabase-security-skill@v1.0.0-action
  with:
    project-ref: ${{ vars.SUPABASE_PROJECT_REF }}
    token: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
    fail-on: critical
```

## How it differs from the alternatives

| | This | SupaExplorer | AuditYourApp |
|---|---|---|---|
| Where your project ref goes | Your machine | Their SaaS | Their SaaS |
| Cost | Free, MIT | $6.75–$187 | $29/mo–$499 |
| Source code | Public | Closed | Closed |
| Generates fix SQL | Yes | Pro tier | Pro tier |
| Lints migrations before deploy | Yes, no credentials | No | No |
| Runs in CI | Trivially | API tier | API tier |

## Limits: read these before trusting it

- **Migration linter**: it's a replay of your SQL, not a Postgres. It skips `DO` blocks, dynamic `EXECUTE` and objects created outside migrations (Dashboard, extensions). Grants mirror your policies, and it can't know which tables you meant to be public. It treats a policy using `auth.uid()` as authenticated-only.
- Doesn't audit per-object Storage RLS (would mean iterating every file).
- Can't revoke `supabase_admin` default privileges via SQL. That needs the Dashboard toggle, and the report tells you so.
- App APIs that are intentionally exposed to anon (e.g. a `get_public_stats()` RPC) will appear as findings. **You decide which are intentional.**
- Alpha. If you find a false positive or missed check, open an issue with the SQL that triggers it and I'll fix it.

## Roadmap

- [x] Keyless migration linter for the Oct 30, 2026 change (`supabase-security migrations`)
- [ ] Storage object-level scan
- [ ] `pg_cron` scheduled-job audit
- [ ] Edge Function secrets scan (env var leak detection)
- [ ] MCP server with `audit` and `apply-fix` tools (preview + rollback)

## License

MIT.
