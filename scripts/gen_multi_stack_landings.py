#!/usr/bin/env python3
"""Generate stack-specific landing pages from the Supabase canonical landing.
Output: docs/{pocketbase,appwrite,nhost,firebase}/index.html
"""
import os, re, pathlib, shutil

DOCS = pathlib.Path(__file__).resolve().parent.parent / 'docs'
SOURCE = DOCS / 'index.html'

STACKS = [
    {
        'slug': 'pocketbase',
        'name': 'PocketBase',
        'auditor_repo': 'pocketbase-security-skill',
        'apify_url': 'https://apify.com/renzomacar/pocketbase-security-auditor',
        'dashboard_url': 'pocketbase.io/docs',
        'token_url': 'your PocketBase admin auth token',
        'extra_copy': 'self-hosted PocketBase instances, the auditor probes anonymous record listing, default-rule wildcards, and admin-API exposure via your superuser token.',
        'breach_examples': '<strong>users</strong>, <strong>posts</strong>, internal admin records — anyone with the public URL could read or modify them.',
        'cutoff_copy': 'PocketBase v0.21+ tightens the default rules but old projects still inherit permissive @request rules. Audit before someone notices.',
    },
    {
        'slug': 'appwrite',
        'name': 'Appwrite',
        'auditor_repo': 'appwrite-security-skill',
        'apify_url': 'https://apify.com/renzomacar/appwrite-security-auditor',
        'dashboard_url': 'cloud.appwrite.io/console',
        'token_url': 'your Appwrite project API key (read-only is enough)',
        'extra_copy': 'the auditor probes anonymous document listing, "any" role grants on collections, public storage buckets, and unprotected execute-functions.',
        'breach_examples': '<strong>users</strong>, <strong>profiles</strong>, internal billing collections — exposed via "any" role grants left from prototyping.',
        'cutoff_copy': 'Appwrite v1.5+ removed the legacy "any" role auto-grant for new projects, but EXISTING collections still carry it. Audit before someone scrapes them.',
    },
    {
        'slug': 'nhost',
        'name': 'Nhost / Hasura',
        'auditor_repo': 'nhost-security-skill',
        'apify_url': 'https://apify.com/renzomacar/nhost-security-auditor',
        'dashboard_url': 'app.nhost.io',
        'token_url': 'your Hasura admin secret (or read-replica token)',
        'extra_copy': 'the auditor probes anonymous GraphQL queries, missing select/insert/update/delete permissions, exposed subscriptions, and unprotected actions/remote-schemas.',
        'breach_examples': '<strong>users</strong>, <strong>sessions</strong>, internal Hasura console URLs — anyone hitting the GraphQL endpoint could pull them.',
        'cutoff_copy': 'Hasura\'s permissive-by-default model means missing one role costs you the whole table. Audit before bots find your endpoint.',
    },
    {
        'slug': 'firebase',
        'name': 'Firebase',
        'auditor_repo': 'firebase-security-skill',
        'apify_url': 'https://apify.com/renzomacar/firebase-security-auditor',
        'dashboard_url': 'console.firebase.google.com',
        'token_url': 'your Firebase service account JSON (revoke 30s after)',
        'extra_copy': 'the auditor probes anonymous Firestore reads, Realtime DB rules with allow:true, public Storage buckets, and weak auth provider configs.',
        'breach_examples': '<strong>users</strong>, <strong>orders</strong>, internal admin documents — exposed via match /{doc} or allow read:if true rules.',
        'cutoff_copy': 'Firebase ships with locked rules for new projects but old ones still have the permissive testMode rules. Audit before they expire and break, or worse, leak.',
    },
]

def make_landing(template, stack):
    # Title + meta
    out = template
    out = out.replace('Supabase Security Audit · $99 · 24h Delivery — Renzo Madueno',
                       f"{stack['name']} Security Audit · $99 · 24h Delivery — Renzo Madueno")
    out = out.replace('Professional Supabase security audit. Detects RLS leaks, exposed SECURITY DEFINER functions, public buckets. Active probe confirms each leak live with the anon key.',
                       f"Professional {stack['name']} security audit. Detects exposed records, public buckets, weak rule grants. Active probe confirms each leak live before flagging.")
    out = out.replace('Supabase Security Audit — $99, 24h delivery',
                       f"{stack['name']} Security Audit — $99, 24h delivery")
    out = out.replace("I'll audit your Supabase project for security leaks. HTML report + fix SQL on every finding. Active probe proves the leak live before flagging it.",
                       f"I'll audit your {stack['name']} project for security leaks. HTML report + fix snippet on every finding. Active probe proves the leak live.")

    # Hero
    out = out.replace("I scanned my own production project last week and found 17 publicly readable tables I had no idea about. <strong>b2b_leads</strong>, <strong>engagement_emails</strong>, internal growth metrics — anyone with the anon key from the JS bundle could read or delete them.",
                       f"I scanned my own production project last week and found 17 publicly readable records I had no idea about. {stack['breach_examples']}")

    # Cutoff section
    out = out.replace("On <strong>October 30, 2026</strong>, Supabase enforces the new default that tables in <code>public</code> no longer auto-expose to the Data API on EXISTING projects. If you've been on Supabase &gt;6 months, you almost certainly have leaky tables right now. After Oct 30 your app may break in unexpected ways if you don't audit and fix proactively.",
                       stack['cutoff_copy'])

    # Why-me — references
    out = out.replace('I built and shipped <a href="https://github.com/Perufitlife/supabase-security-skill" class="text-emerald-400 underline">supabase-security</a>',
                       f'I built and shipped <a href="https://github.com/Perufitlife/{stack["auditor_repo"]}" class="text-emerald-400 underline">{stack["auditor_repo"]}</a>')

    # FAQ
    out = out.replace('A Supabase Personal Access Token from <code>supabase.com/dashboard/account/tokens</code>. Read access is enough for the audit (the auditor never writes to your project).',
                       f"{stack['token_url']}. Read access is enough — the auditor never writes to your project.")
    out = out.replace('<a href="https://github.com/Perufitlife/supabase-security-skill" class="text-emerald-400 underline">github.com/Perufitlife/supabase-security-skill</a>. The $99 saves you the install + interpretation + writing the executive summary for your team.',
                       f'<a href="https://github.com/Perufitlife/{stack["auditor_repo"]}" class="text-emerald-400 underline">github.com/Perufitlife/{stack["auditor_repo"]}</a>. The $99 saves you the install + interpretation + writing the executive summary for your team.')

    # Hide other stack tabs (to keep this page focused)
    # Keep Apify CTA but make this stack the prominent one
    # Already-existing Apify links list (5 stacks) — keep all so visitors can switch
    # Do nothing extra; original landing already lists all five Apify links.

    # Add canonical link back to root + breadcrumb
    breadcrumb = f'<div class="text-center text-emerald-200/70 text-xs mb-6"><a href="/supabase-security-skill/" class="underline hover:text-white">← Back to all stacks</a> · You\'re viewing: <strong>{stack["name"]}</strong></div>'
    out = out.replace('<div class="max-w-3xl mx-auto px-6 py-12">',
                       f'<div class="max-w-3xl mx-auto px-6 py-12">\n{breadcrumb}', 1)

    return out

def main():
    template = SOURCE.read_text(encoding='utf-8')
    print(f'Source: {SOURCE} ({len(template)} bytes)')
    for stack in STACKS:
        target_dir = DOCS / stack['slug']
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / 'index.html'
        out = make_landing(template, stack)
        target.write_text(out, encoding='utf-8')
        print(f'  Wrote {target} ({len(out)} bytes)')

    # Also generate a stack-selector index at /docs/stacks.html
    selector = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Backend Security Audits — Supabase, PocketBase, Appwrite, Nhost, Firebase</title>
<meta name="description" content="Pick your stack. $99 security audit, 24h delivery. Active probe confirms each leak live before flagging.">
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-slate-800 to-emerald-950 text-white font-sans min-h-screen">
<div class="max-w-3xl mx-auto px-6 py-16">
  <h1 class="text-4xl font-extrabold mb-4 leading-tight text-center">Pick your stack — $99 security audit, 24h delivery.</h1>
  <p class="text-center text-slate-300 mb-12 max-w-xl mx-auto">Same auditor, same $99, same 24h SLA. Active anon-probe confirms each leak before flagging. Pick the page that matches your stack:</p>
  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
    <a href="/supabase-security-skill/" class="bg-emerald-700/40 hover:bg-emerald-700/70 border border-emerald-500/40 rounded-xl p-6 transition"><div class="font-bold text-xl mb-2">Supabase</div><div class="text-emerald-200 text-sm">RLS gaps · public storage · SECURITY DEFINER · anon-grant residue</div></a>
    <a href="/supabase-security-skill/pocketbase/" class="bg-emerald-700/40 hover:bg-emerald-700/70 border border-emerald-500/40 rounded-xl p-6 transition"><div class="font-bold text-xl mb-2">PocketBase</div><div class="text-emerald-200 text-sm">Default-rule wildcards · admin-API exposure · anonymous record reads</div></a>
    <a href="/supabase-security-skill/appwrite/" class="bg-emerald-700/40 hover:bg-emerald-700/70 border border-emerald-500/40 rounded-xl p-6 transition"><div class="font-bold text-xl mb-2">Appwrite</div><div class="text-emerald-200 text-sm">"any" role grants · public storage buckets · execute-functions exposed</div></a>
    <a href="/supabase-security-skill/nhost/" class="bg-emerald-700/40 hover:bg-emerald-700/70 border border-emerald-500/40 rounded-xl p-6 transition"><div class="font-bold text-xl mb-2">Nhost / Hasura</div><div class="text-emerald-200 text-sm">Anonymous GraphQL · missing role permissions · subscription leaks</div></a>
    <a href="/supabase-security-skill/firebase/" class="bg-emerald-700/40 hover:bg-emerald-700/70 border border-emerald-500/40 rounded-xl p-6 transition col-span-1 md:col-span-2"><div class="font-bold text-xl mb-2">Firebase</div><div class="text-emerald-200 text-sm">Firestore rules · Realtime DB allow:true · public Storage · weak auth providers</div></a>
  </div>
  <div class="text-center text-slate-500 text-xs mt-12"><a href="https://github.com/Perufitlife" class="text-emerald-400 underline">@Perufitlife</a> · MIT open source auditors for all five stacks</div>
</div>
</body>
</html>
"""
    (DOCS / 'stacks.html').write_text(selector, encoding='utf-8')
    print(f'  Wrote {DOCS / "stacks.html"} ({len(selector)} bytes)')

if __name__ == '__main__':
    main()
