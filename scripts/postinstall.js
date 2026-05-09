#!/usr/bin/env node
// Postinstall hook — prints a friendly nudge to actually run the auditor.
// Skipped silently in CI to not pollute deploy logs.

if (process.env.CI || process.env.NODE_ENV === 'production') process.exit(0);

const lines = [
  "",
  "  ┌──────────────────────────────────────────────────────────────────────────┐",
  "  │  ✓ supabase-security installed                                          │",
  "  │                                                                          │",
  "  │  Run it now (read-only PAT, never persisted):                            │",
  "  │    npx supabase-security <project-ref> --html report.html                │",
  "  │                                                                          │",
  "  │  No-install version (browser, no npm):                                   │",
  "  │    https://apify.com/renzomacar/supabase-security-auditor                │",
  "  │                                                                          │",
  "  │  Want me to run it for you and send back a written report? $99, 24h:    │",
  "  │    https://perufitlife.github.io/supabase-security-skill/                │",
  "  └──────────────────────────────────────────────────────────────────────────┘",
  ""
].join("\n");

process.stdout.write(lines);
