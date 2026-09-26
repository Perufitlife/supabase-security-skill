#!/usr/bin/env node
// Postinstall hook — prints a friendly nudge to actually run the auditor.
// Skipped silently in CI to not pollute deploy logs.

if (process.env.CI || process.env.NODE_ENV === 'production') process.exit(0);

const lines = [
  "",
  "  ┌──────────────────────────────────────────────────────────────────────────┐",
  "  │  ✓ supabase-security installed                                          │",
  "  │                                                                          │",
  "  │  Oct 30, 2026 grants change: lint your migrations (no token needed):     │",
  "  │    npx supabase-security migrations                                      │",
  "  │                                                                          │",
  "  │  Live audit with active anon probe (read-only PAT, never persisted):     │",
  "  │    npx supabase-security <project-ref> --html report.html                │",
  "  │                                                                          │",
  "  │  Want this done + reviewed for you?                                      │",
  "  │    https://perufitlife.github.io/supabase-security-skill/oct30/          │",
  "  └──────────────────────────────────────────────────────────────────────────┘",
  ""
].join("\n");

process.stdout.write(lines);
