#!/usr/bin/env node
// Forward argv to audit.js's main(). Import is needed because audit.js
// only auto-invokes main() when run directly — going through cli.js
// breaks that check, so we call main() explicitly here.
import { main } from "./audit.js";
main().catch((e) => {
  console.error(e?.message || e);
  process.exit(1);
});
