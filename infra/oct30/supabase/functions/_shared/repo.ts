// Read a PUBLIC GitHub repo's Supabase migrations without credentials:
// git smart-HTTP for the default branch + commit, jsDelivr for the file list and contents,
// the GitHub API / raw.githubusercontent.com as fallbacks.

export const LIMITS = { maxFiles: 400, maxBytes: 3 * 1024 * 1024, fetchMs: 25000 };

export interface RepoRef { owner: string; repo: string; branch?: string; sub?: string }
export interface Fetched {
  ok: boolean;
  reason?: "invalid_url" | "repo_unreadable" | "no_migrations" | "timeout" | "error";
  detail?: string;
  owner?: string; repo?: string; branch?: string; sha?: string;
  root?: string; source?: "migrations" | "sql_fallback";
  files?: { path: string; sql: string }[];
  total?: number; partial?: boolean; configToml?: string | null;
}

export function parseRepoUrl(input: string): RepoRef | null {
  let s = String(input || "").trim().replace(/^git\+/, "").replace(/^git@github\.com:/i, "https://github.com/");
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = s.replace(/^(www\.)?github\.com\//i, "");
  else {
    const u = (() => { try { return new URL(s); } catch { return null; } })();
    if (!u || !/^(www\.)?github\.com$/i.test(u.hostname)) return null;
    s = u.pathname.replace(/^\//, "");
  }
  const parts = s.split(/[?#]/)[0].split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0], repo = parts[1].replace(/\.git$/i, "");
  if (!/^[A-Za-z0-9-]{1,39}$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return null;
  const ref: RepoRef = { owner, repo };
  if ((parts[2] === "tree" || parts[2] === "blob") && parts[3]) {
    ref.branch = decodeURIComponent(parts[3]);
    if (parts.length > 4) ref.sub = parts.slice(4).map(decodeURIComponent).join("/");
  }
  return ref;
}

async function timed(url: string, ms: number, init: RequestInit = {}): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try { return await fetch(url, { ...init, signal: ac.signal, headers: { "user-agent": "supabase-security-oct30-check", ...(init.headers ?? {}) } }); }
  finally { clearTimeout(t); }
}

// Default branch + commit sha from the git smart-HTTP advertisement (public repos only; no API rate limit).
async function gitHead(o: string, r: string, branch?: string): Promise<{ status: number; branch?: string; sha?: string }> {
  const res = await timed(`https://github.com/${o}/${r}.git/info/refs?service=git-upload-pack`, 8000);
  if (res.status !== 200 || !res.body) { await res.body?.cancel(); return { status: res.status }; }
  const reader = res.body.getReader();
  let buf = "";
  const dec = new TextDecoder();
  while (buf.length < 512 * 1024) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    if (!branch && buf.includes("symref=HEAD:")) { if (/symref=HEAD:refs\/heads\/\S+/.test(buf)) break; }
    if (branch && buf.includes(`refs/heads/${branch}\n`)) break;
  }
  reader.cancel().catch(() => {});
  const head = /symref=HEAD:refs\/heads\/(\S+)/.exec(buf)?.[1];
  const b = branch ?? head;
  let sha: string | undefined;
  if (b) {
    const m = new RegExp(`([0-9a-f]{40}) refs/heads/${b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n`).exec(buf);
    sha = m?.[1];
    if (!sha && b === head) sha = /([0-9a-f]{40}) HEAD/.exec(buf)?.[1];
  }
  return { status: 200, branch: b, sha };
}

async function listFiles(o: string, r: string, ref: string, branch: string): Promise<{ path: string; size: number }[] | null> {
  try {
    const res = await timed(`https://data.jsdelivr.com/v1/packages/gh/${o}/${r}@${encodeURIComponent(ref)}?structure=flat`, 12000);
    if (res.ok) {
      const j = await res.json();
      if (Array.isArray(j.files)) return j.files.map((f: any) => ({ path: String(f.name).replace(/^\//, ""), size: Number(f.size) || 0 }));
    } else await res.body?.cancel();
  } catch { /* fall through */ }
  try {
    const tok = Deno.env.get("GH_READ_TOKEN");
    const res = await timed(`https://api.github.com/repos/${o}/${r}/git/trees/${encodeURIComponent(branch)}?recursive=1`, 12000,
      { headers: { accept: "application/vnd.github+json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) } });
    if (res.ok) {
      const j = await res.json();
      if (Array.isArray(j.tree)) return j.tree.filter((t: any) => t.type === "blob").map((t: any) => ({ path: t.path, size: t.size ?? 0 }));
    } else await res.body?.cancel();
  } catch { /* */ }
  return null;
}

// github.com serves the tree view as JSON to XHR clients; no API rate limit.
async function listDirWeb(o: string, r: string, branch: string, dir: string): Promise<{ path: string; size: number }[] | null> {
  try {
    const res = await timed(`https://github.com/${o}/${r}/tree/${encodeURIComponent(branch)}/${dir.split("/").map(encodeURIComponent).join("/")}`, 10000,
      { headers: { accept: "application/json", "x-requested-with": "XMLHttpRequest" } });
    if (!res.ok) { await res.body?.cancel(); return null; }
    const j = await res.json();
    const items = j?.payload?.tree?.items ?? j?.payload?.codeViewTreeRoute?.tree?.items;
    if (!Array.isArray(items)) return null;
    return items.filter((x: any) => x.contentType === "file").map((x: any) => ({ path: x.path, size: 0 }));
  } catch { return null; }
}

async function listDir(o: string, r: string, branch: string, dir: string): Promise<{ path: string; size: number }[] | null> {
  try {
    const tok = Deno.env.get("GH_READ_TOKEN");
    const res = await timed(`https://api.github.com/repos/${o}/${r}/contents/${dir.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(branch)}`, 10000,
      { headers: { accept: "application/vnd.github+json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) } });
    if (!res.ok) { await res.body?.cancel(); return null; }
    const j = await res.json();
    if (!Array.isArray(j)) return null;
    return j.filter((x: any) => x.type === "file").map((x: any) => ({ path: x.path, size: x.size ?? 0 }));
  } catch { return null; }
}

async function getText(o: string, r: string, ref: string, branch: string, path: string): Promise<string | null> {
  const enc = path.split("/").map(encodeURIComponent).join("/");
  for (const url of [`https://cdn.jsdelivr.net/gh/${o}/${r}@${ref}/${enc}`, `https://raw.githubusercontent.com/${o}/${r}/${ref === branch ? encodeURIComponent(branch) : ref}/${enc}`]) {
    try {
      const res = await timed(url, 10000);
      if (res.ok) return await res.text();
      await res.body?.cancel();
    } catch { /* next */ }
  }
  return null;
}

const MIG_RE = /^(.*?(?:^|\/)supabase\/migrations)\/.+\.sql$/i;
const SKIP_RE = /(^|\/)(node_modules|vendor|\.git|dist|build|\.next)\//i;

export async function fetchMigrations(input: string): Promise<Fetched> {
  const ref = parseRepoUrl(input);
  if (!ref) return { ok: false, reason: "invalid_url", detail: "Paste a github.com/owner/repo link" };
  const started = Date.now();
  const head = await gitHead(ref.owner, ref.repo, ref.branch).catch(() => ({ status: 0 } as { status: number; branch?: string; sha?: string }));
  if (head.status !== 200 || !head.branch) {
    return { ok: false, reason: "repo_unreadable", owner: ref.owner, repo: ref.repo, detail: head.status === 401 || head.status === 404 ? "private or not found" : `GitHub answered ${head.status || "nothing"}` };
  }
  const branch = head.branch;
  const cdnRef = head.sha ?? branch;
  let all = await listFiles(ref.owner, ref.repo, cdnRef, branch);
  if (!all) {
    // Too big for a full listing (jsDelivr caps packages at 50 MB): list just the conventional folder.
    const s = (ref.sub ?? "").replace(/\/+$/, "");
    const dir = /(^|\/)supabase\/migrations$/i.test(s) ? s : /(^|\/)supabase$/i.test(s) ? `${s}/migrations` : `${s ? s + "/" : ""}supabase/migrations`;
    all = (await listDirWeb(ref.owner, ref.repo, branch, dir)) ?? (await listDir(ref.owner, ref.repo, branch, dir));
    if (all) all.push({ path: dir.replace(/migrations$/i, "config.toml"), size: 0 });
  }
  if (!all) return { ok: false, reason: "error", owner: ref.owner, repo: ref.repo, branch, detail: "couldn't list the repo's files (too large for the free check?)" };
  const inSub = (p: string) => !ref.sub || p === ref.sub || p.startsWith(ref.sub.replace(/\/$/, "") + "/");

  // Group by migrations folder; pick the biggest (monorepos: apps/web/supabase/migrations).
  // supabase/migrations wins; any other "migrations" folder with SQL is second best.
  const pick = (re: RegExp) => {
    const groups = new Map<string, { path: string; size: number }[]>();
    for (const f of all!) {
      if (SKIP_RE.test(f.path) || !inSub(f.path)) continue;
      const m = re.exec(f.path);
      if (!m) continue;
      if (!groups.has(m[1])) groups.set(m[1], []);
      groups.get(m[1])!.push(f);
    }
    let k0 = "", v0: { path: string; size: number }[] = [];
    for (const [k, v] of groups) if (v.length > v0.length || (v.length === v0.length && k.length < k0.length)) { k0 = k; v0 = v; }
    return { root: k0, files: v0 };
  };
  let { root, files: picked } = pick(MIG_RE);
  let source: "migrations" | "sql_fallback" = "migrations";
  if (!picked.length) ({ root, files: picked } = pick(/^(.*?(?:^|\/)migrations)\/[^/]+\.sql$/i));
  const isSchema = (p: string) => /(^|\/)[^/]*schema[^/]*\.sql$/i.test(p) && !/(drop|delete|reset|danger)/i.test(p);
  if (picked.length && source === "migrations" && !MIG_RE.test(picked[0].path)) {
    // Generic migrations/ folder: a base schema.sql next to it usually runs first.
    const parent = root.replace(/\/?migrations$/i, "");
    const base = all.filter((f) => isSchema(f.path) && (parent ? f.path.startsWith(parent + "/") : !f.path.includes("/")) && f.path.split("/").length === (parent ? parent.split("/").length + 1 : 1));
    picked = [...base, ...picked.sort((a, b) => a.path.localeCompare(b.path))];
  } else picked.sort((a, b) => a.path.localeCompare(b.path));
  if (!picked.length) {
    // No migrations folder: any .sql under a supabase/ dir, or schema/migration-looking SQL files.
    picked = all.filter((f) => !SKIP_RE.test(f.path) && inSub(f.path) && /\.sql$/i.test(f.path) &&
      (/(^|\/)supabase\//i.test(f.path) || /(schema|migrat|setup|init|tables|policies|rls)[^/]*\.sql$/i.test(f.path)) &&
      !/(^|\/)(seed|test|tests|__tests__|fixtures?)[^/]*(\/|\.sql$)/i.test(f.path) && !/(drop|delete|reset|danger)[^/]*\.sql$/i.test(f.path)).slice(0, 60);
    if (!picked.length) return { ok: false, reason: "no_migrations", owner: ref.owner, repo: ref.repo, branch };
    picked.sort((a, b) => Number(isSchema(b.path)) - Number(isSchema(a.path)) || a.path.localeCompare(b.path));
    source = "sql_fallback";
    root = "(SQL files)";
  }
  const total = picked.length;
  let bytes = 0;
  const within: typeof picked = [];
  for (const f of picked) {
    if (within.length >= LIMITS.maxFiles || bytes + f.size > LIMITS.maxBytes) break;
    within.push(f); bytes += f.size;
  }
  const supaDir = source === "migrations" && /(^|\/)supabase\/migrations$/i.test(root) ? root.replace(/\/?migrations$/i, "") : "";
  const cfgPath = supaDir ? `${supaDir}/config.toml` : "";
  const hasCfg = !!cfgPath && all.some((f) => f.path === cfgPath);

  const out: { path: string; sql: string }[] = new Array(within.length);
  let i = 0, timedOut = false;
  const worker = async () => {
    while (i < within.length) {
      const k = i++;
      if (Date.now() - started > LIMITS.fetchMs) { timedOut = true; return; }
      const txt = await getText(ref.owner, ref.repo, cdnRef, branch, within[k].path);
      out[k] = { path: within[k].path, sql: txt ?? "" };
    }
  };
  const [configToml] = await Promise.all([
    hasCfg ? getText(ref.owner, ref.repo, cdnRef, branch, cfgPath) : Promise.resolve(null),
    ...Array.from({ length: 8 }, worker),
  ]);
  let kept = 0, realBytes = 0;
  for (const f of out) { if (!f) break; realBytes += f.sql.length; if (realBytes > LIMITS.maxBytes) break; kept++; }
  if (timedOut) return { ok: false, reason: "timeout", owner: ref.owner, repo: ref.repo, branch, detail: `read ${out.filter(Boolean).length} of ${within.length} files before the time limit` };
  return {
    ok: true, owner: ref.owner, repo: ref.repo, branch, sha: head.sha, root, source,
    files: out.slice(0, kept).filter((f) => f && f.sql), total, partial: kept < total, configToml,
  };
}

// [api] schemas = ["public", "api"] from supabase/config.toml (same logic as the CLI).
export function schemasFromToml(txt: string | null | undefined): string[] | null {
  if (!txt) return null;
  const sec = /^\s*\[api\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(txt);
  if (!sec) return null;
  const m = /^\s*schemas\s*=\s*\[([\s\S]*?)\]/m.exec(sec[1]);
  if (!m) return null;
  const list = [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1]).filter((s) => s !== "graphql_public" && s !== "storage");
  return list.length ? list : null;
}
