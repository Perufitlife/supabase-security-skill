// Minimal read-only IMAP client: "did this address write to Renzo's inbox since <date>?"
// Used by oct30-nurture to stop the sequence when a lead replies (reply-to is Renzo's Gmail).
export class Imap {
  private conn!: Deno.TlsConn;
  private buf = "";
  private tag = 0;
  private dec = new TextDecoder();
  private enc = new TextEncoder();

  async open(user: string, pass: string, host = "imap.gmail.com") {
    this.conn = await Deno.connectTls({ hostname: host, port: 993 });
    await this.readUntil(/^\* OK/m);
    const r = await this.cmd(`LOGIN ${this.q(user)} ${this.q(pass)}`);
    if (!r.ok) throw new Error("IMAP login failed");
    const s = await this.cmd(`EXAMINE INBOX`);
    if (!s.ok) throw new Error("IMAP EXAMINE failed");
  }
  private q(s: string) { return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`; }
  private async readUntil(re: RegExp, ms = 15000): Promise<string> {
    const deadline = Date.now() + ms;
    const chunk = new Uint8Array(16384);
    while (!re.test(this.buf)) {
      if (Date.now() > deadline) throw new Error("IMAP timeout");
      const n = await this.conn.read(chunk);
      if (n === null) throw new Error("IMAP closed");
      this.buf += this.dec.decode(chunk.subarray(0, n));
    }
    const m = re.exec(this.buf)!;
    const end = this.buf.indexOf("\n", m.index);
    const out = this.buf.slice(0, end === -1 ? this.buf.length : end + 1);
    this.buf = this.buf.slice(out.length);
    return out;
  }
  private async cmd(c: string): Promise<{ ok: boolean; text: string }> {
    const t = `a${++this.tag}`;
    await this.conn.write(this.enc.encode(`${t} ${c}\r\n`));
    const text = await this.readUntil(new RegExp(`^${t} (OK|NO|BAD)`, "m"));
    return { ok: new RegExp(`^${t} OK`, "m").test(text), text };
  }
  async hasMailFrom(email: string, since: Date): Promise<boolean> {
    const M = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const d = `${since.getUTCDate()}-${M[since.getUTCMonth()]}-${since.getUTCFullYear()}`;
    const r = await this.cmd(`SEARCH FROM ${this.q(email)} SINCE ${d}`);
    const line = /^\* SEARCH([ \d]*)$/m.exec(r.text.replace(/\r/g, ""));
    return !!line && line[1].trim().length > 0;
  }
  async close() {
    try { await this.cmd("LOGOUT"); } catch { /* */ }
    try { this.conn.close(); } catch { /* */ }
  }
}
