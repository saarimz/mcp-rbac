/** Local, read-only audit dashboard. Zero dependencies (node:http + inline HTML/JS). */
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { GuardStore } from "./store.js";

const PAGE = (nonce: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>mcp-rbac audit</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style nonce="${nonce}">
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8b93a1;--card:#171a21;--allow:#2ea043;--deny:#e5534b;--line:#262b36}
*{box-sizing:border-box}body{margin:0;font:13px/1.45 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:15px;margin:0 12px 0 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 10px}.stat b{font-size:15px}
form{display:flex;gap:8px;flex-wrap:wrap;padding:12px 20px;border-bottom:1px solid var(--line)}
input,select,button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
button{cursor:pointer}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:500;position:sticky;top:0;background:var(--bg)}tr:hover td{background:#141821}
.badge{display:inline-block;border-radius:999px;padding:1px 8px;font-weight:600;font-size:12px}.allow{background:#12361d;color:#56d364}.deny{background:#3d1416;color:#ff7b72}
.mut{color:var(--mut)}code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}.chain code{background:#1d2230;border-radius:4px;padding:0 4px;margin-right:4px}
pre{white-space:pre-wrap;word-break:break-all;margin:6px 0 0;background:#11141b;padding:8px;border-radius:6px;font:12px ui-monospace,monospace}
</style></head><body>
<header><h1>mcp-rbac · audit</h1><span class="stat">total <b id="s-total">–</b></span><span class="stat">allowed <b id="s-allow">–</b></span><span class="stat">denied <b id="s-deny">–</b></span><span class="stat">agents <b id="s-agents">–</b></span><span class="mut" id="updated"></span></header>
<form id="f"><input name="agent" placeholder="agent"><input name="user" placeholder="user"><input name="tool" placeholder="tool"><select name="decision"><option value="">any decision</option><option>allow</option><option>deny</option></select><input name="q" placeholder="search reason / chain / ref" size="28"><select name="limit"><option>100</option><option>500</option><option>2000</option></select><button>Filter</button><label class="mut"><input type="checkbox" id="auto" checked> auto-refresh</label></form>
<table><thead><tr><th>time</th><th>decision</th><th>agent</th><th>user</th><th>tool</th><th>reason</th><th>delegation chain</th><th>approval</th></tr></thead><tbody id="rows"></tbody></table>
<script nonce="${nonce}">
const el=(t,c,txt)=>{const e=document.createElement(t);if(c)e.className=c;if(txt!==undefined)e.textContent=txt;return e};
async function load(){
  const p=new URLSearchParams(new FormData(document.getElementById('f')));for(const [k,v] of [...p])if(!v)p.delete(k);
  const [rows,stats]=await Promise.all([fetch('/api/audit?'+p).then(r=>r.json()),fetch('/api/stats').then(r=>r.json())]);
  document.getElementById('s-total').textContent=stats.total;document.getElementById('s-allow').textContent=stats.allow;
  document.getElementById('s-deny').textContent=stats.deny;document.getElementById('s-agents').textContent=stats.agents;
  document.getElementById('updated').textContent='updated '+new Date().toLocaleTimeString();
  const tb=document.getElementById('rows');tb.replaceChildren();
  for(const e of rows){const tr=el('tr');
    tr.append(el('td','mut',new Date(e.ts).toLocaleString()));
    const d=el('td');d.append(el('span','badge '+e.decision,e.decision));tr.append(d);
    tr.append(el('td','',e.agent));tr.append(el('td','',e.user||''));const tt=el('td');tt.append(el('code','',e.tool));tr.append(tt);
    tr.append(el('td',e.decision==='deny'?'':'mut',e.reason));
    const ch=el('td','chain');(e.chain||[]).forEach(g=>ch.append(el('code','',g)));if(!(e.chain||[]).length)ch.append(el('span','mut','direct'));tr.append(ch);
    tr.append(el('td','mut',[e.approval,e.approver].filter(Boolean).join(' · ')));
    tr.style.cursor='pointer';tr.onclick=()=>{const n=tr.nextSibling;if(n&&n.dataset.detail){n.remove();return}
      const r=el('tr');r.dataset.detail='1';const td=el('td');td.colSpan=8;td.append(el('pre','',JSON.stringify(e,null,2)));r.append(td);tr.after(r)};
    tb.append(tr)}
}
document.getElementById('f').onsubmit=e=>{e.preventDefault();load()};
setInterval(()=>{if(document.getElementById('auto').checked)load()},3000);load();
</script></body></html>`;

export async function serveDashboard(store: GuardStore, o: { port?: number; host?: string } = {}) {
  const srv = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const sec = { "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY" };
      if (req.method !== "GET") { res.writeHead(405, sec); return res.end(); }
      if (url.pathname === "/") {
        const nonce = randomBytes(16).toString("base64");
        res.writeHead(200, { ...sec, "content-type": "text/html; charset=utf-8", "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'` });
        return res.end(PAGE(nonce));
      }
      if (url.pathname === "/api/audit") {
        const g = (k: string) => url.searchParams.get(k) || undefined;
        const d = g("decision");
        const rows = await store.queryAudit({ agent: g("agent"), user: g("user"), tool: g("tool"), q: g("q"), decision: d === "allow" || d === "deny" ? d : undefined, limit: Number(g("limit") ?? 100) || 100 });
        res.writeHead(200, { ...sec, "content-type": "application/json" });
        return res.end(JSON.stringify(rows));
      }
      if (url.pathname === "/api/stats") {
        const rows = await store.queryAudit({ limit: 5000 });
        const stats = { total: rows.length, allow: rows.filter((r) => r.decision === "allow").length, deny: rows.filter((r) => r.decision === "deny").length, agents: new Set(rows.map((r) => r.agent)).size };
        res.writeHead(200, { ...sec, "content-type": "application/json" });
        return res.end(JSON.stringify(stats));
      }
      res.writeHead(404, sec); res.end();
    } catch { if (!res.headersSent) { res.writeHead(500); res.end(); } }
  });
  await new Promise<void>((r) => srv.listen(o.port ?? 4319, o.host ?? "127.0.0.1", r));
  const { port } = srv.address() as AddressInfo;
  return { url: `http://${o.host ?? "127.0.0.1"}:${port}/`, close: () => new Promise<void>((r) => srv.close(() => r())) };
}
