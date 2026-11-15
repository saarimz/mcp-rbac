#!/usr/bin/env node
// Static docs site: renders the repo's Markdown docs to site/ (no server, no network), rewrites .md links to .html,
// copies linked assets, and FAILS on broken relative links or missing #anchors. Usage: node tools/docs-site/build.mjs [outDir]
import { marked } from "marked";
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, rmSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, posix } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = resolve(process.argv[2] ?? join(ROOT, "site"));
const ENTRY = ["docs/README.md", "README.md", "AGENTS.md", "SECURITY.md", "CHANGELOG.md", "spec/tool-semantics.md"];

const slug = (s) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/[^\p{L}\p{N}\s_-]/gu, "").trim().replace(/\s/g, "-");
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// crawl: every .md reachable by relative links from ENTRY (inside the repo, not node_modules)
const pages = new Map(); // repo-relative path -> { md, links: [] }
const assets = new Set();
const queue = [...ENTRY];
const linkRe = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
while (queue.length) {
  const p = queue.shift();
  if (pages.has(p)) continue;
  const md = readFileSync(join(ROOT, p), "utf8");
  pages.set(p, { md });
  const noCode = md.replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  for (const m of noCode.matchAll(linkRe)) {
    const href = m[1];
    if (/^[a-z]+:/i.test(href) || href.startsWith("#")) continue;
    const [path] = href.split("#");
    const target = posix.normalize(posix.join(posix.dirname(p), decodeURI(path)));
    if (target.startsWith("..") || target.includes("node_modules")) continue;
    if (!existsSync(join(ROOT, target))) continue; // reported in the check pass
    if (target.endsWith(".md")) queue.push(target);
    else if (statSync(join(ROOT, target)).isFile()) assets.add(target);
  }
}

// headings -> ids (GitHub style, with -1, -2 for duplicates)
const anchors = new Map();
for (const [p, pg] of pages) {
  const ids = new Set();
  const seen = new Map();
  for (const t of marked.lexer(pg.md)) {
    if (t.type !== "heading") continue;
    let id = slug(t.text);
    const n = seen.get(id) ?? 0;
    seen.set(id, n + 1);
    if (n) id = `${id}-${n}`;
    ids.add(id);
  }
  anchors.set(p, ids);
}

const errors = [];
const nav = marked.parse(readFileSync(join(ROOT, "docs/README.md"), "utf8").replace(/^# .*\n/, "").split("\n").filter((l) => !/^Build the browsable|^below is also/.test(l)).join("\n"));

function rewrite(p, href) {
  if (/^[a-z]+:/i.test(href)) return href;
  if (href.startsWith("#")) {
    if (!anchors.get(p).has(href.slice(1))) errors.push(`${p}: missing anchor ${href}`);
    return href;
  }
  const [path, frag] = href.split("#");
  const target = posix.normalize(posix.join(posix.dirname(p), decodeURI(path)));
  if (!existsSync(join(ROOT, target))) { errors.push(`${p}: broken link ${href}`); return href; }
  if (target.endsWith(".md") && pages.has(target)) {
    if (frag && !anchors.get(target).has(frag)) errors.push(`${p}: missing anchor ${href}`);
    const outRel = posix.relative(posix.dirname(p), target.replace(/\.md$/, ".html"));
    return outRel + (frag ? `#${frag}` : "");
  }
  return href; // asset or directory: copied / left as a repo-relative link
}

rmSync(OUT, { recursive: true, force: true });
for (const [p, pg] of pages) {
  const seen = new Map();
  const renderer = {
    heading({ tokens, depth, text }) {
      let id = slug(text);
      const n = seen.get(id) ?? 0;
      seen.set(id, n + 1);
      if (n) id = `${id}-${n}`;
      return `<h${depth} id="${id}"><a class="h" href="#${id}">#</a> ${this.parser.parseInline(tokens)}</h${depth}>\n`;
    },
    link({ href, title, tokens }) {
      return `<a href="${esc(rewrite(p, href))}"${title ? ` title="${esc(title)}"` : ""}>${this.parser.parseInline(tokens)}</a>`;
    },
    image({ href, text }) { return `<img src="${esc(rewrite(p, href))}" alt="${esc(text)}">`; },
  };
  marked.use({ renderer, gfm: true });
  const body = marked.parse(pg.md);
  const outFile = p === "docs/README.md" ? "index.html" : p.replace(/\.md$/, ".html");
  const depthPrefix = posix.relative(posix.dirname(outFile), ".") || ".";
  const navHtml = nav.replace(/href="([^"]+)"/g, (_, h) => {
    if (/^[a-z]+:/i.test(h)) return `href="${h}"`;
    const [path, frag] = h.split("#");
    const t = posix.normalize(posix.join("docs", path));
    const html = t === "docs/README.md" ? "index.html" : t.replace(/\.md$/, ".html");
    return `href="${posix.join(depthPrefix, html)}${frag ? "#" + frag : ""}"`;
  });
  const title = (pg.md.match(/^# (.+)$/m)?.[1] ?? p).replace(/`/g, "");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · mcp-rbac</title><link rel="stylesheet" href="${posix.join(depthPrefix, "style.css")}"></head>
<body><nav><a class="brand" href="${posix.join(depthPrefix, "index.html")}">mcp-rbac</a>${navHtml}</nav><main>${body}
<footer>Source: <code>${esc(p)}</code></footer></main></body></html>\n`;
  mkdirSync(dirname(join(OUT, outFile)), { recursive: true });
  writeFileSync(join(OUT, outFile), html);
}
// docs/README.md also gets an html twin at its own path for links like ../docs/README.md
for (const a of assets) { mkdirSync(dirname(join(OUT, a)), { recursive: true }); copyFileSync(join(ROOT, a), join(OUT, a)); }
writeFileSync(join(OUT, "style.css"), `body{margin:0;display:flex;font:15px/1.6 system-ui,sans-serif;color:#1a1a1a}
nav{width:270px;flex:none;height:100vh;position:sticky;top:0;overflow:auto;padding:16px;border-right:1px solid #e5e5e5;background:#fafafa;font-size:14px}
nav h2{font-size:12px;text-transform:uppercase;color:#666;margin:18px 0 4px}nav ul{padding-left:16px;margin:0}nav .brand{font-weight:700;font-size:18px;text-decoration:none;color:#111}
nav h2 a.h{display:none}main{max-width:900px;padding:24px 40px;min-width:0}pre{background:#f5f5f5;padding:12px;overflow:auto;border-radius:6px}
code{font-family:ui-monospace,monospace;font-size:13px}table{border-collapse:collapse;display:block;overflow:auto}td,th{border:1px solid #ddd;padding:4px 8px;vertical-align:top}
a.h{color:#bbb;text-decoration:none;font-size:.8em}img{max-width:100%}footer{margin-top:40px;color:#888;font-size:12px}
@media(max-width:800px){body{display:block}nav{width:auto;height:auto;position:static}}`);
console.log(`docs site: ${pages.size} pages, ${assets.size} assets -> ${relative(ROOT, OUT) || OUT}`);
if (errors.length) { console.error(`${errors.length} link problem(s):\n  ` + [...new Set(errors)].join("\n  ")); process.exit(1); }
