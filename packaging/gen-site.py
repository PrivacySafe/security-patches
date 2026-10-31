#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: documentation site generator
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Builds a static HTML site from the READMEs, the changelog and the policy
# documents: a home page, tools grouped by kind of software, a CVE index, a
# short guide to how the tools work, the install guide, one page per tool with
# an at-a-glance box, one page per manual page, and a search that works
# offline. The site needs no server, loads nothing from other sites and has no
# tracking. Open site/index.html in a browser, or put the folder on any web
# server.
#
#   python3 packaging/gen-site.py [--out site] [--release 26.10.30-1.0.0] [--date 2026-10-30] [--base-path /docs/]
#
# --base-path is the folder the site is served from on your host (for example
# /security-patches/, or / at the root). It is only used to make 404.html work
# when your host serves it for a missing page several folders deep; leave it out
# when you do not use a custom 404 page.
#
# Needs Python 3 and markdown-it-py with linkify-it-py
# (python3 -m pip install markdown-it-py linkify-it-py). It follows CommonMark, the
# same rules GitHub and Codeberg use, so the pages render as the READMEs do there.
# Run it after you change a README, the changelog or a script header, then run
# packaging/check-site.py and commit the result.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import base64, datetime, hashlib, html, json, os, posixpath, re, shutil, subprocess, sys, textwrap
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from markdown_it import MarkdownIt
import psf_icons as I

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "site")
RELEASE = "26.10.30-1.0.0"; DATE = "2026-10-30"; BASE_PATH = ""; THEME = "standalone"; DOCS_ROOT = None; BASE_URL = ""
a = sys.argv[1:]
while a:
    if a[0] == "--out": OUT = os.path.abspath(a[1]); a = a[2:]
    elif a[0] == "--release": RELEASE = a[1]; a = a[2:]
    elif a[0] == "--date": DATE = a[1]; a = a[2:]
    elif a[0] == "--base-path": BASE_PATH = a[1]; a = a[2:]
    elif a[0] == "--theme": THEME = a[1]; a = a[2:]
    elif a[0] == "--docs-root": DOCS_ROOT = os.path.abspath(a[1]); a = a[2:]
    elif a[0] == "--base-url": BASE_URL = a[1]; a = a[2:]
    else: sys.exit("usage: gen-site.py [--out DIR] [--release X] [--date YYYY-MM-DD] [--base-path /folder/]")
LONGDATE = datetime.date.fromisoformat(DATE).strftime("%-d %B %Y")
APP = THEME == "privacysafe-app"
if THEME not in ("standalone", "privacysafe-app"): sys.exit("--theme is standalone or privacysafe-app")
if APP:
    BASE_URL = BASE_URL or "https://privacysafe.app/docs/security-patches/"
    if DOCS_ROOT: OUT = os.path.join(DOCS_ROOT, "security-patches")
    import psdocs_layout as L
REPO = "https://codeberg.org/PrivacySafe/security-patches"
SRC = REPO + "/src/branch/main/"
SITE = "PrivacySafe Security Patches"

# Kinds of software, in the order a visitor looks for them.
CATEGORIES = [
    ("Servers, proxies and network services", "Web servers, proxies, name servers, FTP, logging, databases and container hosts.",
     ["nginx", "nginx-ui", "haproxy", "tomcat", "trafficserver", "bind", "vsftpd", "rsyslog", "couchdb", "pulsar", "incus"]),
    ("Operating system, libraries and runtimes", "The kernel, system libraries, language runtimes and the certificate store.",
     ["linux-kernel", "openssl", "curl", "expat", "brotli", "heif", "pillow", "node", "php", "php/detect", "php/edge", "ruby", "pki"]),
    ("Content management and web applications", "WordPress, Joomla, Drupal and the other sites and services you host.",
     ["wordpress", "wordpress-pt", "joomla", "drupal", "grav", "craft", "basercms", "magento", "yootheme", "nextcloud", "roundcube", "zammad", "plex"]),
    ("Developer platforms, tools and supply chain", "Developer machines, build and CI systems, frameworks and packages.",
     ["claude-code-vsx", "ghostaction", "litellm", "openapi", "storybook", "jupyter", "sentry", "nextjs", "laravel", "django", "sagemaker", "gitea", "gitlab", "jenkins"]),
]
NAMES = {  # short names for the menu and the cards
    "wordpress": "WordPress core and plugins", "linux-kernel": "Linux kernel", "drupal": "Drupal", "grav": "Grav",
    "brotli": "Brotli", "ruby": "Ruby and GitLab regexp", "gitlab": "GitLab", "django": "Django REST framework",
    "jenkins": "Jenkins plugins", "joomla": "Joomla", "nextcloud": "Nextcloud Collabora", "php": "PHP2Shell",
    "php/detect": "PHP2Shell detection rules", "php/edge": "PHP2Shell edge guards", "heif": "libheif", "expat": "libexpat",
    "pulsar": "Apache Pulsar", "sentry": "Sentry for Next.js", "magento": "Magento and Adobe Commerce",
    "plex": "Plex Media Server", "pki": "eMudhra CA compromise", "haproxy": "HAProxy", "node": "Node.js", "nginx": "nginx",
    "curl": "curl", "openssl": "OpenSSL", "roundcube": "Roundcube", "trafficserver": "Apache Traffic Server",
    "wordpress-pt": "WordPress path traversal", "bind": "BIND 9", "couchdb": "CouchDB", "craft": "Craft CMS",
    "basercms": "baserCMS", "claude-code-vsx": "Claude Code extension backdoor", "sagemaker": "SageMaker SDK",
    "nextjs": "Next.js Server Actions", "jupyter": "Jupyter and nbconvert", "yootheme": "YOOtheme Pro",
    "incus": "Incus", "storybook": "Storybook", "zammad": "Zammad", "rsyslog": "rsyslog", "vsftpd": "vsftpd",
    "tomcat": "Apache Tomcat", "gitea": "Gitea", "ghostaction": "GhostAction", "litellm": "LiteLLM", "pillow": "Pillow",
    "openapi": "openapi-typescript-codegen", "laravel": "Laravel TokenGuard", "nginx-ui": "nginx-ui",
}
RELATED = [["php", "php/detect", "php/edge"], ["wordpress", "wordpress-pt"], ["node", "brotli"], ["ruby", "gitlab"], ["nextjs", "sentry"], ["grav", "craft"]]
FACT_KEYS = [("Fixed", "The fix"), ("Move to", "The fix"), ("Remedy", "The fix"), ("Severity", "Severity"), ("Exploited", "Exploited")]
PROTECT_WORDS = re.compile(r"mitigat|workaround|protect|rollback|guard|block|rule|hardening|deactivat|clean", re.I)
SYNONYMS = {  # words people type that the page itself does not use; added to the search index only
    "install.html": "checksum checksums sha256 verify download apt dnf deb rpm package uninstall remove removal upgrade",
    "how-it-works.html": "docker podman containers exit code exit codes dry run dry-run rollback mitigate hunt check settings environment variable state backups root",
    "cves.html": "cve number identifier vulnerability",
    "glossary.html": "meaning means definition what is explained terms abbreviation acronym kev cwe rce xss ssrf dos lpe eol",
}
HUBS = {"index.html", "tools.html", "cves.html", "man/index.html", "changelog.html", "about.html"}   # long lists that mention everything
READONLY = {"check", "hunt", "scan", "audit", "version", "keys", "verify", "status", "list", "report"}
CHANGERS = {"mitigate", "rollback", "apply", "guard", "unguard", "harden", "clean", "update", "block", "unblock", "quarantine", "restore", "enforce", "complain", "cleanup", "remove"}
NOT_COMMANDS = {"sudo", "tail", "nohup", "env", "bash", "curl", "wget", "systemctl", "cat", "echo", "grep", "tar", "the", "see", "run"}

# ---------------------------------------------------------------- helpers
def read(p): return open(os.path.join(ROOT, p), encoding="utf-8").read()
def exists(p): return os.path.exists(os.path.join(ROOT, p))
def esc(s): return html.escape(s, quote=True)
def ghslug(value, sep="-"):
    return re.sub(r"[^\w\- ]", "", value.strip().lower()).replace(" ", "-")
def plain(h): return html.unescape(re.sub(r"<[^>]+>", " ", h))

def _md():
    md = MarkdownIt("commonmark", {"html": True, "linkify": True}).enable("table").enable("linkify")
    md.linkify.set({"fuzzy_link": False, "fuzzy_email": False, "fuzzy_ip": False})   # link web addresses, not file names like config.php
    return md

def _heading_text(inline):
    return "".join(c.content for c in (inline.children or []) if c.type in ("text", "code_inline"))

def render_md(text):
    md = _md(); tokens = md.parse(text); ids = set(); toc = []
    for i, t in enumerate(tokens):
        if t.type != "heading_open": continue
        name = I.strip_emoji(_heading_text(tokens[i + 1])); level = int(t.tag[1])   # ids and the table of contents go by the words; the icon stays in the heading
        base = ghslug(name); hid = base; n = 1
        while hid in ids: hid = f"{base}-{n}"; n += 1      # GitHub numbers repeated headings with a hyphen
        ids.add(hid); t.attrSet("id", hid)
        if level in (2, 3): toc.append((level, name, hid))
    h = md.renderer.render(tokens, md.options, {})
    def fix_anchor(m):
        name, inner = m.group(1), m.group(2)
        if f'id="{name}"' in h: return inner
        return f'<a id="{name}">{inner}</a>'
    h = re.sub(r'<a name="([^"]+)">(.*?)</a>', fix_anchor, h, flags=re.S)
    h = re.sub(r'<a [^>]*>\s*<img [^>]*src="https?://[^"]*"[^>]*/?>\s*</a>', "", h)
    h = re.sub(r'<img [^>]*src="https?://[^"]*"[^>]*/?>', "", h)
    h = re.sub(r"<thead>\s*<tr>(?:\s*<th[^>]*>\s*</th>)+\s*</tr>\s*</thead>", "", h)
    h = re.sub(r"<p>\s*</p>", "", h)
    h = h.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
    return h, toc

def cell_html(c):
    return _md().renderInline(c)

def sections(text):
    parts = re.split(r"^## (.+)$", text, flags=re.M)
    return parts[0], [(parts[i].strip(), re.sub(r"\n+---\s*$", "", parts[i + 1].strip("\n"))) for i in range(1, len(parts), 2)]   # a rule that ends a section is not part of it

# ---------------------------------------------------------------- sources
root_md = read("README.md")
pre, root_secs = sections(root_md)
raw_title = {I.strip_emoji(t): t for t, _ in root_secs}        # the README headings carry an emoji: pages that rebuild a heading keep it, and it becomes an icon
root_secs = [(I.strip_emoji(t), b) for t, b in root_secs]     # everything else goes by the words
rs = dict(root_secs)
home_md = read("packaging/site/home.md")                       # the home page's Start here and Newest sections live here, not in the README
_, home_secs = sections(home_md)
home_secs = [(I.strip_emoji(t), b) for t, b in home_secs]
rs.update(home_secs)
NEWEST = next((t for t, _ in home_secs if t.startswith("Newest")), "Newest")

tool_dirs = []
for dp, dn, fn in os.walk(ROOT):
    rel = os.path.relpath(dp, ROOT)
    if rel == "." or rel.startswith(("packaging", ".git", "site", "man", "dist")): continue
    if "README.md" in fn: tool_dirs.append(rel)
tool_dirs.sort()
categorised = [d for _, _, ds in CATEGORIES for d in ds]
missing = sorted(set(tool_dirs) - set(categorised)); extra = sorted(set(categorised) - set(tool_dirs))
if missing or extra: sys.exit(f"category list out of date: not placed {missing}, not found {extra}")
cat_of = {d: i for i, (_, _, ds) in enumerate(CATEGORIES) for d in ds}

DOCS = {
    "CHANGELOG.md": ("changelog.html", "Changelog"), "SECURITY.md": ("security.html", "Security policy"),
    "CODE_OF_CONDUCT.md": ("code-of-conduct.html", "Code of conduct"), "CONTRIBUTING.md": ("contributing.html", "Contributing"),
    "CONTRIBUTOR_GUIDELINES.md": ("contributor-guidelines.html", "Contributor guidelines"), "CONTRIBUTORS.md": ("contributors.html", "Contributors"),
    "VALUES.md": ("values.html", "Values"), "AI_POLICY.md": ("ai-policy.html", "AI policy"),
}
DOCS = {k: v for k, v in DOCS.items() if exists(k)}

rows = []   # rows of the All tools table: one per product page entry
header_cells = []
for line in rs.get("Available tools", "").split("\n"):
    if line.startswith("| Patch"): header_cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
    m = re.match(r"^\|\s*\[([^\]]+)\]\(([^)#]+)(#[^)]*)?\)\s*\|(.*)\|\s*$", line)
    if m and m.group(2).endswith("README.md"):
        cells = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", m.group(4))]
        rows.append({"label": m.group(1), "dir": posixpath.dirname(m.group(2)), "anchor": (m.group(3) or "")[1:], "cells": cells})
def h1_of(text):
    m = re.match(r"# (.+)", text); return I.strip_emoji(m.group(1).strip()) if m else ""
tool_title = {}; tool_text = {}; labels = {}
for d in tool_dirs:
    t = read(d + "/README.md"); tool_text[d] = t; tool_title[d] = h1_of(t)
    first = next((r["label"] for r in rows if r["dir"] == d), None)
    labels[d] = NAMES.get(d) or first or re.split(r"[:(]", tool_title[d])[0].strip()[:60]

def home_dir(path):
    """A folder named in home.md, relative to that file, as a folder of the repository."""
    return posixpath.normpath(posixpath.join("packaging/site", path)).rstrip("/")
newest = []
for line in rs.get(NEWEST, "").split("\n"):
    m = re.match(r"^\|\s*(\d+ \w+)\s*\|\s*\[([^\]]+)\]\(([^)#]+)README\.md(?:#([^)]*))?\)", line)
    if m: newest.append((m.group(1), m.group(2), home_dir(m.group(3)), m.group(4) or ""))
newest_rows = []
for line in rs.get(NEWEST, "").split("\n"):
    m = re.match(r"^\|\s*(\d+) (\w+)\s*\|\s*\[([^\]]+)\]\(([^)#]+)README\.md(?:#([^)]*))?\)(.*)$", line)
    if m:
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", m.group(6).rstrip().rstrip("|"))]
        what = (re.sub(r"^:\s*", "", cells[0]) if cells else "")
        iso = datetime.datetime.strptime(f"{m.group(1)} {m.group(2)} 2026", "%d %B %Y").date().isoformat()
        newest_rows.append({"iso": iso, "label": m.group(3), "dir": home_dir(m.group(4)), "anchor": m.group(5) or "", "what": re.sub(r"[`*]|\[([^\]]*)\]\([^)]*\)", lambda mm: mm.group(1) or "", what)})

scripts = []
for dp, dn, fn in os.walk(ROOT):
    rel = os.path.relpath(dp, ROOT)
    if rel.startswith(("packaging", ".git", "site", "man", "dist")): continue
    for f in fn:
        if f.endswith(".sh"): scripts.append(posixpath.join(rel, f) if rel != "." else f)
scripts.sort()
def man_name(p): return "psf-" + posixpath.basename(p)[:-3]
_help = {}
def helptext(p):
    if p not in _help:
        r = subprocess.run(["bash", os.path.join(ROOT, p), "--help"], capture_output=True, text=True, timeout=30, cwd=ROOT)
        _help[p] = r.stdout.rstrip("\n")
    return _help[p]
def commands_of(t):
    lines = t.split("\n")
    try: u = next(i for i, l in enumerate(lines) if re.match(r"Usage\b[^:]*:\s*$", l.strip()))
    except StopIteration: return []
    out = []
    for l in lines[u + 1:]:
        if not l.strip(): continue
        ind = len(l) - len(l.lstrip())
        if ind == 0 and out: break
        if 2 <= ind <= 3:
            term = l.strip().split("  ")[0].strip()
            w = re.match(r"[a-z][a-z-]{2,}", term)
            if w and not term.startswith("./") and w.group(0) not in NOT_COMMANDS and w.group(0) not in out: out.append(w.group(0))
    return out

def facts_of(text):
    """Key facts from the README's own summary table, only when the page has a single one."""
    found = {}; count = {}
    for l in text.split("\n")[:90]:
        if not l.startswith("|"): continue
        cells = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", l.strip().strip("|"))]
        if len(cells) != 2: continue
        key = re.sub(r"[*`]", "", cells[0]).strip()
        count[key] = count.get(key, 0) + 1
        found.setdefault(key, cells[1])
    if count.get("Affected", 0) != 1: return []
    out = []; seen = set()
    for key, label in FACT_KEYS:
        if key in found and label not in seen and count.get(key, 0) == 1:
            seen.add(label); out.append((label, found[key]))
    return out

def default_command(t):
    """The command a script runs when given none, from the '(default)' mark in its usage block."""
    lines = t.split("\n")
    u = next((i for i, l in enumerate(lines) if re.match(r"Usage\b[^:]*:\s*$", l.strip())), None)
    if u is None: return None
    for l in lines[u + 1:u + 60]:
        m = re.match(r"^\s{2,3}([a-z][a-z-]+)\b[^\n]*\(default\)", l)
        if m: return m.group(1)
    return None

cves_of = {}
for d in tool_dirs:
    cves_of[d] = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", tool_text[d])), key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))

ROOT_PAGES = {"Start here": "index.html", NEWEST: "index.html", "Available tools": "tools.html",
              "Install from a package": "install.html", "Updates": "install.html", "Important notice": "install.html"}
root_anchor = {}
_cur = None
for _line in root_md.split("\n") + [f"## {t}" for t, _ in home_secs]:
    _h2 = re.match(r"^## (.+)$", _line); _h3 = re.match(r"^### (.+)$", _line)
    if _h2:
        _cur = I.strip_emoji(_h2.group(1)); root_anchor[ghslug(_cur)] = ROOT_PAGES.get(_cur, "about.html")
    elif _h3 and _cur:
        root_anchor[ghslug(I.strip_emoji(_h3.group(1)))] = ROOT_PAGES.get(_cur, "about.html")
def tool_out(d): return posixpath.join(d, "index.html")

# ---------------------------------------------------------------- links
def rewriter(src_rel, page_out):
    srcdir = posixpath.dirname(src_rel); outdir = posixpath.dirname(page_out) or "."
    def rel_to(out, anchor=""):
        return posixpath.relpath(out, outdir) + ("#" + anchor if anchor else "")
    def fix(m):
        attr, url = m.group(1), m.group(2)
        if re.match(r"^(https?:|mailto:|#|data:|javascript:)", url) or not url: return m.group(0)
        path, _, anchor = url.partition("#")
        if not path: return m.group(0)
        target = posixpath.normpath(posixpath.join(srcdir, path)).rstrip("/")
        if target == "README.md": return f'{attr}="{rel_to(root_anchor.get(anchor, "index.html"), anchor)}"'
        if target in DOCS: return f'{attr}="{rel_to(DOCS[target][0], anchor)}"'
        if target in ("LICENSE", "NOTICE"): return f'{attr}="{rel_to("license.html", anchor)}"'
        if target.endswith("/README.md") and posixpath.dirname(target) in tool_dirs:
            return f'{attr}="{rel_to(tool_out(posixpath.dirname(target)), anchor)}"'
        if target in tool_dirs: return f'{attr}="{rel_to(tool_out(target), anchor)}"'
        if target.endswith(".svg") and exists(target): return f'{attr}="{rel_to("assets/" + posixpath.basename(target))}"'
        if exists(target): return f'{attr}="{SRC}{target}"'
        return m.group(0)
    return lambda h: re.sub(r'(href|src)="([^"]*)"', fix, h)

def clean_tool_md(text):
    L = text.split("\n")
    for i, l in enumerate(L):
        if re.match(r"^## ", l) and I.strip_emoji(l[3:]) in ("Important notice", "Support PrivacySafe Foundation"):
            j = i
            while j > 0 and (not L[j - 1].strip() or L[j - 1].strip() == "---"): j -= 1
            L = L[:j]; break
    if L and L[0].startswith("# "): L = L[1:]
    out = []
    for n, l in enumerate(L):
        if n < 14 and re.match(r"^\*\*Scripts?:\*\*", l): continue
        if l.startswith("Part of the "):
            l = re.sub(r"^Part of the .*?collection\.\s*", "", l)
            if not l.strip(): continue
        out.append(l)
    return "\n".join(out).strip() + "\n"

# ---------------------------------------------------------------- layout
START = [("Home", "index.html"), ("How the tools work", "how-it-works.html"), ("Glossary", "glossary.html"), ("Install and update", "install.html"),
         ("All tools", "tools.html"), ("Find a CVE", "cves.html"), ("Manual pages", "man/index.html"),
         ("Changelog", "changelog.html"), ("Security policy", "security.html"), ("About and support", "about.html")]

def nav_html(cur_out):
    outdir = posixpath.dirname(cur_out) or "."
    def link(label, out):
        cls = ' aria-current="page"' if out == cur_out else ""
        return f'<li><a href="{esc(posixpath.relpath(out, outdir))}"{cls}>{esc(label)}</a></li>'
    cur_dir = next((d for d in tool_dirs if tool_out(d) == cur_out), None)
    new_dirs = []
    for _, _, d, _ in newest:
        if d in tool_dirs and d not in new_dirs: new_dirs.append(d)
    search = ""
    if APP:
        search = ('<div class="side-search js-only"><label class="sr" for="site-search">Search Security Patches</label>'
                  '<input id="site-search" type="search" placeholder="Search tools, CVEs, commands" title="Press / to search" aria-keyshortcuts="/" autocomplete="off" '
                  'aria-controls="search-results" data-index="/docs/security-patches/assets/search-index.js" data-base="/docs/security-patches/">'
                  '<div id="search-results" role="listbox" hidden></div></div>')
    o = ['<nav class="docs-side" aria-label="Security Patches">' + search + '<details class="side-box" open><summary>Menu</summary><ul class="start">']
    o += [link(l, p) for l, p in START]
    o.append("</ul>")
    o.append(f'<details class="grp"{" open" if cur_dir in new_dirs or cur_out == "index.html" else ""}><summary>{esc(NEWEST)}</summary><ul>')
    shown = set()
    for date, label, d, _ in newest:
        if d in tool_dirs and d not in shown:
            shown.add(d); o.append(link(f"{date.split()[0]} Oct: {labels[d]}", tool_out(d)))
    o.append("</ul></details>")
    for i, (title, blurb, ds) in enumerate(CATEGORIES):
        is_open = " open" if cur_dir in ds else ""
        o.append(f'<details class="grp"{is_open}><summary>{esc(title)}</summary><ul>')
        for d in sorted(ds, key=lambda x: labels[x].lower()): o.append(link(labels[d], tool_out(d)))
        o.append("</ul></details>")
    o.append("</details></nav>")
    return "\n".join(o)

JS_FLAG = 'document.documentElement.className+=" js"'
CSP = ("default-src 'none'; img-src 'self' data:; style-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
       "script-src 'self' 'sha256-" + base64.b64encode(hashlib.sha256(JS_FLAG.encode()).digest()).decode() + "'")

def canon(out):
    return BASE_URL + (out[:-len("index.html")] if out.endswith("index.html") else out)

def page_html_app(out, title, body, toc, desc, crumbs, footer_nav, wide, crumb):
    is_home = out == "index.html"; here = posixpath.dirname(out) or "."
    cr = '<nav class="crumbs" aria-label="Breadcrumb"><a href="/docs/">Docs</a>'
    if is_home: cr += " / <span>Security Patches</span></nav>"
    else:
        cr += ' / <a href="%s">Security Patches</a>' % esc(posixpath.relpath("index.html", here))
        for label, link in (crumbs or []): cr += ' / <a href="%s">%s</a>' % (esc(posixpath.relpath(link, here)), esc(label))
        cr += " / <span>%s</span></nav>" % esc(crumb or textwrap.shorten(title, 58, placeholder="..."))
    toc_html = ""
    if toc and len(toc) > 2:
        toc_html = '<aside class="toc" aria-label="On this page"><h2>On this page</h2><ul>%s</ul></aside>' % "".join(
            '<li class="l%d"><a href="#%s">%s</a></li>' % (lv, esc(i), esc(n)) for lv, n, i in toc)
    url = canon(out); d = desc or "PrivacySafe Security Patches: free, public domain tools that check, hunt and protect against serious vulnerabilities."
    trail = [("PrivacySafe", L.SITE + "/"), ("Docs", L.DOCS)] + ([("Security Patches", BASE_URL)] if not is_home else [])
    for label, link in (crumbs or []): trail.append((label, BASE_URL + link))
    if not is_home: trail.append((crumb or title, url))
    page = {"@type": "CollectionPage" if is_home else ("TechArticle" if (out.endswith("/index.html") or out.startswith("man/")) else "WebPage"),
            "@id": url + "#page", "url": url, "name": title, "headline": textwrap.shorten(title, 108, placeholder="..."), "description": d,
            "inLanguage": "en", "dateModified": DATE, "isPartOf": {"@id": L.DOCS + "#docs"}, "publisher": {"@id": "https://ivycyber.com/#organization"},
            "author": {"@id": "https://privacysafe.app/#organization"}, "license": "https://creativecommons.org/publicdomain/zero/1.0/"}
    ld = [page, L.breadcrumb_ld(trail)]
    html_out = L.head(title=title if is_home else f"{title} | PrivacySafe Security Patches", description=d, canonical=url, kind="patches", page_name=title, ld=ld,
                      alternates=[(BASE_URL + "feed.xml", "application/atom+xml", "PrivacySafe Security Patches: newest advisories")],
                      keywords="Security Patches, CVE, vulnerability, GNU/Linux, server hardening, mitigation", full=is_home,
                      copyright_note="Security Patches software and documentation CC0 1.0 Universal. Site source AGPL-3.0-or-later.",
                      license_url="https://creativecommons.org/publicdomain/zero/1.0/")
    html_out += L.topbar("Security Patches")
    lic = '<p class="page-license">The Security Patches software and this documentation are dedicated to the public domain under <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="noopener noreferrer" target="_blank">CC0 1.0 Universal</a>. Other pages on privacysafe.app/docs are CC BY-SA 4.0 unless the page says otherwise.</p>'
    html_out += (f'<div class="doc-page"><div class="wrap doc-layout{"" if toc_html else " no-toc"}">{nav_html(out)}\n'
                 f'<main id="top">{cr}\n<article class="doc{" wide" if wide else ""}">{body}{lic}{footer_nav}</article></main>\n{toc_html}</div></div>\n')
    if is_home: html_out += L.cta_band()
    return html_out + L.footer()

def page_html(out, title, body, toc=None, desc="", crumbs=None, footer_nav="", wide=False, crumb=None):
    if APP: return page_html_app(out, title, body, toc, desc, crumbs, footer_nav, wide, crumb)
    depth = out.count("/"); root = "../" * depth
    cr = ""
    if out != "index.html":
        cr = '<nav class="crumbs" aria-label="Breadcrumb"><a href="%sindex.html">Home</a>' % root
        for label, link in (crumbs or []):
            cr += ' / <a href="%s">%s</a>' % (esc(posixpath.relpath(link, posixpath.dirname(out) or ".")), esc(label))
        cr += " / <span>%s</span></nav>" % esc(crumb or textwrap.shorten(title, 58, placeholder="..."))
    toc_html = ""
    if toc and len(toc) > 2:
        toc_html = '<aside class="toc" aria-label="On this page"><h2>On this page</h2><ul>%s</ul></aside>' % "".join(
            '<li class="l%d"><a href="#%s">%s</a></li>' % (lv, esc(i), esc(n)) for lv, n, i in toc)
    head_title = SITE if out == "index.html" else f"{title} | {SITE}"
    return f'''<!doctype html>
<html lang="en" data-root="{root}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#0b5cc7"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="{esc(CSP)}">
<title>{esc(head_title)}</title><meta name="description" content="{esc(desc or SITE)}">
<link rel="icon" href="{root}assets/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="{root}assets/site.css"><script>{JS_FLAG}</script></head>
<body><a class="skip" href="#main">Skip to content</a>
<header class="top"><a class="brand" href="{root}index.html"><img src="{root}assets/privacysafe_horizontal_logo_lock_reg_padded.svg" alt="PrivacySafe" height="28"><span>Security Patches</span></a>
<nav class="topnav" aria-label="Main"><a href="{root}tools.html">Tools</a><a href="{root}cves.html">CVEs</a><a href="{root}how-it-works.html">How it works</a><a href="{root}install.html">Install</a><a href="{root}man/index.html">Manual pages</a></nav>
<div class="search js-only"><label class="sr" for="site-search">Search the documentation</label><input id="site-search" type="search" placeholder="Search tools, CVEs, commands" title="Press / to search" aria-keyshortcuts="/" autocomplete="off" aria-controls="search-results"><div id="search-results" role="listbox" hidden></div></div></header>
<div class="layout{"" if toc_html else " no-toc"}">{nav_html(out)}
<main id="main" tabindex="-1">{cr}
<article class="doc{" wide" if wide else ""}">{body}{footer_nav}</article></main>
{toc_html}</div>
<footer class="foot"><p>{esc(SITE)} {esc(RELEASE)}, {esc(LONGDATE)}. Written and published by PrivacySafe Foundation, a 501(c)(3) nonprofit, with the assistance of Ivy Cyber LLC. CC0 1.0 Universal: use it, copy it, change it.</p>
<p><a href="{root}license.html">License and notice</a> | <a href="{root}security.html">Security policy</a> | <a href="{REPO}/issues">Report a problem</a> | <a href="https://privacysafe.app">Get PrivacySafe</a> | <a href="https://privacysafe.foundation">Support PrivacySafe Foundation</a> | <a href="{REPO}">Source on Codeberg</a></p></footer>
<script src="{root}assets/site.js" defer></script></body></html>
'''

# ---------------------------------------------------------------- pages
pages = []
def write(out, content):
    if I.has_emoji(re.sub(r"<svg\b.*?</svg>", "", content, flags=re.S)): sys.exit(f"an emoji is left on {out}: it needs an icon (packaging/psf_icons.py)")
    p = os.path.join(OUT, out); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(content)
def accessible_tables(h):
    """Scrollable tables must be reachable by keyboard, and every header cell needs text."""
    h = h.replace('<div class="table-wrap">', '<div class="table-wrap" tabindex="0">')
    h = re.sub(r'<pre(?![^>]*(?:tabindex|manual))', '<pre tabindex="0"', h)   # code blocks scroll sideways on a phone
    return re.sub(r"<th([^>]*)>\s*</th>", r'<th\1><span class="sr">Item</span></th>', h)

def nowrap_cves(h):
    """Keep each CVE number on one line (outside code blocks and attributes)."""
    parts = re.split(r"(<pre.*?</pre>)", h, flags=re.S)
    cv = re.compile(r"CVE-\d{4}-\d{4,7}")
    for i, part in enumerate(parts):
        if i % 2 == 0:
            parts[i] = re.sub(r">([^<]+)<", lambda m: ">" + cv.sub(lambda c: '<span class="nw">' + c.group(0) + "</span>", m.group(1)) + "<", part)
    return "".join(parts)

def add(out, title, body, toc=None, kind="Guide", extra_heads=None, **kw):
    title = I.strip_emoji(title)
    body = accessible_tables(nowrap_cves(I.iconize(body)))     # every emoji becomes a drawn icon; an emoji with no icon stops the build
    write(out, page_html(out, title, body, toc, **kw))
    text = re.sub(r"\s+", " ", plain(re.sub(r'<h2 class="sr">.*?</h2>', "", re.sub(r'<p class="kicker">.*?</p>', "", re.sub(r"<h1>.*?</h1>", "", body, count=1, flags=re.S), flags=re.S), flags=re.S))).strip()[:12000]
    weight = 2 if kind == "Tool" else (1 if out in ("how-it-works.html", "install.html", "glossary.html") else (-3 if out in HUBS else 0))
    pages.append({"url": out, "title": title, "kind": kind, "w": weight, "heads": [n for _, n, _ in (toc or [])] + (extra_heads or []), "alias": SYNONYMS.get(out, ""), "text": text})

shutil.rmtree(OUT, ignore_errors=True); os.makedirs(os.path.join(OUT, "assets"))
_logo = read("privacysafe_horizontal_logo_lock_reg_padded.svg")
_logo = re.sub(r'(<g\b[^>]*?)\saria-label="[^"]*"', r"\1", _logo)   # the page gives the image its alt text; aria-label on <g> is not valid
if not APP: open(os.path.join(OUT, "assets", "privacysafe_horizontal_logo_lock_reg_padded.svg"), "w", encoding="utf-8").write(_logo)
if not APP: open(os.path.join(OUT, ".nojekyll"), "w").close()
if not APP: open(os.path.join(OUT, "assets", "favicon.svg"), "w").write('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#0b5cc7"/><path d="M32 10l18 7v13c0 12-8 20-18 24C22 50 14 42 14 30V17z" fill="#fff"/><path d="M26 31l5 5 9-11" fill="none" stroke="#0b5cc7" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>')

# ---- home
lead = [p for p in re.split(r"\n\s*\n", pre) if p.strip() and not p.strip().startswith(("<", "#", "---")) and "support" not in p.lower()[:40]]
intro_h, _ = render_md("\n\n".join(lead[:2]).replace("This repository contains", "This collection contains"))
start_h, _ = render_md(rs["Start here"]); newest_h, _ = render_md(rs[NEWEST])
start_h = rewriter("packaging/site/home.md", "index.html")(start_h); newest_h = rewriter("packaging/site/home.md", "index.html")(newest_h)   # home.md links are relative to that file
ncves = len({c for d in tool_dirs for c in cves_of[d]})
cards = f'''<div class="cards">
<a class="card" href="tools.html"><strong>Find your software</strong><span>{len(tool_dirs)} tool pages in four groups: servers, system and runtimes, web applications, developer tools.</span></a>
<a class="card" href="cves.html"><strong>Find a CVE</strong><span>{ncves} CVE numbers, each linked to the tool that covers it.</span></a>
<a class="card" href="how-it-works.html"><strong>How the tools work</strong><span>The few commands every tool shares, and what a change does to your machine.</span></a>
<a class="card" href="install.html"><strong>Install and update</strong><span>Packages for Debian and RPM systems, with checksums.</span></a></div>'''
browse = "".join(
    f'<div class="kind"><h3>{esc(t)}</h3><p>{esc(b)}</p><ul>' + "".join(f'<li><a href="{tool_out(d)}">{esc(labels[d])}</a></li>' for d in sorted(ds, key=lambda x: labels[x].lower())) + "</ul></div>"
    for t, b, ds in CATEGORIES)
body = (f'<h1>Security Patches</h1><div class="lead">{intro_h}</div>{cards}'
        f'<h2 id="start-here">Start here</h2>{start_h}<h2 id="newest">{esc(NEWEST)}</h2>{newest_h}'
        f'<h2 id="browse">Browse by kind of software</h2><div class="kinds">{browse}</div>')
add("index.html", "Security Patches", rewriter("README.md", "index.html")(body),
    desc="Free security tools for GNU/Linux servers, shared for the public good: check, hunt and protect.")

# ---- tools, grouped
def can_change(d):
    return any(c in CHANGERS for s in scripts if posixpath.dirname(s) == d for c in commands_of(helptext(s)))
def row_html(r, out):
    tds = "".join(f"<td>{cell_html(c)}</td>" for c in r["cells"])
    prot = "1" if can_change(r["dir"]) and len(r["cells"]) >= 3 and PROTECT_WORDS.search(r["cells"][-1]) else "0"
    return f'<tr data-protects="{prot}"><td><a href="{tool_out(r["dir"]) + ("#" + r["anchor"] if r["anchor"] else "")}">{esc(r["label"])}</a></td>{tds}</tr>'
head = [html.escape(c) for c in (header_cells or ["Patch", "Targets", "CVEs", "Type"])]
groups = []
for i, (title, blurb, ds) in enumerate(CATEGORIES):
    rr = [r for r in rows if r["dir"] in ds]
    n = len(rr)
    if not rr: continue
    t = "".join(row_html(r, "tools.html") for r in rr)
    th = "".join(f"<th>{c}</th>" for c in head)
    groups.append(f'<section class="tool-group"><h2 id="{ghslug(title)}">{esc(title)} <small data-total="{n}">{n} entries</small></h2><p>{esc(blurb)}</p><div class="table-wrap"><table class="tools-table"><thead><tr>{th}</tr></thead><tbody>{t}</tbody></table></div></section>')
tools_body = ('<h1>All tools</h1><p>Every tool in the collection, grouped by the kind of software it protects. Type to filter by product, CVE or kind of protection.</p>'
              '<p class="js-only"><label class="sr" for="tool-filter">Filter the tools</label><input id="tool-filter" type="search" placeholder="Filter, for example nginx, CVE-2026-110353 or mitigation" autocomplete="off"></p>'
              '<p class="chips js-only"><label><input type="checkbox" id="only-protect"> Only tools that can protect the machine, not just check it</label></p><p class="status js-only" id="filter-status" role="status" aria-live="polite"></p>' + "".join(groups))
tools_toc = [(2, t, ghslug(t)) for t, _, _ in CATEGORIES]
add("tools.html", "All tools", rewriter("README.md", "tools.html")(tools_body), tools_toc, desc="Every PrivacySafe security tool, grouped by the kind of software, with the CVEs each covers.", wide=True)

# ---- CVE index
by_cve = {}
for d in tool_dirs:
    for c in cves_of[d]: by_cve.setdefault(c, []).append(d)
order = sorted(by_cve, key=lambda c: (-int(c.split("-")[1]), -int(c.split("-")[2])))
crow = "".join(f'<tr id="{c.lower()}"><td><code>{c}</code></td><td>' + ", ".join(f'<a href="{tool_out(d)}">{esc(labels[d])}</a>' for d in sorted(by_cve[c], key=lambda x: labels[x].lower())) + "</td></tr>" for c in order)
cve_body = (f'<h1>Find a CVE</h1><p>{len(order)} CVE numbers appear in the tool pages. Each is linked to the tools that cover it. A tool covers a CVE when it checks for it, hunts for it or protects against it; a few CVEs are covered by more than one tool.</p>'
            '<p class="js-only"><label class="sr" for="tool-filter">Filter the CVE list</label><input id="tool-filter" type="search" placeholder="Filter, for example 2026-1103 or HAProxy" autocomplete="off"></p><p class="status js-only" id="filter-status" role="status" aria-live="polite"></p>'
            f'<div class="table-wrap"><table class="tools-table cve-table"><thead><tr><th>CVE</th><th>Covered by</th></tr></thead><tbody>{crow}</tbody></table></div>')
add("cves.html", "Find a CVE", cve_body, desc="Every CVE the tools cover, linked to the tool that covers it.", wide=True)

# ---- how the tools work
HOW = '''## What every tool has in common

Each tool is one bash script with its own page and manual page. They share a few commands, so you learn them once.

| Command | What it does |
|---|---|
| `check` | Tells you whether this machine is exposed. It changes nothing. Most tools run it when you give no command. |
| `hunt` | Looks for signs that the flaw was used. It changes nothing. |
| `mitigate` | Applies protection that you can undo. It needs root, and not every tool has one. |
| `rollback` | Undoes what `mitigate` changed. |

Type the command every time. Two tools do something else when you give none: `php2shell-mitigate.sh` and `emudhra-mitigate.sh` apply their protection by default.

The Claude Code extension tool also has `update`, `keys`, `clean`, `block` and `unblock`; its page explains each one.

The four steps to follow, in order, are on the [home page](README.md#start-here).

## What `mitigate` does before it changes anything

- It copies every file it is about to edit.
- Where the service has its own checker (`nginx -t`, `haproxy -c`, `rsyslogd -N1`, `xmllint` and so on), it checks the result with it, and puts the original back at once if the check fails.
- It supports `--dry-run`, which shows the change and makes none.
- It reloads or restarts nothing unless you ask with `--reload` or `--restart`.
- It keeps its backups and a record for `rollback` under `/var/lib/psf-security-patches/`, in a folder named for the tool.

## Results and exit codes

Most tools use the same exit codes, so you can use them in scripts and monitoring.

| Code | Meaning |
|---|---|
| 0 | Nothing exposed, or nothing found. |
| 1 | Exposed, or an indicator was found. |
| 2 | Bad arguments, or something the tool needed could not be read. |

A hunt match tells you where to look. A clean hunt means none of the published indicators were found.

## Settings

| Setting | Effect |
|---|---|
| `SCAN_CONTAINERS=0` | Skip running docker and podman containers. By default a tool also checks them when you do not name a directory. |
| `STATE_DIR=/path` | Where a tool keeps its backups and rollback record. Each tool's page names its default. |
| `--dry-run` | Show what a change would do and change nothing. |

## Where things are

- The scripts: `/opt/psf-security-patches/`, one folder for each product.
- Manual pages: `man psf-security-patches` for the overview, then `man psf-NAME` for a tool. `info psf-security-patches` has all of them in one manual.
- This documentation, offline: `/usr/share/doc/psf-security-patches/html/index.html` (on RPM systems the folder is `psf-security-patches-<version>`).

Terms such as CVE, CVSS, backport and indicator are explained in the [glossary](glossary.html).
'''
how_h, how_toc = render_md(HOW)
add("how-it-works.html", "How the tools work", "<h1>How the tools work</h1>" + rewriter("README.md", "how-it-works.html")(how_h), how_toc,
    desc="The commands every tool shares, what a change does before it happens, exit codes and settings.")

# ---- glossary: only terms that appear on the pages, in plain words
GLOSSARY = [
 ("Advisory", "A notice from a vendor or project that describes a vulnerability, the versions it affects and the versions that fix it."),
 ("Affected and exposed", "Affected means a version has the flaw. Exposed is how these tools use the word: the version is affected and the conditions needed to reach the flaw are present on this machine."),
 ("Backport", "A fix a distribution applies to an older release, so the package keeps its old version number. This is why the tools read a package's changelog and not only its version number."),
 ("CVE", "A public identifier for one vulnerability, written like CVE-2026-110353."),
 ("CVSS", "A score from 0 to 10 for how severe a vulnerability is. Critical is 9.0 to 10, High is 7.0 to 8.9, Medium is 4.0 to 6.9 and Low is below 4.0. Vendors often score the same flaw differently."),
 ("CWE", "A category of weakness, for example CWE-287, improper authentication."),
 ("Cross-site scripting (XSS)", "Getting a victim's browser to run an attacker's script as if it came from a site the victim trusts."),
 ("Denial of service (DoS)", "Making a service slow or unavailable instead of taking it over."),
 ("Deserialization", "Turning stored or received data back into objects. If an attacker controls that data, it can end in running the attacker's code."),
 ("End of life", "A version the vendor no longer fixes. The only remedy is to move to a supported version."),
 ("Exploited in the wild", "Attackers are using the flaw against real systems, not only in a lab."),
 ("Fix and mitigation", "A fix is the vendor's update. A mitigation is protection that makes the flaw harder to reach until you update. It does not replace the update."),
 ("Indicator", "Something you can observe, such as a file, a log line, a process or a network connection, that suggests a flaw was used. `hunt` looks for indicators. A clean hunt means none of the published indicators were found."),
 ("KEV", "The Known Exploited Vulnerabilities catalog kept by the US agency CISA: flaws confirmed to be exploited."),
 ("Memory corruption", "Bugs where a program reads or writes memory it should not, such as a use-after-free or an out-of-bounds write. They can crash a program or let an attacker run code."),
 ("Path traversal", "Using `../` in a path to reach files outside the folder an application meant to allow."),
 ("Privilege escalation", "Gaining more rights than you were given, for example a local user becoming root."),
 ("Remote code execution (RCE)", "Running the attacker's code on your machine from across the network."),
 ("Rollback", "Undoing what `mitigate` changed."),
 ("SQL injection", "Putting database commands into input that an application passes on to its database."),
 ("Server-side request forgery (SSRF)", "Tricking a server into making requests for the attacker, often to addresses that are only reachable from inside."),
]
gl = "".join(f'<dt id="{ghslug(t)}">{esc(t)}</dt><dd>{cell_html(d)}</dd>' for t, d in GLOSSARY)
add("glossary.html", "Glossary", f'<h1>Glossary</h1><p>Plain meanings for the terms used on this site.</p><dl class="gloss">{gl}</dl>',
    [(2, t, ghslug(t)) for t, _ in GLOSSARY], desc="Plain meanings for CVE, CVSS, backport, indicator, mitigation and the other terms used on this site.")

# ---- install, about, documents
inst_h, inst_toc = render_md("\n\n".join(f"## {raw_title.get(t, t)}\n\n{rs[t]}" for t in ("Install from a package", "Updates", "Important notice")))
add("install.html", "Install and update", "<h1>Install and update</h1>" + rewriter("README.md", "install.html")(inst_h), inst_toc, desc="Install the packages, check the checksums, update and remove.")
if APP:
    ABOUT = """## Who makes this

PrivacySafe Security Patches is written and published by PrivacySafe Foundation, a 501(c)(3) nonprofit, with the assistance of Ivy Cyber LLC. It is released into the public domain under CC0 1.0 Universal, so you can use it, copy it and change it without asking.

## Get PrivacySafe

[PrivacySafe](https://privacysafe.app) is the free, open source app suite from the same team: private chat, peer-to-peer voice and video calls, and a secure zone for your passwords, passports and other sensitive data. You can sign up free, without a phone number.

- [Download PrivacySafe](https://privacysafe.app/#download) for Android, Windows, Mac and GNU/Linux.
- [Read the PrivacySafe documentation](https://privacysafe.app/docs/), including the user guide, the VPN setup guide and the 3NWeb protocols.

## Support the work

Donations to [PrivacySafe Foundation](https://privacysafe.foundation/donate) support education, research, documentation and public code, including these tools.

## Contribute

- The source is on [GitHub](https://github.com/PrivacySafe/security-patches), mirrored on [Codeberg](https://codeberg.org/PrivacySafe/security-patches).
- To report a vulnerability in these tools, follow the [security policy](security.html). Never send sensitive information through ordinary direct messages or unencrypted email.
- The [contributing guide](contributing.html), [code of conduct](code-of-conduct.html) and [AI policy](ai-policy.html) say how we work.

## License

Software and documentation: [CC0 1.0 Universal](license.html). PrivacySafe(R) and 3NWeb(R) are registered trademarks of Ivy Cyber LLC, and trademark rights are not licensed.
""".replace("(R)", "\u00ae")
    ab_h, ab_toc = render_md(ABOUT)
    add("about.html", "About Security Patches", "<h1>About Security Patches</h1>" + ab_h, ab_toc, desc="Who makes PrivacySafe Security Patches, how to get PrivacySafe, and how to support and contribute to the tools.")
else:
    about_md = "\n\n".join(f"## {raw_title.get(t, t)}\n\n{rs[t]}" for t in ("Support PrivacySafe Foundation", "Contributing", "More from PrivacySafe", "License") if t in rs)
    ab_h, ab_toc = render_md(about_md)
    add("about.html", "About and support", "<h1>About and support</h1>" + rewriter("README.md", "about.html")(ab_h), ab_toc)
DOC_DESC = {  # one description for each policy page, so no two pages share one
    "changelog.html": "New tools and changes in each PrivacySafe Security Patches release, newest first.",
    "security.html": "How to report a vulnerability in the PrivacySafe Security Patches tools, and how reports are handled.",
    "code-of-conduct.html": "The code of conduct for everyone who contributes to PrivacySafe Security Patches.",
    "contributing.html": "How to contribute a fix or a new tool to PrivacySafe Security Patches, and the terms that apply.",
    "contributor-guidelines.html": "Guidelines for contributing scripts and documentation to PrivacySafe Security Patches.",
    "contributors.html": "The people and organizations behind PrivacySafe Security Patches.",
    "values.html": "The principles that guide how PrivacySafe Security Patches is written and shared.",
    "ai-policy.html": "How AI tools may be used when you contribute to PrivacySafe Security Patches.",
}
for src, (out, title) in DOCS.items():
    h, toc = render_md(re.sub(r"^# .+\n", "", read(src), count=1))
    add(out, title, f"<h1>{esc(title)}</h1>" + rewriter(src, out)(h), toc, desc=DOC_DESC.get(out, ""))
lic = "<h1>License and notice</h1>" + render_md(read("NOTICE"))[0] + '<h2 id="cc0-1-0-universal">CC0 1.0 Universal</h2><pre class="license">' + esc(read("LICENSE")) + "</pre>"
add("license.html", "License and notice", lic, desc="The CC0 1.0 Universal license and the notice that cover PrivacySafe Security Patches.")

# ---- tool pages
def glance(d):
    mine = [s for s in scripts if posixpath.dirname(s) == d]
    items = []
    my_rows = [r for r in rows if r["dir"] == d]
    targets = []
    for r in my_rows:
        t = r["cells"][0] if r["cells"] else ""
        if t and t not in [x[1] for x in targets]: targets.append((r["label"], t))
    if targets:
        many = len(targets) > 1
        items.append(("Affects", "".join(f'<div class="aff">{("<strong>" + esc(l) + ":</strong> ") if many else ""}{cell_html(t)}</div>' for l, t in targets)))
    for label, value in facts_of(tool_text[d]):
        items.append((label, cell_html(value)))
    cv = cves_of[d]
    if cv:
        shown = ", ".join(cv[:6]); rest = ""
        if len(cv) > 6: rest = f' <details class="more"><summary>and {len(cv) - 6} more</summary>{", ".join(cv[6:])}</details>'
        items.append(("Covers", f'<span class="cves">{shown}</span>{rest}'))
    else:
        items.append(("Covers", "No CVE number (see the description below)"))
    blocks = []
    for s in mine:
        cmds = commands_of(helptext(s))
        ro = [c for c in cmds if c in READONLY]; ch = [c for c in cmds if c in CHANGERS]; ot = [c for c in cmds if c not in READONLY and c not in CHANGERS]
        parts = []
        if ro: parts.append("reads only: " + ", ".join(f"<code>{c}</code>" for c in ro))
        if ch: parts.append("can change the system: " + ", ".join(f"<code>{c}</code>" for c in ch))
        if ot: parts.append("also: " + ", ".join(f"<code>{c}</code>" for c in ot))
        first = ("check" if "check" in cmds else (ro[0] if ro else None))
        if first: run = f'<pre><code>sudo /opt/psf-security-patches/{esc(s)} {first}</code></pre>'
        elif not cmds: run = f'<pre><code>/opt/psf-security-patches/{esc(s)}</code></pre>'
        else: run = ""
        mp = f'<a href="{posixpath.relpath("man/" + man_name(s) + ".html", d)}">manual page</a>'
        dflt = default_command(helptext(s))
        if dflt in CHANGERS:
            run += f'<p class="warn"><strong>Type the command every time.</strong> Run with no command, this script does <code>{dflt}</code>, which changes the system.</p>'
        blocks.append(f'<div class="scr"><code>{esc(posixpath.basename(s))}</code> ({mp}, <a href="{SRC}{s}">source</a>)<br>{"; ".join(parts)}{run}</div>')
    if blocks:
        hint = ""
        if any("--dry-run" in helptext(s) and any(c in CHANGERS for c in commands_of(helptext(s))) for s in mine):
            hint = '<p class="hint">Add <code>--dry-run</code> to see a change before it happens.</p>'
        items.append(("Script" if len(blocks) == 1 else "Scripts", "".join(blocks) + hint))
    fam = next((f for f in RELATED if d in f), None)
    if fam:
        items.append(("Related", ", ".join(f'<a href="{posixpath.relpath(tool_out(x), d)}">{esc(labels[x])}</a>' for x in fam if x != d)))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in items)
    return f'<aside class="glance" aria-label="At a glance"><h2 class="sr">At a glance</h2><dl>{dl}</dl></aside>'

order_tools = sorted(tool_dirs, key=lambda x: labels[x].lower())
for i, d in enumerate(order_tools):
    text = clean_tool_md(tool_text[d]); h, toc = render_md(text)
    out = tool_out(d); h = rewriter(d + "/README.md", out)(h)
    prv = order_tools[i - 1] if i else None; nxt = order_tools[i + 1] if i + 1 < len(order_tools) else None
    nav = f'<p class="edit"><a href="{SRC}{d}/README.md">Edit this page on Codeberg</a></p><nav class="pn" aria-label="Previous and next tool">'
    nav += f'<a rel="prev" href="{posixpath.relpath(tool_out(prv), d)}">&larr; {esc(labels[prv])}</a>' if prv else "<span></span>"
    nav += f'<a rel="next" href="{posixpath.relpath(tool_out(nxt), d)}">{esc(labels[nxt])} &rarr;</a>' if nxt else "<span></span>"
    nav += "</nav>"
    cat = CATEGORIES[cat_of[d]][0]
    desc = next((r["cells"][0] for r in rows if r["dir"] == d and r["cells"]), "")
    add(out, tool_title[d] or labels[d], f'<p class="kicker-line"><a href="{posixpath.relpath("tools.html", d)}#{ghslug(cat)}">{esc(cat)}</a></p><h1>{esc(tool_title[d])}</h1>' + glance(d) + h,
        toc, kind="Tool", extra_heads=cves_of[d], footer_nav=nav, crumbs=[("Tools", "tools.html")], crumb=labels[d], desc=re.sub(r"`", "", desc))

# ---- manual pages
rows_m = []
for s in scripts:
    n = man_name(s); d = posixpath.dirname(s); t = helptext(s)
    first = re.sub(r"\s+\(v\d+\)\s*$", "", t.split("\n")[0].strip())
    readme = f'<a href="{posixpath.relpath(tool_out(d), "man")}">{esc(labels.get(d, d))}</a>' if d in tool_dirs else ""
    body = f'<h1>{esc(n)}(8)</h1><p class="meta">Script: <code>/opt/psf-security-patches/{esc(s)}</code>. {("Tool page: " + readme + ". ") if readme else ""}<a href="{SRC}{s}">Source</a>. With the package installed: <code>man {esc(n)}</code>.</p><pre class="manual">{esc(t)}</pre>'
    add(f"man/{n}.html", f"{n}(8)", body, crumbs=[("Manual pages", "man/index.html")], kind="Manual page",
        desc=first if len(first) >= 20 else f"Manual page for {n}, a PrivacySafe security script: {labels.get(d, d)}.")
    rows_m.append((n, first))
intro = ('<h1>Manual pages</h1><p>Every script has a manual page, installed with the packages. Start with <code>man psf-security-patches</code> for the overview, then <code>man psf-NAME</code> for a tool, or read the whole set with <code>info psf-security-patches</code>. The pages below show the same text each script prints for <code>--help</code>.</p>'
         '<p class="js-only"><label class="sr" for="tool-filter">Filter the manual pages</label><input id="tool-filter" type="search" placeholder="Filter, for example nginx or CVE-2026-110353" autocomplete="off"></p><p class="status js-only" id="filter-status" role="status" aria-live="polite"></p>'
         '<div class="table-wrap"><table class="tools-table"><thead><tr><th>Page</th><th>What it covers</th></tr></thead><tbody>')
intro += "".join(f'<tr><td><a href="{n}.html">{esc(n)}(8)</a></td><td>{esc(t)}</td></tr>' for n, t in rows_m) + "</tbody></table></div>"
add("man/index.html", "Manual pages", intro, desc="Manual pages for every PrivacySafe security script.", wide=True)

_404 = None if APP else page_html("404.html", "Page not found", '<h1>Page not found</h1><p>That page is not here. Try the <a href="index.html">home page</a>, the <a href="tools.html">list of tools</a>, the <a href="cves.html">CVE index</a> or the search box above.</p>')
if BASE_PATH and _404: _404 = _404.replace("<head>", f'<head><base href="{esc(BASE_PATH)}">', 1)
if _404: write("404.html", _404)

open(os.path.join(OUT, "assets", "search-index.js"), "w", encoding="utf-8").write("window.PSF_INDEX=" + json.dumps(pages, ensure_ascii=False, separators=(",", ":")) + ";\n")
if APP:
    feed_url = BASE_URL + "feed.xml"
    ents = ""
    for r in sorted(newest_rows, key=lambda r: r["iso"], reverse=True):
        link = BASE_URL + r["dir"] + "/" + ("#" + r["anchor"] if r["anchor"] else "")
        ents += (f'<entry><title>{esc(r["label"])}</title><link href="{esc(link)}"/><id>{esc(BASE_URL + r["dir"] + "/")}#{r["iso"]}</id>'
                 f'<updated>{r["iso"]}T00:00:00Z</updated><summary type="text">{esc(r["what"])}</summary></entry>\n')
    open(os.path.join(OUT, "feed.xml"), "w", encoding="utf-8").write(
        '<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"><title>PrivacySafe Security Patches: newest advisories</title>'
        '<subtitle>Checks, hunts and protection for serious vulnerabilities, from PrivacySafe.</subtitle>'
        f'<link href="{esc(feed_url)}" rel="self" type="application/atom+xml"/><link href="{esc(BASE_URL)}"/><id>{esc(BASE_URL)}</id>'
        f'<updated>{DATE}T00:00:00Z</updated><author><name>PrivacySafe Foundation</name><uri>https://privacysafe.foundation</uri></author>'
        f'<rights>CC0 1.0 Universal</rights>\n{ents}</feed>\n')
    json.dump([{"date": r["iso"], "title": r["label"], "url": BASE_URL + r["dir"] + "/" + ("#" + r["anchor"] if r["anchor"] else ""), "what": r["what"]} for r in sorted(newest_rows, key=lambda r: r["iso"], reverse=True)],
              open(os.path.join(OUT, "newest.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({"scripts": len(scripts), "cves": len(order), "tool_pages": len(tool_dirs), "release": RELEASE, "date": DATE}, open(os.path.join(OUT, "stats.json"), "w"), indent=1)
    # the section uses /docs/css/docs.css and /docs/js/docs.js; keep those two in step with packaging/site/
    if DOCS_ROOT:
        for sub, f in (("css", "docs.css"), ("js", "docs.js")):
            os.makedirs(os.path.join(DOCS_ROOT, sub), exist_ok=True)
            shutil.copy(os.path.join(ROOT, "packaging", "site", f), os.path.join(DOCS_ROOT, sub, f))
else:
    for f in ("site.css", "site.js"):
        shutil.copy(os.path.join(ROOT, "packaging", "site", f), os.path.join(OUT, "assets", f))
print(f"site written to {OUT}: {len(pages)} pages, {len(tool_dirs)} tool pages, {len(scripts)} manual pages, {len(order)} CVEs")
