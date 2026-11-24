#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: documentation site checker
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Checks the generated site: every link and anchor resolves, ids are unique,
# the site loads nothing from other sites, images have alt text, each page
# has one h1 and a title, tags balance, and no page uses a dash character.
#
#   python3 packaging/check-site.py SITE_DIR
#   python3 packaging/check-site.py --webroot /path/to/privacysafe-app-site
#
# The second form checks the whole docs/ tree of the privacysafe.app site: links
# that start with / are resolved under the web root, the only outside script
# allowed is the site's metrics script, no page may use inline styles, inline
# scripts or event handler attributes (the site's Content Security Policy forbids
# them), every page's canonical URL must match where the file is served, and
# every JSON-LD block must parse.
#
# It also holds the pages to one standard: no emoji is left on any page (the READMEs'
# emoji are drawn as icons), every icon is hidden from screen readers, every tool page has
# the same parts in the same order, and on privacysafe.app every page carries the same
# header row, ecosystem card and footer.
#
# Exit 0 when everything passes, 1 otherwise.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psf_icons
from html.parser import HTMLParser
from urllib.parse import unquote

ARGS = sys.argv[1:]; WEBROOT = None
if ARGS[:1] == ["--webroot"]: WEBROOT = os.path.abspath(ARGS[1]); ARGS = ARGS[2:]
if not WEBROOT and not ARGS: sys.exit("usage: check-site.py SITE_DIR   or   check-site.py --webroot SITE_ROOT\nCheck docs/ for the repository copy, or any other generated site folder.")
SITE = os.path.join(WEBROOT, "docs") if WEBROOT else os.path.abspath(ARGS[0])
NO_SCRIPT_OK = {"runtimes/php/detect/index.html"}                        # detection rules: there is no script to describe
NESTED_OK = {"runtimes/php/index.html", "developer/claude-code-vsx/index.html"}      # these pages have sections under Before you run it
ALLOWED_EXTERNAL = {"https://privacysafe.click/js/script.js"} if WEBROOT else set()
import json
VOID = {"meta", "link", "img", "br", "hr", "input", "source", "col", "area", "base", "wbr"}
DASHES = "".join(chr(c) for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212))

class P(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []; self.links = []; self.res = []; self.h1 = 0; self.title = False; self.title_text = ""
        self.stack = []; self.errors = []; self.imgs_no_alt = 0; self.inline = []; self.scripts = []; self.ld_open = False; self.ld = []; self.canonical = None; self.refresh = None; self.noindex = False
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d: self.ids.append(d["id"])
        if tag == "a" and "name" in d: self.ids.append(d["name"])
        if "style" in d: self.inline.append(f"style attribute on <{tag}>")
        for k in d:
            if k.startswith("on"): self.inline.append(f"{k} attribute on <{tag}>")
        if tag == "style": self.inline.append("<style> block")
        if tag == "script" and "src" not in d and d.get("type") != "application/ld+json": self.inline.append("inline <script>")
        if tag == "script" and d.get("type") == "application/ld+json": self.ld_open = True
        if tag == "script" and "src" in d: self.scripts.append((d["src"], d.get("data-domain"), "defer" in d))
        if tag == "link" and d.get("rel") == "canonical": self.canonical = d.get("href")
        if tag == "meta" and (d.get("http-equiv") or "").lower() == "refresh": self.refresh = (d.get("content") or "").partition("url=")[2]
        if tag == "meta" and d.get("name") == "robots" and "noindex" in (d.get("content") or ""): self.noindex = True
        if tag == "h1": self.h1 += 1
        if tag == "title": self.title = True
        if tag == "a" and "href" in d: self.links.append(d["href"])
        if tag == "link" and d.get("href") and (d.get("rel") or "").lower() in ("stylesheet", "icon", "shortcut icon", "apple-touch-icon", "preload", "manifest"): self.res.append(d["href"])
        if tag in ("script", "img", "source") and d.get("src"): self.res.append(d["src"])
        if tag == "img" and "alt" not in d: self.imgs_no_alt += 1
        if tag not in VOID: self.stack.append(tag)
    def handle_endtag(self, tag):
        if tag == "title": self.title = False
        if tag in VOID: return
        if not self.stack or self.stack[-1] != tag:
            if tag in self.stack:
                while self.stack and self.stack[-1] != tag: self.errors.append(f"unclosed <{self.stack.pop()}>")
                self.stack.pop()
            else: self.errors.append(f"stray </{tag}>")
        else: self.stack.pop()
    def handle_data(self, data):
        if self.title: self.title_text += data
        if self.ld_open: self.ld.append(data); self.ld_open = False

pages = {}
for dp, dn, fn in os.walk(SITE):
    for f in fn:
        if f.endswith(".html"):
            p = os.path.join(dp, f); pages[os.path.relpath(p, SITE)] = P()
            raw = open(p, encoding="utf-8").read(); pages[os.path.relpath(p, SITE)].feed(raw); pages[os.path.relpath(p, SITE)].raw = raw
problems = []
def bad(page, msg): problems.append(f"{page}: {msg}")
ids = {k: set(v.ids) for k, v in pages.items()}
for name, pr in sorted(pages.items()):
    if len(pr.ids) != len(set(pr.ids)):
        dup = sorted({i for i in pr.ids if pr.ids.count(i) > 1}); bad(name, f"duplicate ids {dup[:4]}")
    if pr.h1 != 1: bad(name, f"{pr.h1} h1 elements")
    if not pr.title_text.strip(): bad(name, "no title")
    if pr.imgs_no_alt: bad(name, "image without alt text")
    for e in pr.errors[:3] + [f"unclosed <{t}>" for t in pr.stack[:3]]: bad(name, e)
    if WEBROOT:
        for msg in sorted(set(pr.inline)): bad(name, f"inline code the Content Security Policy forbids: {msg}")
    for blob in pr.ld:
        try: json.loads(blob)
        except Exception as e: bad(name, f"JSON-LD does not parse: {e}")
    if WEBROOT:
        metrics = [s for s in pr.scripts if s[0] == "https://privacysafe.click/js/script.js"]
        if len(metrics) != 1 or metrics[0][1] != "privacysafe.app" or not metrics[0][2]: bad(name, "the privacysafe.click metrics script is missing, repeated, or lacks data-domain=privacysafe.app and defer")
        if ("/docs/js/docs.js", None, True) not in pr.scripts: bad(name, "the docs script is missing")
        want = "https://privacysafe.app/" + ("docs/" + (name[:-len("index.html")] if name.endswith("index.html") else name)).replace("//", "/")
        if pr.refresh is not None:
            # a page left at a moved page's old address: it forwards to a page that exists, names that page as
            # canonical, and asks not to be indexed
            tgt = pr.refresh
            if not tgt.startswith("https://privacysafe.app/docs/"): bad(name, f"forwards outside the docs: {tgt}")
            else:
                full = os.path.join(WEBROOT, "docs", tgt[len("https://privacysafe.app/docs/"):])
                if full.endswith("/"): full += "index.html"
                if not os.path.exists(full): bad(name, f"forwards to {tgt}, which does not exist")
                if os.path.exists(full) and 'http-equiv="refresh"' in open(full, encoding="utf-8").read(): bad(name, f"forwards to {tgt}, itself a forwarding page")
            if pr.canonical != tgt: bad(name, f"canonical {pr.canonical} should be the page it forwards to, {tgt}")
            if not pr.noindex: bad(name, "forwarding page without noindex")
        elif pr.canonical != want: bad(name, f"canonical {pr.canonical} should be {want}")
    for r in pr.res:
        if r in ALLOWED_EXTERNAL: continue
        if re.match(r"^(https?:)?//", r): bad(name, f"loads an outside resource: {r}")
        elif r.startswith("/") and WEBROOT:
            if not os.path.exists(os.path.join(WEBROOT, unquote(r.split("#")[0].split("?")[0]).lstrip("/"))): bad(name, f"missing resource {r}")
        elif not os.path.exists(os.path.normpath(os.path.join(SITE, os.path.dirname(name), unquote(r.split('#')[0].split('?')[0])))): bad(name, f"missing resource {r}")
    for l in pr.links:
        if re.match(r"^(https?:|mailto:|data:)", l): continue
        path, _, anchor = l.partition("#")
        if WEBROOT and l.startswith("/"):
            if path in ("", "/"): continue                      # the home page is not part of this tree
            full = os.path.join(WEBROOT, unquote(path).lstrip("/"))
            if os.path.isdir(full): full = os.path.join(full, "index.html")
            if not os.path.exists(full): bad(name, f"broken link {l}"); continue
            rel = os.path.relpath(full, SITE)
            if anchor and not rel.startswith("..") and rel.endswith(".html") and anchor not in ids.get(rel, set()): bad(name, f"missing anchor {l}")
            continue
        tgt = name if not path else os.path.normpath(os.path.join(os.path.dirname(name), unquote(path)))
        if path and not os.path.exists(os.path.join(SITE, tgt)): bad(name, f"broken link {l}"); continue
        if anchor and tgt.endswith(".html") and anchor not in ids.get(tgt, set()): bad(name, f"missing anchor {l}")
    if any(c in pr.raw for c in DASHES): bad(name, "contains a dash character")
    visible = re.sub(r"<(svg|script|pre|code)\b.*?</\1>", "", pr.raw, flags=re.S)
    if psf_icons.has_emoji(visible): bad(name, "an emoji is left on the page: it needs an icon in packaging/psf_icons.py")
    for tag in re.findall(r"<svg\b[^>]*\bclass=\"ico\b[^>]*>", pr.raw):
        if 'aria-hidden="true"' not in tag: bad(name, "an icon is not hidden from screen readers")
    # one standard for every tool page
    tool = name[len("security-patches/"):] if name.startswith("security-patches/") else name
    if "<aside class=\"glance\"" in pr.raw:
        for what, rx in (("a kicker line with the kind of software", r'<p class="kicker-line">'), ("the at-a-glance box", r'<aside class="glance" aria-label="At a glance">'),
                         ("a Covers line in the at-a-glance box", r"<dt>Covers</dt>"), ("a Script or Scripts line in the at-a-glance box", r"<dt>Scripts?</dt>" if tool not in NO_SCRIPT_OK else r"<dt>Covers</dt>"),
                         ("previous and next links", r'aria-label="Previous and next tool"')):
            if not re.search(rx, pr.raw): bad(name, f"tool page has no {what}")
        h = re.search(r'<(h[23]) id="before-you-run-it"', pr.raw)
        if h and h.group(1) != "h2" and tool not in NESTED_OK: bad(name, "Before you run it is a sub-heading here but a section on the other tool pages")
        if re.search(r'<h2 id="(important-notice|support-privacysafe-foundation)"', pr.raw): bad(name, "the README footer leaked onto a tool page")
        md = re.search(r'<meta\b(?=[^>]*\bname="description")[^>]*\bcontent="([^"]*)"', pr.raw)
        if not (md and 20 <= len(md.group(1)) <= 400): bad(name, "meta description is missing or the wrong length")
    # the header row, the ecosystem card and the footer are the privacysafe.app ones on every page, online and offline
    for what, rx in (("the documentation row", r'class="docs-subnav"'), ("the ecosystem card", r'id="ecosystem"'), ("the footer", r'class="footer-community"'),
                     ("the Get PrivacySafe button", r'href="/#download"' if WEBROOT else r'href="https://privacysafe\.app/#download"')):
        if not re.search(rx, pr.raw): bad(name, f"page has no {what}")
    # GNU LibreJS: the page points at a web labels page, and an inline script carries its own license notice
    if WEBROOT:
        if not re.search(r'<link href="/weblabels\.html" rel="jslicense"/>', pr.raw): bad(name, "no link to /weblabels.html with rel=jslicense")
    else:
        _m = re.search(r'<link rel="jslicense" href="([^"]+)">', pr.raw)
        if not _m or not os.path.exists(os.path.normpath(os.path.join(SITE, os.path.dirname(name), _m.group(1)))): bad(name, "no local link to weblabels.html with rel=jslicense")
        for _t in re.findall(r'<(?:a|link)\b[^>]*\brel="[^"]*jslicense[^"]*"[^>]*>', pr.raw):
            if re.search(r'href="(?:https?:)?//', _t): bad(name, "the offline page's rel=jslicense link points to an outside page")
        for _blob in re.findall(r'<script>(.*?)</script>', pr.raw, re.S):
            if not re.search(r'^// @license magnet:\S+ \S+$', _blob, re.M) or "// @license-end" not in _blob: bad(name, "an inline script has no license notice for GNU LibreJS")
    if not WEBROOT:
        for img in ("privacysafe-logo.svg", "ivy-logo-horizontal-white.svg", "logo-foundation.svg", "bitsontape-avatar.png"):
            if f"assets/img/{img}" not in pr.raw: bad(name, f"the offline page does not use its local copy of {img}")
# ---- GNU LibreJS: every script file carries its license notice, and the offline web labels list exactly the scripts of this copy
LIBREJS_OK = {"magnet:?xt=urn:btih:90dc5c0be029de84e523b9b3922520e79e0e6f08&dn=cc0.txt": "CC0-1.0",
              "magnet:?xt=urn:btih:0b31508aeb0634b347b8270c7bee4d411b5d4109&dn=agpl-3.0.txt": "AGPL-3.0",
              "magnet:?xt=urn:btih:d3d9a9a6595521f9666a5e94cc830dab83b65699&dn=expat.txt": "Expat"}
def librejs_notice(rel):
    txt = open(os.path.join(SITE, rel), encoding="utf-8").read()
    m = re.search(r"^// @license (magnet:\S+) (\S+)\s*$", txt, re.M)
    if not m: return "no '// @license magnet:... NAME' line"
    if m.group(1) not in LIBREJS_OK: return f"the magnet link {m.group(1)} is not one of the approved licenses"
    if txt[:m.start()].strip(): return "code or comments come before the license notice"
    ends = [e for e in re.finditer(r"^// @license-end\s*$", txt, re.M) if e.start() > m.end()]
    if len(ends) != 1: return f"{len(ends)} '// @license-end' lines after the notice (one is needed)"
    if any(l.strip() and not l.strip().startswith("//") for l in txt[ends[0].end():].splitlines()): return "code comes after '// @license-end'"
    return None
JS_FILES = sorted(os.path.relpath(os.path.join(dp, f), SITE) for dp, _, fs in os.walk(SITE) for f in fs if f.endswith(".js"))
for rel in JS_FILES:
    err = librejs_notice(rel)
    if err: bad(rel, f"GNU LibreJS: {err}")
if not WEBROOT:
    wl = os.path.join(SITE, "weblabels.html")
    if not os.path.exists(wl): bad("weblabels.html", "the offline copy has no web labels page")
    else:
        raw = open(wl, encoding="utf-8").read()
        t = re.search(r'<table id="jslicense-labels1">(.*?)</table>', raw, re.S)
        rows = re.findall(r"<tr><td><a href=\"([^\"]+)\">[^<]*</a></td><td><a href=\"([^\"]+)\"[^>]*>[^<]*</a></td><td><a href=\"([^\"]+)\">[^<]*</a></td></tr>", t.group(1)) if t else []
        if not t: bad("weblabels.html", "no table with id jslicense-labels1")
        listed = sorted(r[0] for r in rows)
        if listed != JS_FILES: bad("weblabels.html", f"the table lists {listed}, the site has the script files {JS_FILES}")
        for r in rows:
            if not os.path.exists(os.path.join(SITE, r[0])): bad("weblabels.html", f"{r[0]} does not exist")
            if r[2] != r[0]: bad("weblabels.html", f"the source of {r[0]} should be the file itself, not {r[2]}")
            if not r[1].startswith("https://creativecommons.org/publicdomain/zero/1.0/"): bad("weblabels.html", f"{r[0]}: the license link {r[1]} is not the CC0 text this copy's scripts carry")
for f in (("css/docs.css", "js/docs.js") if WEBROOT else ("assets/ps-base.css", "assets/docs.css", "assets/site.js")):
    if os.path.exists(os.path.join(SITE, f)) and any(ch in open(os.path.join(SITE, f), encoding="utf-8").read() for ch in DASHES): bad(f, "contains a dash character")
print(f"checked {len(pages)} pages in {SITE}")
if problems:
    print(f"{len(problems)} problems:"); [print("  " + p) for p in problems[:40]]; sys.exit(1)
print("all links, anchors, ids, headings, resources, alt text and tags pass; no dash characters, no emoji, one standard for tool pages")
