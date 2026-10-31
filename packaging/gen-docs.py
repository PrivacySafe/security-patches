#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: manual page and info manual generator
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Builds one manual page (section 8) for every script, an overview page
# (section 7) and a Texinfo manual, all from the text each script prints for
# --help, so the manuals always say what the tools say. Run it from the
# repository root after you change a script's header, and commit the result:
#
#   python3 packaging/gen-docs.py [--date 2026-10-30] [--release 26.10.30-1.0.0]
#
# Writes man/man8/psf-NAME.8, man/man7/psf-security-patches.7 and
# man/psf-security-patches.texi. If makeinfo is installed it also writes
# man/psf-security-patches.info.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import os, re, subprocess, sys, datetime, textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATE = "2026-10-30"; RELEASE = "26.10.30-1.0.0"
args = sys.argv[1:]
while args:
    if args[0] == "--date": DATE = args[1]; args = args[2:]
    elif args[0] == "--release": RELEASE = args[1]; args = args[2:]
    else: sys.exit("usage: gen-docs.py [--date YYYY-MM-DD] [--release X]")
LONGDATE = datetime.date.fromisoformat(DATE).strftime("%-d %B %Y")
URL = "https://codeberg.org/PrivacySafe/security-patches"

NEWEST = [  # (date, script, what happened)
 ("30 October 2026", "vsftpd/vsftpd-ftps-ticket-check.sh", "vsftpd FTPS data channel hijack (CVE-2026-119568) and a denial of service in Red Hat family packages (CVE-2025-14242)"),
 ("29 October 2026", "claude-code-vsx/claude-code-vsx-oct2026-check.sh", "the tampered Claude Code extension served from Cursor's marketplace (no CVE)"),
 ("25 October 2026", "brotli/brotli-oct2026-check.sh", "Brotli decoder out-of-bounds write (CVE-2026-111497)"),
 ("24 October 2026", "grav/grav-core-check.sh", "Grav core allowlist bypass (CVE-2026-116019)"),
 ("23 October 2026", "basercms/basercms-check.sh", "baserCMS 5 (CVE-2026-114621, CVE-2026-114622, CVE-2026-114624)"),
 ("23 October 2026", "openapi/openapi-codegen-check.sh", "openapi-typescript-codegen code injection (CVE-2026-108551)"),
 ("23 October 2026", "ruby/ruby-regexp-oct2026-check.sh", "Ruby and GitLab regular expression memory corruption"),
 ("22 October 2026", "django/drf-check.sh", "Django REST framework (CVE-2026-114138, CVE-2026-114137)"),
 ("22 October 2026", "expat/expat-check.sh", "libexpat entity amplification (CVE-2026-115506)"),
 ("22 October 2026", "haproxy/haproxy-check.sh", "HAProxy HTTP/2 PING frame (CVE-2026-110353)"),
 ("22 October 2026", "rsyslog/rsyslog-dynafile-audit.sh", "rsyslog dynaFile path traversal (CVE-2026-92709)"),
 ("22 October 2026", "yootheme/yootheme-check.sh", "YOOtheme Pro remote code execution (CVE-2026-102785)"),
]
COPYRIGHT = ("CC0 1.0 Universal. To the extent possible under law, Ivy Cyber LLC has waived all copyright and "
             "related or neighboring rights to PrivacySafe Security Patches, including its software and documentation. "
             "CC0 does not waive trademark or patent rights.")
AUTHORS = "Written and published by PrivacySafe Foundation, a 501(c)(3) nonprofit, with the assistance of Ivy Cyber LLC."

def find_scripts():
    out = []
    for dp, dn, fn in os.walk(ROOT):
        rel = os.path.relpath(dp, ROOT)
        if rel.startswith(("packaging", ".git", "man", "dist")): continue
        for f in fn:
            if f.endswith(".sh"): out.append(os.path.join(rel, f) if rel != "." else f)
    return sorted(out)

def helptext(path):
    r = subprocess.run(["bash", os.path.join(ROOT, path), "--help"], capture_output=True, text=True, timeout=30, cwd=ROOT)
    return r.stdout.rstrip("\n")

def trailer(path):
    names = []
    for l in open(os.path.join(ROOT, path), errors="ignore"):
        if l.startswith("# Assisted-by:"): names.append(l.split(":", 1)[1].strip())
    return sorted(set(names))

def esc(s):
    s = s.replace("\\", "\\e")
    def tok(m):
        t = m.group(0)
        if t.lstrip("(\"[\'").startswith("-") or "/" in t or "=" in t: t = t.replace("-", "\\-")
        if len(t) > 40 and "/" in t: t = t.replace("/", "/\\:")   # let very long paths and URLs wrap
        return t
    s = re.sub(r"\S+", tok, s)
    if s.startswith((".", "'")): s = "\\&" + s
    return s

def split_help(text):
    lines = text.split("\n")
    title = re.sub(r"\s+\(v\d+\)\s*$", "", lines[0].strip())
    i = 1; sub = ""
    if i < len(lines) and lines[i].strip() and not lines[i].startswith("If this software"):
        sub = lines[i].strip(); i += 1
    body = lines[i:]
    # drop the donation lines
    clean = []; skip = 0
    for j, l in enumerate(body):
        if l.startswith("If this software is helpful"): skip = 2
        if skip: skip -= 1; continue
        clean.append(l)
    while clean and not clean[0].strip(): clean.pop(0)
    return title, sub, clean

def blocks(lines):
    """Group lines into paragraphs and indented blocks."""
    out = []; cur = []; kind = None
    def flush():
        nonlocal cur, kind
        if cur: out.append((kind, cur)); cur = []; kind = None
    for l in lines:
        if not l.strip(): flush(); continue
        ind = len(l) - len(l.lstrip())
        k = "indent" if ind >= 2 else "para"
        if kind and k != kind: flush()
        kind = k; cur.append(l)
    flush()
    return out

def wrap_literal(l, width=66):
    if len(l) <= width or re.search(r"\S {3,}\S", l): return [l]
    ind = len(l) - len(l.lstrip())
    return textwrap.wrap(l.strip(), width=width, initial_indent=" " * ind, subsequent_indent=" " * (ind + 2), break_long_words=False, break_on_hyphens=False) or [l]

def table_like(lines):
    return any(re.search(r"\S {3,}\S", l.strip()) for l in lines) or any(l.lstrip().startswith(("- ", "* ")) for l in lines)

def roff_blocks(lines):
    r = []
    for kind, ls in blocks(lines):
        if kind == "para":
            r.append(".PP"); r.extend(esc(l.strip()) for l in ls)
        elif table_like(ls):
            r.append(".RS 2"); r.append(".nf")
            m = min(len(l) - len(l.lstrip()) for l in ls)
            for l in ls:
                for w in wrap_literal(l[m:].rstrip()): r.append(esc(w))
            r.append(".fi"); r.append(".RE")
        else:
            r.append(".RS 2"); r.append(".PP")
            r.extend(esc(l.strip()) for l in ls); r.append(".RE")
    return r

def usage_parts(clean):
    """Split into description lines, synopsis line, usage entries and trailing col-0 sections."""
    try: u = next(i for i, l in enumerate(clean) if re.match(r"Usage\b[^:]*:\s*$", l.strip()))
    except StopIteration: return clean, None, [], []
    desc = clean[:u]; rest = clean[u + 1:]
    syn = None
    for l in rest:
        if l.strip().startswith("./"): syn = l.strip(); break
    entries = []; extra = []; cur = None; in_extra = False
    for l in rest:
        if not l.strip():
            if cur and not in_extra: cur["gap"] = True
            if in_extra: extra.append(l)
            continue
        if l.strip() == syn: continue
        ind = len(l) - len(l.lstrip())
        if ind == 0 and not in_extra: in_extra = True
        if in_extra: extra.append(l); continue
        if ind <= 3:
            m = re.match(r"^\s*(\S.*?)(?:\s{2,}(\S.*))?$", l)
            cur = {"term": m.group(1), "text": [m.group(2)] if m.group(2) else [], "lines": []}
            entries.append(cur)
        elif cur is not None:
            cur["lines"].append(l)
    return desc, syn, entries, extra

def left_adjust(lines):
    """.SH resets the adjustment mode, so set it again after every section heading."""
    out = []; prev = ""
    for l in lines:
        out.append(l)
        if l.startswith(".SH ") or prev.startswith(".TP"): out.append(".ad l")   # .TP resets it after the term line too
        prev = l
    return out

def man_page(path):
    base = os.path.basename(path)[:-3]; name = "psf-" + base
    d = os.path.dirname(path)
    title, sub, clean = split_help(helptext(path))
    desc, syn, entries, extra = usage_parts(clean)
    full = f"/opt/psf-security-patches/{path}"
    o = []
    o.append(f'.TH {esc(name.upper())} 8 "{LONGDATE}" "psf-security-patches {RELEASE}" "System Administration"')
    o.append(".ad l")
    o.append(".SH NAME"); o.append(f"{esc(name)} \\- {esc(title)}")
    o.append(".SH SYNOPSIS")
    if syn:
        o.append("\\fB" + esc(full).replace("/", "/\\:") + "\\fR" + esc(re.sub(r"^\./\S+", "", syn)))
    else:
        o.append(".B " + esc(full).replace("/", "/\\:"))
    o.append(".SH DESCRIPTION")
    if sub: o.append(".PP"); o.append(esc(sub))
    o.extend(roff_blocks(desc))
    if entries:
        o.append(".SH COMMANDS AND OPTIONS")
        for e in entries:
            o.append(".TP"); o.append("\\fB" + esc(e["term"]) + "\\fR")
            body = []
            if e["text"]: body.append(esc(" ".join(e["text"])))
            if e["lines"]:
                base = min(len(l) - len(l.lstrip()) for l in e["lines"])
                lit = []
                def flush_lit():
                    nonlocal lit
                    if not lit: return
                    rows = []; ok = True
                    m = min(len(x) - len(x.lstrip()) for x in lit)
                    for x in lit:
                        ind = len(x) - len(x.lstrip())
                        mm = re.match(r"^(\S.*?)\s{2,}(\S.*)$", x.strip())
                        if ind == m and mm: rows.append([mm.group(1), [mm.group(2)]])
                        elif ind == m and not mm: rows.append([x.strip(), []])
                        elif rows: rows[-1][1].append(x.strip())
                        else: ok = False
                    if ok and rows:
                        body.append(".RS 2")
                        for term, txts in rows:
                            body.append(".TP 10"); body.append("\\fB" + esc(term) + "\\fR"); body.append(esc(" ".join(txts)) if txts else "")
                        body.append(".RE")
                    else:
                        body.append(".RS 2"); body.append(".nf")
                        for x in lit:
                            for w in wrap_literal(x[m:].rstrip(), 56): body.append(esc(w))
                        body.append(".fi"); body.append(".RE")
                    lit = []
                for l in e["lines"]:
                    ind = len(l) - len(l.lstrip())
                    if ind >= base + 2: lit.append(l)
                    else: flush_lit(); body.append(esc(l.strip()))
                flush_lit()
            o.extend(body if body else [""])
    if extra:
        o.extend(roff_blocks(extra))
    sd = re.findall(r"/var/lib/psf-security-patches/[A-Za-z0-9._/-]+", helptext(path))
    o.append(".SH FILES")
    o.append(".TP"); o.append("\\fB" + esc(full).replace("/", "/\\:") + "\\fR"); o.append("The script.")
    for s in sorted(set(sd)):
        o.append(".TP"); o.append("\\fB" + esc(s) + "\\fR"); o.append("Backups and the record that rollback uses.")
    o.append(".SH SEE ALSO")
    siblings = sorted(os.path.basename(p)[:-3] for p in ALL if os.path.dirname(p) == d and p != path)
    refs = ["psf\\-security\\-patches(7)"] + [esc("psf-" + s) + "(8)" for s in siblings]
    o.append(", ".join(refs) + ".")
    o.append(".PP"); o.append(esc(URL)); o.append(".br"); o.append("Documentation: https://privacysafe.app/docs/security-patches/"); o.append(".br"); o.append("PrivacySafe: https://privacysafe.app")
    o.append(".SH AUTHORS"); o.append(esc(AUTHORS))
    tr = trailer(path)
    if tr:
        o.append(".PP"); o.append(esc("AI assistance in this script: " + ", ".join(tr) + " (the Assisted-by line in the script header)."))
    o.append(".SH COPYRIGHT"); o.append(esc(COPYRIGHT))
    o.append(".PP"); o.append("If this software is helpful, please consider supporting PrivacySafe Foundation: https://privacysafe.foundation")
    return name, title, "\n".join(left_adjust(o)) + "\n"

def overview(pages):
    o = []
    o.append(f'.TH PSF\\-SECURITY\\-PATCHES 7 "{LONGDATE}" "psf-security-patches {RELEASE}" "Miscellaneous"')
    o.append(".ad l")
    o.append(".SH NAME"); o.append("psf\\-security\\-patches \\- security checks, hunts and protection for serious vulnerabilities")
    o.append(".SH DESCRIPTION")
    o.append(".PP"); o.append("Free security tools for GNU/Linux servers (and one for developer machines), written by PrivacySafe Foundation with the help of Ivy Cyber and released into the public domain. When a serious vulnerability is announced, each tool tells you whether your machine is exposed and looks for signs that someone has already used the flaw. Where there is a safe way to do it, the tool also protects the machine until you can update. Everything is plain bash.")
    o.append(".SH GETTING STARTED")
    o.append(".IP 1. 3"); o.append("Run the tool's \\fBcheck\\fR. It changes nothing.")
    o.append(".IP 2. 3"); o.append("If you are exposed, install the vendor's update. That is the permanent fix.")
    o.append(".IP 3. 3"); o.append("If you cannot update yet, run \\fBmitigate \\-\\-dry\\-run\\fR to see what the protection would do, then \\fBmitigate\\fR. \\fBrollback\\fR undoes it.")
    o.append(".IP 4. 3"); o.append("If the flaw was being exploited, run \\fBhunt\\fR, then change any password, key or token an attacker could have reached.")
    o.append(".SH NEWEST: 22 TO 30 OCTOBER 2026")
    byscript = {p: n for n, p, t in pages}
    for date, script, what in NEWEST:
        n = "psf-" + os.path.basename(script)[:-3]
        o.append(".TP"); o.append(esc(date) + ": \\fB" + esc(n) + "\\fR(8)"); o.append(esc(what))
    o.append(".SH ALL TOOLS")
    for n, p, t in pages:
        o.append(".TP"); o.append("\\fB" + esc(n) + "\\fR(8)"); o.append(esc(t))
    o.append(".SH COMMON COMMANDS")
    o.append(".TP"); o.append("\\fBcheck\\fR"); o.append("Reports whether this machine is exposed. Read-only. Most tools run it when you give no command; the PHP2Shell and eMudhra mitigation scripts apply their protection instead, so type the command every time.")
    o.append(".TP"); o.append("\\fBhunt\\fR"); o.append("Looks for signs of exploitation. Read-only.")
    o.append(".TP"); o.append("\\fBmitigate\\fR"); o.append("Applies protection you can undo. Copies every file first, checks the result with the service's own checker, puts the original back if the check fails, and reloads nothing unless you ask. Supports \\fB\\-\\-dry\\-run\\fR.")
    o.append(".TP"); o.append("\\fBrollback\\fR"); o.append("Undoes what mitigate changed.")
    o.append(".SH ENVIRONMENT")
    o.append(".TP"); o.append("\\fBSCAN_CONTAINERS\\fR"); o.append("Set to 0 to skip running docker and podman containers.")
    o.append(".TP"); o.append("\\fBSTATE_DIR\\fR"); o.append("Where a tool keeps its backups and rollback record. Each tool documents its default under /var/lib/psf\\-security\\-patches.")
    o.append(".SH FILES")
    o.append(".TP"); o.append("\\fB/opt/psf\\-security\\-patches/\\fR"); o.append("The tools, one folder per product.")
    o.append(".TP"); o.append("\\fB/usr/share/doc/psf\\-security\\-patches/\\fR"); o.append("README, change log, licence and notice. On RPM systems the folder is psf\\-security\\-patches\\-VERSION.")
    o.append(".SH SEE ALSO"); o.append("info psf\\-security\\-patches")
    o.append(".PP"); o.append(esc(URL)); o.append(".br"); o.append("Documentation: https://privacysafe.app/docs/security-patches/"); o.append(".br"); o.append("PrivacySafe: https://privacysafe.app")
    o.append(".SH AUTHORS"); o.append(esc(AUTHORS))
    o.append(".PP"); o.append("AI assistance is disclosed in each script, in the Assisted-by line of its header, and in each manual page.")
    o.append(".SH COPYRIGHT"); o.append(esc(COPYRIGHT))
    return "\n".join(left_adjust(o)) + "\n"

def tex(s): return s.replace("@", "@@").replace("{", "@{").replace("}", "@}")

def texi(pages, texts):
    o = []
    o.append("\\input texinfo")
    o.append("@setfilename psf-security-patches.info")
    o.append("@settitle PrivacySafe Security Patches")
    o.append("@documentencoding UTF-8")
    o.append("@dircategory System administration")
    o.append("@direntry")
    o.append("* PrivacySafe Security Patches: (psf-security-patches).    Security checks, hunts and protection for serious vulnerabilities.")
    o.append("@end direntry")
    o.append("@copying")
    o.append(tex(f"PrivacySafe Security Patches {RELEASE}. {COPYRIGHT}"))
    o.append("@end copying")
    o.append("@titlepage"); o.append("@title PrivacySafe Security Patches")
    o.append("@subtitle " + tex(f"Release {RELEASE}")); o.append("@page"); o.append("@vskip 0pt plus 1filll"); o.append("@insertcopying"); o.append("@end titlepage")
    o.append("@contents")
    o.append("@ifnottex"); o.append("@node Top"); o.append("@top PrivacySafe Security Patches")
    o.append("Free security tools for GNU/Linux servers (and one for developer machines), written by PrivacySafe Foundation with the help of Ivy Cyber and released into the public domain.")
    o.append("@insertcopying"); o.append("@end ifnottex")
    o.append("@menu"); o.append("* Start here::"); o.append("* Newest::"); o.append("* Tools::"); o.append("* Files and environment::"); o.append("* Credits and license::"); o.append("@end menu")
    o.append("@node Start here"); o.append("@chapter Start here"); o.append("@enumerate")
    o.append("@item"); o.append("Run the tool's @code{check}. It changes nothing.")
    o.append("@item"); o.append("If you are exposed, install the vendor's update. That is the permanent fix.")
    o.append("@item"); o.append("If you cannot update yet, run @code{mitigate --dry-run} to see what the protection would do, then @code{mitigate}. @code{rollback} undoes it.")
    o.append("@item"); o.append("If the flaw was being exploited, run @code{hunt}, then change any password, key or token an attacker could have reached.")
    o.append("@end enumerate")
    o.append("@node Newest"); o.append("@chapter Newest: 22 to 30 October 2026"); o.append("@table @asis")
    for date, script, what in NEWEST:
        n = "psf-" + os.path.basename(script)[:-3]
        o.append("@item " + tex(f"{date}: {n}")); o.append(tex(what))
    o.append("@end table")
    o.append("@node Tools"); o.append("@chapter Tools"); o.append("@menu")
    for n, p, t in pages: o.append(f"* {n}::  {tex(t)}")
    o.append("@end menu")
    for n, p, t in pages:
        o.append(f"@node {n}"); o.append(f"@section {n}")
        o.append(tex(t)); o.append("@example"); o.append(tex(texts[p]))
        o.append("@end example")
        o.append(tex(f"The script is /opt/psf-security-patches/{p}. Manual page: {n}(8)."))
    o.append("@node Files and environment"); o.append("@chapter Files and environment")
    o.append("@table @file"); o.append("@item /opt/psf-security-patches/"); o.append("The tools, one folder per product.")
    o.append("@item /usr/share/doc/psf-security-patches/"); o.append("README, change log, licence and notice. On RPM systems the folder is psf-security-patches-VERSION."); o.append("@end table")
    o.append("@table @env"); o.append("@item SCAN_CONTAINERS"); o.append("Set to 0 to skip running docker and podman containers.")
    o.append("@item STATE_DIR"); o.append("Where a tool keeps its backups and rollback record.")
    o.append("@end table")
    o.append("@node Credits and license"); o.append("@chapter Credits and license")
    o.append(tex(AUTHORS)); o.append("")
    o.append("AI assistance is disclosed in each script, in the Assisted-by line of its header.")
    o.append(""); o.append(tex(COPYRIGHT))
    o.append(""); o.append(tex(f"Project: {URL}"))
    o.append("@bye")
    return "\n".join(o) + "\n"

ALL = find_scripts()
os.makedirs(os.path.join(ROOT, "man", "man8"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "man", "man7"), exist_ok=True)
pages = []; texts = {}
for p in ALL:
    n, t, body = man_page(p)
    open(os.path.join(ROOT, "man", "man8", n + ".8"), "w").write(body)
    pages.append((n, p, t)); texts[p] = helptext(p)
pages.sort()
open(os.path.join(ROOT, "man", "man7", "psf-security-patches.7"), "w").write(overview(pages))
open(os.path.join(ROOT, "man", "psf-security-patches.texi"), "w").write(texi(pages, texts))
import shutil
if shutil.which("makeinfo"):
    r = subprocess.run(["makeinfo", "--no-split", "-o", os.path.join(ROOT, "man", "psf-security-patches.info"), os.path.join(ROOT, "man", "psf-security-patches.texi")], capture_output=True, text=True)
    if r.returncode: sys.exit("makeinfo failed:\n" + r.stderr[:600])
    print(f"wrote {len(pages)} manual pages, the overview page, the Texinfo manual and the info file")
else:
    print(f"wrote {len(pages)} manual pages, the overview page and the Texinfo manual; makeinfo is not installed, so man/psf-security-patches.info was not rebuilt and is out of date")
