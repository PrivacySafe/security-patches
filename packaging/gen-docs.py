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
# --help, so the manuals always say what the tools say. They are not kept in the
# repository: packaging/build-release.sh builds them into the packages. Run this by
# hand to read the result:
#
#   python3 packaging/gen-docs.py --out DIR [--date 2026-11-04] [--release 26.11.04-1.0.0]
#
# Writes DIR/man8/psf-NAME.8, DIR/man7/psf-security-patches.7 and
# DIR/psf-security-patches.texi. If makeinfo is installed it also writes
# DIR/psf-security-patches.info. Without --date and --release it uses the newest
# dated heading of CHANGELOG.md.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import os, re, subprocess, sys, datetime, textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def newest_release():
    """The newest dated heading of CHANGELOG.md, as (YYYY-MM-DD, YY.MM.DD-1.0.0). A release build passes its own."""
    for line in open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8"):
        m = re.match(r"## (\d{4})-(\d{2})-(\d{2})\b", line)
        if m: return f"{m.group(1)}-{m.group(2)}-{m.group(3)}", f"{m.group(1)[2:]}.{m.group(2)}.{m.group(3)}-1.0.0"
    sys.exit("CHANGELOG.md has no dated heading")
DATE, RELEASE = newest_release(); OUT = None
args = sys.argv[1:]
while args:
    if args[0] == "--date": DATE = args[1]; args = args[2:]
    elif args[0] == "--release": RELEASE = args[1]; args = args[2:]
    elif args[0] == "--out": OUT = os.path.abspath(args[1]); args = args[2:]
    else: sys.exit("usage: gen-docs.py --out DIR [--date YYYY-MM-DD] [--release X]")
if OUT is None: sys.exit("usage: gen-docs.py --out DIR [--date YYYY-MM-DD] [--release X]\nThe manual pages are generated, not kept in the repository, so say where to write them.")
LONGDATE = datetime.date.fromisoformat(DATE).strftime("%-d %B %Y")
URL = "https://codeberg.org/PrivacySafe/security-patches"

NEWEST = [  # (date, script, what happened)
 ("4 November 2026", "apt/apt-nov2026-check.sh", "APT package downloads swapped after verification (CVE-2026-109518)"),
 ("2 November 2026", "btcpayserver/btcpayserver-nov2026-check.sh", "BTCPay Server hot wallet thefts on 2.4.1 and earlier (no CVE)"),
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
            r.append(".PP")
            for n, l in enumerate(ls):
                r.append(esc(l.strip()))
                if n + 1 < len(ls) and re.match(r"CVE-\d{4}-\d+", l.strip()) and re.match(r"CVE-\d{4}-\d+", ls[n + 1].strip()): r.append(".br")
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
    """.SH resets the adjustment mode, so set it again after every section heading, and turn hyphenation
    off so that a command, a path or a setting name is never split across two lines. A .PP straight after
    a heading adds nothing (the heading already starts a paragraph) and stricter renderers warn about it."""
    out = []; prev = ""; after_head = False
    for l in lines:
        if after_head and l == ".PP": continue
        out.append(l)
        if l.startswith(".SH "): out.append(".ad l"); out.append(".nh"); after_head = True; prev = l; continue
        if prev.startswith(".TP"): out.append(".ad l")   # .TP resets it after the term line too
        if l not in (".ad l", ".nh"): after_head = False
        prev = l
    return out

def man_page(path):
    base = os.path.basename(path)[:-3]; name = "psf-" + base
    d = os.path.dirname(path)
    title, sub, clean = split_help(helptext(path))
    desc, syn, entries, extra = usage_parts(clean)
    if sub.startswith("CVE-") and desc and desc[0].startswith("CVE-"): desc = [sub] + desc; sub = ""   # headline lines that were one block in the help
    full = f"/opt/psf-security-patches/{path}"
    o = []
    o.append(f'.TH {esc(name.upper())} 8 "{DATE}" "psf-security-patches {RELEASE}" "System Administration"')
    o.append(".nh"); o.append(".ad l")
    o.append(".SH NAME"); o.append(f"{esc(name)} \\- {esc(title)}")
    o.append(".SH SYNOPSIS")
    if syn:
        o.append("\\fB" + esc(full).replace("/", "/\\:") + "\\fR" + esc(re.sub(r"^\./\S+", "", syn)))
    else:
        o.append(".B " + esc(full).replace("/", "/\\:"))
    uq = next((re.match(r"Usage\s*\(([^)]*)\)", l.strip()).group(1) for l in clean if re.match(r"Usage\s*\([^)]*\)\s*:\s*$", l.strip())), "")
    if uq: o.append(".PP"); o.append(esc(f"Run {uq}."))   # the help says "Usage (as root):"; the synopsis keeps that
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

RHSA = os.path.join(ROOT, "packaging", "rhsa", "rhsa.py")
RHSA_DIR = "/opt/psf-security-patches/rhsa"

def rhsa_help(*a):
    env = dict(os.environ, COLUMNS="58")
    out = subprocess.run([sys.executable, RHSA, *a], capture_output=True, text=True, env=env).stdout
    return out.replace("optional arguments:", "options:").rstrip("\n")

def rhsa_page():
    """The manual page of the Red Hat advisory finder and checker, from the tool's own --help."""
    top = rhsa_help("--help")
    names = re.search(r"\{([a-z,]+)\}", top).group(1).split(",")
    short, cur = {}, None
    for l in top.split("\n"):
        m = re.match(r"^\s{4}([a-z]+)\s{2,}(\S.*)$", l)
        if m and m.group(1) in names: cur = m.group(1); short[cur] = m.group(2).strip()
        elif cur and re.match(r"^\s{12,}\S", l): short[cur] += " " + l.strip()
        else: cur = None
    title = "find Red Hat security advisories and check installed packages against them"
    full = RHSA_DIR + "/rhsa.py"
    o = [f'.TH PSF\\-RHSA 8 "{DATE}" "psf-security-patches {RELEASE}" "System Administration"', ".nh", ".ad l",
         ".SH NAME", f"psf\\-rhsa \\- {esc(title)}",
         ".SH SYNOPSIS", "\\fB" + esc(full).replace("/", "/\\:") + "\\fR \\fICOMMAND\\fR [\\fIOPTIONS\\fR]",
         ".SH DESCRIPTION",
         ".PP", esc("Red Hat publishes a security advisory (RHSA) for each fix it ships. This tool reads Red Hat's list of them and answers two questions: which advisories name a CVE, and which package release fixes it; and whether a package installed on this host is at or after that release. It is meant for Red Hat family hosts (RHEL, AlmaLinux, Rocky Linux, Oracle Linux, CentOS Stream) and works from files: the index that comes with the package, or a list downloaded with fetch. Only fetch and find --live use the network."),
         ".PP", esc("A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The list holds security advisories only, not bug fixes or enhancements."),
         ".SH COMMANDS"]
    for c in names:
        h = rhsa_help(c, "--help").split("\n\n")
        o += [".TP", "\\fB" + esc(c) + "\\fR", esc(short.get(c, ""))]
        for blk in h[1:]:
            if blk.startswith(("positional arguments:", "options:")):
                o += [".RS 2", ".nf"] + [esc(l) for l in blk.split("\n")] + [".fi", ".RE"]
            else:
                o += [".PP", ".RS 2", esc(" ".join(blk.split())), ".RE"]
    o += [".SH HOW VERIFY DECIDES",
          ".PP", esc("verify compares releases the way rpm does (rpmvercmp, with the epoch, ~ and ^), and only under these rules."),
          ".IP 1. 3", esc("Same stream. The stream is read from the release: el9_6 is RHEL 9.6, hum1 is a Hummingbird build. A package on a stream with no advisory is reported as such, never compared across streams."),
          ".IP 2. 3", esc("Same product release. OpenShift builds name theirs (rhaos4.18, rhaos4.21); those are different products."),
          ".IP 3. 3", esc("Same version line. PHP 8.0, 8.2 and 8.3 sit side by side in one RHEL stream as modules, so a fix for 8.0 says nothing about 8.2. Only another line having an advisory gives \"check by hand\"."),
          ".IP 4. 3", esc("No bundles. An advisory that lists more than 8 source packages does not say which package fixes which CVE, so it is never used to pair a package with a fix (--max-packages changes the limit)."),
          ".IP 5. 3", esc("The earliest fixed release counts, when several advisories name a CVE for a package in one stream."),
          ".PP", esc("A verdict is a fact about the release. Whether the flaw can be reached on this host is another question."),
          ".SH EXAMPLES",
          ".TP", "Check every installed package against the shipped index:", ".B " + esc(full).replace("/", "/\\:") + " verify \\-\\-rpm",
          ".TP", "Which advisories fix the kernel flaw CVE\\-2026\\-98432 on RHEL 9.6:", ".B " + esc(full).replace("/", "/\\:") + " find CVE\\-2026\\-98432 \\-\\-stream 9.6",
          ".TP", "Check against Red Hat's current list instead of the shipped index:", ".B " + esc(full).replace("/", "/\\:") + " fetch \\-\\-after 2026\\-04\\-01 \\-\\-out /var/tmp/rhsa.json",
          ".br", ".B " + esc(full).replace("/", "/\\:") + " verify \\-\\-rpm \\-\\-list /var/tmp/rhsa.json",
          ".SH EXIT STATUS",
          ".TP", "\\fB0\\fR", "No package is older than a Red Hat fix, or find found an advisory.",
          ".TP", "\\fB1\\fR", "verify found a package older than a fix, or find found nothing.",
          ".TP", "\\fB2\\fR", "A usage error, or a list or index that cannot be read.",
          ".SH FILES",
          ".TP", "\\fB" + esc(full).replace("/", "/\\:") + "\\fR", "The tool. It needs Python 3.8 or newer and nothing else.",
          ".TP", "\\fB" + esc(RHSA_DIR + "/data/rhsa-index.json").replace("/", "/\\:") + "\\fR", "The index: the advisories for the CVEs the READMEs name, from Red Hat's list for 2026\\-04\\-01 to 2026\\-11\\-03.",
          ".TP", "\\fB" + esc(RHSA_DIR + "/placement.json").replace("/", "/\\:") + "\\fR", "Which advisories go in which README. Used by index and docs.",
          ".SH SEE ALSO", "psf\\-security\\-patches(7)",
          ".PP", esc(URL), ".br", "Documentation: https://privacysafe.app/docs/security-patches/", ".br", "PrivacySafe: https://privacysafe.app",
          ".SH AUTHORS", esc(AUTHORS)]
    tr = trailer(RHSA)
    if tr:
        o += [".PP", esc("AI assistance in this tool: " + ", ".join(tr) + " (the Assisted-by line in the script header).")]
    o += [".SH COPYRIGHT", esc(COPYRIGHT), ".PP", "If this software is helpful, please consider supporting PrivacySafe Foundation: https://privacysafe.foundation"]
    plain = top + "\n\n" + "\n\n".join(rhsa_help(c, "--help") for c in names)
    return "psf-rhsa", title, "\n".join(left_adjust(o)) + "\n", plain


def overview(pages):
    o = []
    o.append(f'.TH PSF\\-SECURITY\\-PATCHES 7 "{DATE}" "psf-security-patches {RELEASE}" "Miscellaneous"')
    o.append(".nh"); o.append(".ad l")
    o.append(".SH NAME"); o.append("psf\\-security\\-patches \\- security checks, hunts and protection for serious vulnerabilities")
    o.append(".SH DESCRIPTION")
    o.append(".PP"); o.append("Free security tools for GNU/Linux servers, written by PrivacySafe Foundation with the help of Ivy Cyber and released into the public domain. The collection is focused on GNU/Linux; in rare cases, such as the Claude Code extension, a macOS or Windows script is provided as well. When a serious vulnerability is announced, each tool tells you whether your machine is exposed and looks for signs that someone has already used the flaw. Where there is a safe way to do it, the tool also protects the machine until you can update. Everything is plain bash (the one Windows script is PowerShell).")
    o.append(".SH GETTING STARTED")
    o.append(".IP 1. 3"); o.append("Run the tool's \\fBcheck\\fR. It changes nothing.")
    o.append(".IP 2. 3"); o.append("If you are exposed, install the vendor's update. That is the permanent fix.")
    o.append(".IP 3. 3"); o.append("If you cannot update yet, run \\fBmitigate \\-\\-dry\\-run\\fR to see what the protection would do, then \\fBmitigate\\fR. \\fBrollback\\fR undoes it.")
    o.append(".IP 4. 3"); o.append("If the flaw was being exploited, run \\fBhunt\\fR, then change any password, key or token an attacker could have reached.")
    o.append(".SH NEWEST: 22 TO 30 OCTOBER 2026")
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
    o.append(".TP"); o.append("\\fB/usr/share/doc/psf\\-security\\-patches/\\fR"); o.append("README, change log, license and notice. On RPM systems the folder is psf\\-security\\-patches\\-VERSION.")
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
    o.append("Free security tools for GNU/Linux servers, written by PrivacySafe Foundation with the help of Ivy Cyber and released into the public domain. The collection is focused on GNU/Linux; in rare cases, such as the Claude Code extension, a macOS or Windows script is provided as well.")
    o.append("@insertcopying"); o.append("@end ifnottex")
    o.append("@menu"); o.append("* Start here::"); o.append("* Newest::"); o.append("* Tools::"); o.append("* Files and environment::"); o.append("* Credits and license::"); o.append("@end menu")
    o.append("@node Start here"); o.append("@chapter Start here"); o.append("@enumerate")
    o.append("@item"); o.append("Run the tool's @code{check}. It changes nothing.")
    o.append("@item"); o.append("If you are exposed, install the vendor's update. That is the permanent fix.")
    o.append("@item"); o.append("If you cannot update yet, run @code{mitigate --dry-run} to see what the protection would do, then @code{mitigate}. @code{rollback} undoes it.")
    o.append("@item"); o.append("If the flaw was being exploited, run @code{hunt}, then change any password, key or token an attacker could have reached.")
    o.append("@end enumerate")
    o.append("@node Newest"); o.append("@chapter Newest: 22 October to 2 November 2026"); o.append("@table @asis")
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
    o.append("@item /usr/share/doc/psf-security-patches/"); o.append("README, change log, license and notice. On RPM systems the folder is psf-security-patches-VERSION."); o.append("@end table")
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
os.makedirs(os.path.join(OUT, "man8"), exist_ok=True)
os.makedirs(os.path.join(OUT, "man7"), exist_ok=True)
pages = []; texts = {}
for p in ALL:
    n, t, body = man_page(p)
    open(os.path.join(OUT, "man8", n + ".8"), "w").write(body)
    pages.append((n, p, t)); texts[p] = helptext(p)
if os.path.exists(RHSA):
    n, t, body, plain = rhsa_page()
    open(os.path.join(OUT, "man8", n + ".8"), "w").write(body)
    pages.append((n, "rhsa/rhsa.py", t)); texts["rhsa/rhsa.py"] = plain
pages.sort()
open(os.path.join(OUT, "man7", "psf-security-patches.7"), "w").write(overview(pages))
open(os.path.join(OUT, "psf-security-patches.texi"), "w").write(texi(pages, texts))
import shutil
if shutil.which("makeinfo"):
    r = subprocess.run(["makeinfo", "--no-split", "-o", os.path.join(OUT, "psf-security-patches.info"), os.path.join(OUT, "psf-security-patches.texi")], capture_output=True, text=True)
    if r.returncode: sys.exit("makeinfo failed:\n" + r.stderr[:600])
    print(f"wrote {len(pages)} manual pages, the overview page, the Texinfo manual and the info file")
else:
    print(f"wrote {len(pages)} manual pages, the overview page and the Texinfo manual; makeinfo is not installed, so there is no info file")
