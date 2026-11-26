#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: psf-report turns the JSON Lines the scripts write into reports.
# Donate: https://privacysafe.foundation/donate
#
# Usage:
#   psf-report.py [options] [FILE|FOLDER ...]      read JSON Lines (stdin when no file is given)
#
#   --format summary|text|md|html|pdf|jsonl|ecs   summary (default): a few lines for a terminal or a mail;
#                       text: the whole report as plain text; md: a Markdown report; html: one
#                       self-contained page; pdf: a printable report; jsonl: the records, merged and
#                       checked; ecs: the records with Elastic Common Schema field names, for a log
#                       platform. Every format needs Python 3 alone and loads nothing from the network
#   --out FILE          write the report here instead of standard output (a PDF is never written to a
#                       terminal)
#   --title TEXT        the report's title (default: Security check report)
#   --paper letter|a4   the PDF page size (default: letter)
#   --no-details        leave out passes and notes: only what needs attention and the run table
#   --fail-on crit|warn exit 1 when a run found something at this level or above (for CI and cron)
#   --accept FILE       a list of accepted risks (ignore: cves: with a reason, exclude: paths:): matching findings
#                       are shown as accepted with their reason, still listed, and not counted
#   -h, --help          this help
#   -V, --version       the version
#
# Input is what a script writes with --output jsonl, from one run or many, one host or many: files,
# folders (every *.jsonl in them) or standard input, in any mix. A line that is not a record is
# counted and skipped, never fatal. Exit 0 = report written, 1 = --fail-on matched, 2 = no records or
# a usage error. Nothing is read from the network and no program is run. With SOURCE_DATE_EPOCH set (seconds since
# 1970, as in reproducible builds) the report gives that time as the time it was made, so the same records always
# give the same report, byte for byte.
import datetime
import html
import json
import os
import re
import stat
import sys
import tempfile
import zlib

NAME, VERSION, DATE = "psf-report.py", "1.0.0", "2026-11-25"
LEVELS = ("crit", "warn", "error", "ok", "info")
RANK = {"crit": 0, "error": 1, "warn": 2, "info": 3, "ok": 4}
KIND_RANK = {"compromise": 0, "indicator": 1, "vulnerability": 2, "exposure": 3, "config": 4}
LABEL = {"crit": "CRIT", "warn": "WARN", "error": "ERROR", "ok": "OK", "info": "INFO"}
BRAND_NAME = "PrivacySafe Security Patches"
SITE_URL = "https://privacysafe.app/docs/security-patches/"
HOME_URL = "https://privacysafe.app"
CONTACT = "security@privacysafe.net"
CONTACT_GPG = "7E3E C7D6 D965 CF1D 8C76 8F80 74AB DBE3 E3FB C689"
CONTACT_LINE = "Report security issues in these tools to %s (GPG %s)." % (CONTACT, CONTACT_GPG)
HELP = "help@privacysafe.net"
HELP_GPG = "7702 BD22 435B 5F3E B00C 1E78 21FB 9DF4 D742 422D"
MAX_LINE = 1000000      # a record line longer than this is skipped
MAX_MSG = 4000          # a message longer than this is shortened in reports (the jsonl format keeps it whole)
MAX_FILE = 256 * 1024 * 1024   # a records file larger than this is skipped, so a planted file cannot exhaust memory


CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clip(s):
    """Record text made safe to show: no control characters (a terminal would act on them), and not too long."""
    s = CONTROL.sub("?", str(s)).replace("\n", " ").replace("\t", " ")
    return s if len(s) <= MAX_MSG else s[:MAX_MSG] + " [shortened: %d characters]" % len(s)
STANDARDS_NOTE = ("The records follow, closely rather than exactly, the joint guide Best Practices for Event Logging and "
                  "Threat Detection (ASD's ACSC, CISA and international partners, 2024), the NIST SP 800-53 Rev. 5 "
                  "Audit and Accountability (AU) controls and OMB Memorandum M-26-14.")
CAUTION = "A finding is what the tool read on the host; confirm before acting on it."
STATUS_TEXT = {
    "compromise": "Signs of compromise",
    "action": "Action needed",
    "review": "Review",
    "incomplete": "Incomplete",
    "clean": "Clean",
    "empty": "No checks ran",
}


# ---------- reading ----------------------------------------------------------------------------
def read_inputs(paths):
    """Records grouped by run, in the order they arrive, and the number of lines skipped."""
    runs, order, skipped = {}, [], 0

    def take(text):
        nonlocal skipped
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if len(line) > MAX_LINE:
                skipped += 1
                continue
            try:
                r = json.loads(line)
                if not isinstance(r, dict) or r.get("schema") != 1 or "type" not in r:
                    raise ValueError
            except ValueError:
                skipped += 1
                continue
            key = r.get("run") or "%s/%s" % (r.get("host", "?"), r.get("tool", "?"))
            if key not in runs:
                runs[key] = []
                order.append(key)
            runs[key].append(r)

    if not paths:
        t = read_capped(sys.stdin.buffer, "standard input")
        if t is not None:
            take(t)
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                fp = os.path.join(p, f)
                if not f.endswith(".jsonl"):
                    continue
                st = os.lstat(fp)
                if stat.S_ISLNK(st.st_mode):        # a link in a log folder is not something a run writes
                    print("%s: skipped %s: a symbolic link" % (NAME, fp), file=sys.stderr)
                    continue
                if stat.S_ISREG(st.st_mode):
                    t = read_records_file(fp)
                    if t is not None:
                        take(t)
        else:
            t = read_records_file(p)
            if t is not None:
                take(t)
    return [summarize(runs[k]) for k in order], skipped


def parse_time(v):
    """A time as an aware UTC datetime, read leniently, so records from any release or any pipeline work: an RFC 3339 or
    ISO 8601 string (Z or an offset such as +00:00 or +0200, any number of fraction digits, T or a space between date
    and time; no zone means UTC), or a number of seconds or milliseconds since 1970. None when it cannot be read."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        x = float(v) / 1000 if abs(float(v)) > 1e11 else float(v)       # 1e11 seconds is the year 5138: so milliseconds
        try:
            return datetime.datetime.fromtimestamp(x, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(v, str):
        return None
    m = re.match(r"^\s*(\d{4}-\d\d-\d\d)[Tt ](\d\d:\d\d:\d\d)(?:[.,](\d+))?\s*(Z|z|[+-]\d\d:?\d\d)?\s*$", v)
    if not m:
        return None
    frac = "." + (m.group(3) or "")[:6].ljust(6, "0")
    off = m.group(4) or "+00:00"
    off = "+00:00" if off in ("Z", "z") else (off if ":" in off else off[:3] + ":" + off[3:])
    try:
        return datetime.datetime.fromisoformat(m.group(1) + "T" + m.group(2) + frac + off).astimezone(datetime.timezone.utc)
    except ValueError:
        return None


def record_time(r):
    """The most precise time a record carries: ts_epoch_ms, then ts_ms, then ts."""
    for k in ("ts_epoch_ms", "ts_ms", "ts"):
        t = parse_time(r.get(k))
        if t:
            return t
    return None


def latest_runs(runs):
    """The newest run of each tool command on each host: a rerun after a fix replaces the earlier result.
    The earlier runs stay in the records; they are history, not the current state."""
    newest = {}
    for r in runs:
        k = (r["host"], r["tool"], r["command"])
        if k not in newest or _start_key(r) >= _start_key(newest[k]):
            newest[k] = r
    return [r for r in runs if newest[(r["host"], r["tool"], r["command"])] is r]


def _start_key(run):
    """Order runs by when they started, to the millisecond where the records say so; a run with no readable time sorts first."""
    t = run.get("started_dt")
    return (1, t) if t else (0, run.get("started") or "")


# ---------- accepted risks -----------------------------------------------------------------------
# A reviewable list of findings a team has decided to accept, in a small YAML shape:
#   ignore:
#     cves:
#       CVE-2026-12345:
#         reason: Not reachable here; the module is disabled
#   exclude:
#     paths:
#       - /srv/legacy-app
# A critical finding or warning whose CVEs are all on the list, or whose path contains one of the paths
# (plain substring matching, no wildcards), is shown as accepted with its reason: still listed, never hidden,
# but not counted as needing attention and never the cause of an alert. A finding of kind compromise
# (signs of an attack) is never accepted. Other top-level sections in the file are not read.
ACCEPT = {"cves": {}, "paths": [], "source": ""}


def _yaml_scalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return re.sub(r"\s+#.*$", "", v).strip()


def load_accepted(path):
    """Read an accepted-risk file into ACCEPT. Raises ConfigError when it cannot be used."""
    if not os.path.lexists(path):
        raise ConfigError("%s: no such file" % path)
    if os.geteuid() == 0:
        why = untrusted_as_root([path])
        if why:
            raise ConfigError("%s cannot be used as root: %s. Whoever can change it decides which findings stop raising alerts." % (path, why))
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4 * 1024 * 1024:
            raise ConfigError("%s: not a regular file of a sensible size" % path)
        lines = open(path, encoding="utf-8").read().split("\n")
    except OSError as e:
        raise ConfigError("%s: %s" % (path, e.strerror))
    cves, paths, top, sub, cur = {}, [], None, None, None
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        ind = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if ind == 0:
            top, sub, cur = line.rstrip(":").strip(), None, None
            continue
        if top == "ignore":
            if line.endswith(":") and line[:-1].strip() == "cves":
                sub = "cves"; continue
            if sub == "cves":
                m = re.match(r"^[\"']?(CVE-\d{4}-\d{4,7})[\"']?\s*:\s*(.*)$", line)
                if m:
                    cur = m.group(1)
                    cves[cur] = _yaml_scalar(m.group(2)) if m.group(2).strip() else ""
                    continue
                m = re.match(r"^reason\s*:\s*(.*)$", line)
                if m and cur:
                    cves[cur] = _yaml_scalar(m.group(1))
        elif top == "exclude":
            if line.endswith(":") and line[:-1].strip() == "paths":
                sub = "paths"; continue
            if sub == "paths" and line.startswith("- "):
                p = _yaml_scalar(line[2:])
                if p:
                    paths.append(p)
    ACCEPT["cves"] = {c: (r or "no reason given") for c, r in cves.items()}
    ACCEPT["paths"] = paths
    ACCEPT["source"] = path
    return ACCEPT


def accepted_reason(r):
    """Why this finding is accepted, or None."""
    if r.get("type") != "event" or r.get("level") not in ("crit", "warn") or r.get("kind") == "compromise":
        return None
    cves = r.get("cve") or []
    if cves and all(c in ACCEPT["cves"] for c in cves):
        return "; ".join(dict.fromkeys(ACCEPT["cves"][c] for c in cves))
    p = r.get("path") or ""
    for x in ACCEPT["paths"]:
        if p and x in p:
            return "path excluded (%s)" % x
    return None


def accepted_items(runs):
    """Every accepted finding, with its run."""
    return [(run, r) for run in runs for r in run["events"] if r.get("accepted")]


def summarize(recs):
    """One run: its identity, verdict, events in order, and what needs attention."""
    first = recs[0]
    start = next((r for r in recs if r["type"] == "start"), {})
    verdict = next((r for r in recs if r["type"] == "verdict"), None)
    events = [r for r in recs if r["type"] in ("event", "section", "text", "applicable")]
    counts = {k: 0 for k in LEVELS}
    counts["accepted"] = 0
    for r in recs:
        if r["type"] == "event" and r.get("level") in counts:
            why = accepted_reason(r)
            if why:
                r["accepted"] = why
                counts["accepted"] += 1
            else:
                r.pop("accepted", None)
                counts[r["level"]] += 1
    applicable = verdict.get("applicable") if verdict else None
    if any(r["type"] == "applicable" for r in recs):
        applicable = False
    return {
        "run": first.get("run", ""),
        "host": first.get("host", "?"),
        "tool": first.get("tool", "?"),
        "version": first.get("version", ""),
        "command": first.get("command", "") or "",
        "started": start.get("ts", first.get("ts", "")),
        "started_dt": record_time(start) or record_time(first),
        "euid": start.get("euid"),
        "read_only": start.get("read_only"),
        # a run whose every critical finding and warning is accepted is "accepted", not "findings"
        "result": ("accepted" if verdict and verdict.get("result") == "findings" and counts["accepted"]
                   and not counts["crit"] and not counts["warn"] else verdict.get("result") if verdict else "incomplete"),
        "exit": verdict.get("exit") if verdict else None,
        "duration": verdict.get("duration_s") if verdict else None,
        "applicable": applicable,
        "counts": counts,
        "events": events,
        "records": recs,
    }


def attention(runs):
    """Every warning, critical finding and error, the most serious first."""
    out = []
    for run in runs:
        for r in run["events"]:
            if r["type"] == "event" and r.get("level") in ("crit", "warn", "error") and not r.get("accepted"):
                out.append((run, r))
    out.sort(key=lambda x: (x[1].get("kind") != "compromise", RANK.get(x[1].get("level"), 9),
                            KIND_RANK.get(x[1].get("kind", ""), 5), x[0]["host"], x[0]["tool"]))
    return out


def overall(runs):
    if not runs:
        return "empty"
    items = attention(runs)
    if any(r.get("kind") == "compromise" for _, r in items):
        return "compromise"
    if any(r.get("level") == "crit" for _, r in items):
        return "action"
    if any(r.get("level") == "warn" for _, r in items) or any(x["result"] == "findings" for x in runs):
        return "review"
    if any(x["result"] in ("undecided", "incomplete") for x in runs):
        return "incomplete"
    return "clean"


def cve_index(runs):
    idx = {}
    for run, r in attention(runs):
        for c in r.get("cve") or []:
            idx.setdefault(c, set()).add("%s on %s" % (run["tool"], run["host"]))
    return dict(sorted(idx.items(), key=lambda kv: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", kv[0])]))


# ---- root safety: the same lines in psf-report.py, psf-status.py and psf-logs.py (out_test compares them) ----
def untrusted_as_root(paths):
    """Run as root, the code that runs must be root's: each file, and every folder above it, owned by root and
    writable by no other account (a sticky folder such as /tmp excepted). None, or why not."""
    if os.geteuid() != 0:
        return None
    for p in paths:
        p = cur = os.path.realpath(p)
        while True:
            try:
                st = os.stat(cur)
            except OSError as e:
                return "%s: %s" % (cur, e.strerror)
            if st.st_uid != 0:
                return "%s belongs to uid %d" % (cur, st.st_uid)
            if st.st_mode & 0o022 and not (cur != p and st.st_mode & stat.S_ISVTX):
                return "%s can be written by other accounts (mode %o)" % (cur, stat.S_IMODE(st.st_mode))
            if cur == "/":
                break
            cur = os.path.dirname(cur)
    return None


def refuse_untrusted_root(paths):
    why = untrusted_as_root(paths)
    if why:
        print("refusing to run as root: %s. Whoever can change that file would control a run as root: install the "
              "package (its files are root's), or run this as the account that owns the files." % why, file=sys.stderr)
        sys.exit(2)


def root_note(why):
    """At a terminal, a run as root says why root is used and what is done with it; never in cron or a pipe."""
    if os.geteuid() != 0 or os.environ.get("PSF_NO_ROOT_NOTE") or not sys.stderr.isatty():
        return
    print("[!] Running as root: %s (PSF_NO_ROOT_NOTE=1 hides this note)." % why, file=sys.stderr)
    try:
        login = os.getlogin()
    except OSError:
        login = ""
    if not os.environ.get("SUDO_USER") and login == "root" and not os.path.exists("/.dockerenv") and any(
            os.access(os.path.join(d, "sudo"), os.X_OK) for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")):
        print("[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made "
              "the change (PSF_NO_ROOT_NOTE=1 hides this note).", file=sys.stderr)
# ---- end of root safety ----


def read_capped(f, name):
    """At most MAX_FILE bytes as text; None, with a warning, when there is more."""
    data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        print("%s: skipped %s, larger than %d MB" % (NAME, name, MAX_FILE // (1024 * 1024)), file=sys.stderr)
        return None
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def read_records_file(path):
    """A records file's text, read only if it is a regular file (a device or a pipe could block or never end).
    A file that does not exist or cannot be read raises OSError, as open() would."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        print("%s: skipped %s: not a regular file" % (NAME, path), file=sys.stderr)
        return None
    if st.st_size > MAX_FILE:                   # known before reading a byte
        print("%s: skipped %s, larger than %d MB" % (NAME, path, MAX_FILE // (1024 * 1024)), file=sys.stderr)
        return None
    with open(path, "rb") as f:
        return read_capped(f, path)


def write_private(out, data):
    """Write the report through a new file of an unguessable name in the same folder, made only for this write
    (O_EXCL: never an existing file or a link) and readable by its owner only, then renamed over out (a rename
    replaces a link at out, it does not follow it)."""
    d = os.path.dirname(os.path.abspath(out))
    fd, tmp = tempfile.mkstemp(prefix=".psf-report.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------- configuration (/etc/psf-security-patches/psf.conf), read by psf-run, psf-status and psf-logs ----------
CONFIG_PATH = "/etc/psf-security-patches/psf.conf"
CONFIG_DEFAULTS = {"LOG_DIR": "/var/log/psf-security-patches", "KEEP_DAYS": "90", "FORMATS": "summary text pdf",
                   "TOOLS": "auto", "ALERT_ON": "crit", "ALERT_COMMAND": "", "TIMEOUT": "900", "ENV": "", "ACCEPT_FILE": ""}
REPORT_FORMATS = {"summary": "summary.txt", "text": "report.txt", "md": "report.md", "html": "report.html", "pdf": "report.pdf",
                  "ecs": "records.ecs.ndjson"}
ECS_VERSION = "8.11.0"


def render_ecs(runs):
    """The records with Elastic Common Schema field names, one JSON document per line. The mapping is the one the
    automation guide gives (ts @timestamp, host host.name, tool event.provider, command event.action, code event.code,
    seq event.sequence, level log.level, msg message, cve vulnerability.id, path file.path), plus fix as
    event.reference and run and seq as event.id; every field ECS has no place for is kept under psf."""
    mapped = {"ts", "ts_ms", "ts_epoch_ms", "host", "tool", "command", "code", "seq", "level", "msg", "cve", "path", "fix"}
    out = []
    for run in runs:
        for r in run["records"]:
            doc = {"@timestamp": r.get("ts_ms") or r.get("ts", ""), "ecs": {"version": ECS_VERSION}, "message": r.get("msg", ""),
                   "host": {"name": r.get("host", "")},
                   "event": {"provider": r.get("tool", ""), "action": r.get("command", ""), "kind": "event",
                             "module": "psf_security_patches", "dataset": "psf_security_patches." + str(r.get("type", ""))}}
            if r.get("seq") is not None:
                doc["event"]["sequence"] = r["seq"]
                doc["event"]["id"] = "%s-%s" % (r.get("run", ""), r["seq"])
            if r.get("code"):
                doc["event"]["code"] = r["code"]
            if str(r.get("fix", "")).startswith(("https://", "http://")):
                doc["event"]["reference"] = r["fix"]
            if r.get("level"):
                doc["log"] = {"level": r["level"]}
            if r.get("cve"):
                doc["vulnerability"] = {"id": list(r["cve"])}
            if r.get("path"):
                doc["file"] = {"path": r["path"]}
            rest = {k: v for k, v in r.items() if k not in mapped}
            if rest:
                doc["psf"] = rest
            out.append(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
    return ("\n".join(out) + "\n").encode("utf-8")
FORBIDDEN_ENV = re.compile(r"^(PATH|IFS|ENV|BASH_ENV|BASH_FUNC_.*|LD_.*|PYTHON.*|PERL.*|RUBY.*|NODE_.*|SHELLOPTS|"
                           r"PS4|HOME|TMPDIR|PSF_READ_ONLY|PSF_OUTPUT|PSF_CONFIG|PSF_LOG_DIR)$")


class ConfigError(Exception):
    pass


def config_path():
    return os.environ.get("PSF_CONFIG") or CONFIG_PATH


def load_config(path=None):
    """(settings, sources): every setting validated, with where each value came from. The file is read, never run.
    As root it must be root's and writable by no other account, like code, because it decides what runs."""
    path = path or config_path()
    conf = dict(CONFIG_DEFAULTS)
    src = {k: "default" for k in conf}
    if os.path.exists(path):
        why = untrusted_as_root([path])
        if why:
            raise ConfigError("%s cannot be used as root: %s. Whoever can change it decides what runs as root." % (path, why))
        seen = set()
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Z_]+)\s*=\s*(.*)$", line)
                if not m:
                    raise ConfigError("%s line %d: expected NAME = value" % (path, n))
                k, v = m.group(1), m.group(2).strip()
                if k not in CONFIG_DEFAULTS:
                    raise ConfigError("%s line %d: unknown setting %s (known: %s)" % (path, n, k, ", ".join(CONFIG_DEFAULTS)))
                if k in seen:
                    raise ConfigError("%s line %d: %s is set twice" % (path, n, k))
                seen.add(k)
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                conf[k], src[k] = v, "%s line %d" % (path, n)
    if os.environ.get("PSF_LOG_DIR"):
        conf["LOG_DIR"], src["LOG_DIR"] = os.environ["PSF_LOG_DIR"], "PSF_LOG_DIR"
    check_config(conf)
    return conf, src


def check_config(c):
    if not c["LOG_DIR"].startswith("/") or "\n" in c["LOG_DIR"]:
        raise ConfigError("LOG_DIR must be an absolute path: %r" % c["LOG_DIR"])
    if not c["KEEP_DAYS"].isdigit() or int(c["KEEP_DAYS"]) < 1:
        raise ConfigError("KEEP_DAYS must be a whole number of days, 1 or more: %r" % c["KEEP_DAYS"])
    fm = c["FORMATS"].replace(",", " ").split()
    bad = [x for x in fm if x not in REPORT_FORMATS]
    if bad:
        raise ConfigError("FORMATS: unknown %s (choose from %s; the .jsonl records are always kept)" % (", ".join(bad), ", ".join(REPORT_FORMATS)))
    if c["ALERT_ON"] not in ("crit", "warn", "never"):
        raise ConfigError("ALERT_ON must be crit, warn or never: %r" % c["ALERT_ON"])
    if not c["TIMEOUT"].isdigit() or not 10 <= int(c["TIMEOUT"]) <= 86400:
        raise ConfigError("TIMEOUT must be seconds, 10 to 86400: %r" % c["TIMEOUT"])
    if c["ACCEPT_FILE"] and (not c["ACCEPT_FILE"].startswith("/") or "\n" in c["ACCEPT_FILE"]):
        raise ConfigError("ACCEPT_FILE must be an absolute path: %r" % c["ACCEPT_FILE"])
    for item in c["ENV"].split():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", item)
        if not m:
            raise ConfigError("ENV: expected NAME=value items: %r" % item)
        if FORBIDDEN_ENV.match(m.group(1)):
            raise ConfigError("ENV: %s cannot be set here" % m.group(1))
    if c["TOOLS"] != "auto":
        for t in c["TOOLS"].replace(",", " ").split():
            path, _, cmd = t.partition(":")
            if path.startswith("/") or ".." in path.split("/") or not path.endswith(".sh") or (cmd and not re.match(r"^[a-z][a-z-]*$", cmd)):
                raise ConfigError("TOOLS: %r is not FOLDER/TOOL.sh[:command] inside the collection" % t)


def report_time():
    """The time the report says it was made: SOURCE_DATE_EPOCH when set (reproducible reports), else now."""
    sde = os.environ.get("SOURCE_DATE_EPOCH", "")
    if sde.isdigit():
        return datetime.datetime.fromtimestamp(int(sde), datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc)


def now_utc():
    return report_time().strftime("%Y-%m-%d %H:%M UTC")


def applic(run):
    return {True: "yes", False: "no", None: "unknown"}[run["applicable"]]


# ---------- summary ----------------------------------------------------------------------------
def render_summary(runs, title, details):
    st = overall(runs)
    hosts = sorted({r["host"] for r in runs})
    lines = ["%s: %s" % (clip(title), STATUS_TEXT[st]),
             "%d run(s) on %d host(s) (%s); generated %s" % (len(runs), len(hosts), clip(", ".join(hosts)), now_utc())]
    hw = min(max(len(r["host"]) for r in runs), 24)
    for run in runs:
        c = run["counts"]
        lines.append("  %-*s %-26s %-6s %-10s crit %d  warn %d%s" % (
            hw, clip(run["host"])[:hw], clip(run["tool"] + " " + run["version"])[:26], clip(run["command"])[:6], clip(run["result"]),
            c["crit"], c["warn"], "  (nothing to check here)" if run["applicable"] is False else ""))
    items = attention(runs)
    if items:
        lines.append("Needs attention:")
        for run, r in items:
            k = (" [%s]" % r["kind"]) if r.get("kind") else ""
            lines.append("  %s%s %s/%s: %s" % (LABEL[r["level"]], clip(k), clip(run["host"]), clip(run["tool"]), clip(r["msg"])))
    acc = accepted_items(runs)
    if acc:
        lines.append("Accepted (%d, from %s), not counted:" % (len(acc), clip(ACCEPT["source"])))
        for run, r in acc:
            lines.append("  %s/%s: %s (accepted: %s)" % (clip(run["host"]), clip(run["tool"]), clip(r["msg"])[:120], clip(r["accepted"])))
    lines.append("%s | %s | help: %s | security issues: %s" % (BRAND_NAME, SITE_URL, HELP, CONTACT))
    return "\n".join(lines) + "\n"


# ---------- plain text -------------------------------------------------------------------------
def render_text(runs, title, details):
    """The whole report as plain text: for a log folder, a mail, less or grep. No markup, no control characters."""
    import textwrap
    W = 100
    st = overall(runs)
    hosts = sorted({r["host"] for r in runs})

    def para(text, indent=""):
        return textwrap.fill(clip(text), W, initial_indent=indent, subsequent_indent=indent, break_on_hyphens=False,
                             break_long_words=True) or indent

    out = [clip(title).upper(), "=" * min(W, len(title)), "",
           "Status: %s" % STATUS_TEXT[st],
           para("%d run(s) on %d host(s): %s. Generated %s by %s %s." % (len(runs), len(hosts), ", ".join(hosts), now_utc(), NAME, VERSION)),
           "", "RUNS", "----"]
    rows = [("Host", "Tool", "Command", "Result", "Crit", "Warn", "Applies", "Time")]
    for r in runs:
        rows.append((clip(r["host"]), clip(r["tool"] + " " + r["version"]), clip(r["command"] or "-"), clip(r["result"]),
                     str(r["counts"]["crit"]), str(r["counts"]["warn"]), applic(r), "%ss" % r["duration"] if r["duration"] is not None else "-"))
    wid = [min(max(len(row[i]) for row in rows), 28) for i in range(8)]
    for row in rows:
        cells = [c[:wid[i]].rjust(wid[i]) if i in (4, 5, 7) else c[:wid[i]].ljust(wid[i]) for i, c in enumerate(row)]
        out.append("  ".join(cells).rstrip())
    out += ["", "NEEDS ATTENTION", "---------------"]
    items = attention(runs)
    if not items:
        out.append("Nothing. No run reported a warning, a critical finding or an error.")
    for run, r in items:
        out.append("[%s]%s %s, %s %s" % (LABEL[r["level"]], (" (%s)" % clip(r["kind"])) if r.get("kind") else "",
                                         clip(run["host"]), clip(run["tool"]), clip(run["command"])))
        out.append(para(r["msg"], "    "))
        extra = []
        if r.get("cve"):
            extra.append("CVE: " + ", ".join(clip(c) for c in r["cve"]))
        if r.get("code"):
            extra.append("code " + clip(r["code"]))
        if r.get("path"):
            extra.append("path " + clip(r["path"]))
        if extra:
            out.append(para("; ".join(extra), "    "))
        if str(r.get("fix", "")).startswith(("https://", "http://")):
            out.append("    What to do: " + clip(r["fix"]))
        out.append("")
    acc = accepted_items(runs)
    if acc:
        out += ["ACCEPTED RISKS (%d, from %s)" % (len(acc), clip(ACCEPT["source"])), "-" * 24]
        for run, r in acc:
            out.append("[accepted] %s, %s %s: %s" % (clip(run["host"]), clip(run["tool"]), clip(run["command"]), clip(r["msg"])))
            out.append(para("Reason: " + r["accepted"] + (("; CVE: " + ", ".join(clip(c) for c in r["cve"])) if r.get("cve") else ""), "    "))
        out.append("")
    idx = cve_index(runs)
    if idx:
        out += ["CVES BEHIND THE FINDINGS", "------------------------"]
        for c, where in idx.items():
            out.append(para("%s: %s" % (c, ", ".join(sorted(where)))))
        out.append("")
    if details:
        out += ["DETAILS", "-------"]
        for run in runs:
            out.append("%s %s %s on %s: %s (exit %s)%s" % (clip(run["tool"]), clip(run["version"]), clip(run["command"]), clip(run["host"]),
                                                          clip(run["result"]), run["exit"],
                                                          "; nothing to check on this host" if run["applicable"] is False else ""))
            for r in run["events"]:
                if r["type"] == "section":
                    out.append("  " + clip(r["msg"]))
                elif r["type"] == "event":
                    out.append(para("%-5s %s" % (LABEL.get(r.get("level"), "INFO"), r["msg"]), "    "))
                elif r["type"] == "applicable":
                    out.append(para("N/A   " + r["msg"], "    "))
                elif r["type"] == "text":
                    out.append(para(r["msg"], "      "))
            out.append("")
    out += ["-" * W, para("%s, %s. Each finding's page: %s. %s" % (BRAND_NAME, HOME_URL, SITE_URL, CAUTION)), para(STANDARDS_NOTE),
            para("Questions and other issues: %s (GPG %s). Report security issues in these tools to %s (GPG %s)." % (
                HELP, HELP_GPG, CONTACT, CONTACT_GPG))]
    return "\n".join(out) + "\n"


# ---------- Markdown ---------------------------------------------------------------------------
def md_escape(s):
    return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", s)


# Anything a renderer could turn into a link: a scheme (https:, javascript:, data:), www., an email address, or a
# word that passes for a domain name (magento-check.sh, psf-report.py: .sh and .py are country domains).
URLISH = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*:[^\s]+|www\.[^\s]+|[^\s@]+@[^\s@]+\.[^\s@]+|[^\s]*[a-z0-9-]\.[a-z]{2,}[^\s]*)")


def md_code(s):
    """s as a code span: never a link, never markup, whatever it holds."""
    s = s.replace("\n", " ")
    ticks = "`" * (max([len(m) for m in re.findall(r"`+", s)] or [0]) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return ticks + pad + s + pad + ticks


def md_text(s):
    """Text from a host or a tool: escaped, and any address in it made a code span, so no renderer links it."""
    s, out, i = clip(s), [], 0
    for m in URLISH.finditer(s):
        out.append(md_escape(s[i:m.start()]))
        out.append(md_code(m.group(0)))
        i = m.end()
    out.append(md_escape(s[i:]))
    return "".join(out)


def render_md(runs, title, details):
    st = overall(runs)
    hosts = sorted({r["host"] for r in runs})
    out = ["# %s" % md_text(title), "",
           "**Status: %s.** %d run(s) on %d host(s): %s. Generated %s by %s %s." % (
               STATUS_TEXT[st], len(runs), len(hosts), md_text(", ".join(hosts)), now_utc(), md_code(NAME), VERSION), ""]
    out += ["## Runs", "", "| Host | Tool | Command | Result | Crit | Warn | Applies here | Time |",
            "|---|---|---|---|---:|---:|---|---:|"]
    for run in runs:
        c = run["counts"]
        out.append("| %s | %s %s | %s | %s | %d | %d | %s | %s |" % (
            md_text(run["host"]), md_text(run["tool"]), md_text(run["version"]), md_text(run["command"] or "-"),
            run["result"], c["crit"], c["warn"], applic(run), "%ss" % run["duration"] if run["duration"] is not None else "-"))
    out.append("")
    items = attention(runs)
    out += ["## Needs attention", ""]
    if not items:
        out += ["Nothing. No run reported a warning, a critical finding or an error.", ""]
    for run, r in items:
        kind = " (%s)" % r["kind"] if r.get("kind") else ""
        out.append("- **%s%s** on %s, %s %s: %s" % (LABEL[r["level"]], kind, md_text(run["host"]), md_text(run["tool"]),
                                                    md_text(run["command"]), md_text(r["msg"])))
        extra = []
        if r.get("cve"):
            extra.append("CVE: " + ", ".join(r["cve"]))
        if r.get("code"):
            extra.append("code %s" % md_code(r["code"]))
        if r.get("path"):
            extra.append("path %s" % md_code(r["path"]))
        if str(r.get("fix", "")).startswith(("https://", "http://")) and not re.search(r"[\s<>]", r["fix"]):
            extra.append("what to do: <%s>" % r["fix"])
        if extra:
            out.append("  " + "; ".join(extra))
    out.append("")
    acc = accepted_items(runs)
    if acc:
        out += ["## Accepted risks", "", "Listed in %s; not counted as needing attention." % md_code(ACCEPT["source"]), ""]
        for run, r in acc:
            out.append("- **Accepted** on %s, %s %s: %s. Reason: %s%s" % (md_text(run["host"]), md_text(run["tool"]), md_text(run["command"]),
                       md_text(r["msg"]), md_text(r["accepted"]), ("; CVE: " + ", ".join(r["cve"])) if r.get("cve") else ""))
        out.append("")
    idx = cve_index(runs)
    if idx:
        out += ["## CVEs behind the findings", ""]
        for c, where in idx.items():
            out.append("- %s: %s" % (c, md_text(", ".join(sorted(where)))))
        out.append("")
    if details:
        out += ["## Details", ""]
        for run in runs:
            out += ["### %s: %s %s on %s" % (md_text(run["command"] or "run"), md_text(run["tool"]), md_text(run["version"]),
                                             md_text(run["host"])), ""]
            out.append("Started %s; result %s (exit %s)%s." % (run["started"], run["result"], run["exit"],
                                                             "; nothing to check on this host" if run["applicable"] is False else ""))
            out.append("")
            for r in run["events"]:
                if r["type"] == "section":
                    out += ["", "**%s**" % md_text(r["msg"]), ""]
                elif r["type"] == "event":
                    out.append("- %s: %s" % (LABEL.get(r.get("level"), "INFO"), md_text(r["msg"])))
                elif r["type"] == "applicable":
                    out.append("- NOT APPLICABLE: %s" % md_text(r["msg"]))
                elif r["type"] == "text":
                    out.append("- %s" % md_text(r["msg"]))
            out.append("")
    out += ["---", "", "**%s** (<%s>). Each finding links to its tool's page at <%s>. %s" % (BRAND_NAME, HOME_URL, SITE_URL, CAUTION), "",
            "%s %s" % (STANDARDS_NOTE, "See the automation guide for how they line up."), "",
            "Questions and other issues: <%s> (GPG `%s`). Report security issues in these tools to <%s> (GPG `%s`)." % (
                HELP, HELP_GPG, CONTACT, CONTACT_GPG)]
    return "\n".join(out) + "\n"


# ---------- HTML -------------------------------------------------------------------------------
CSS = """
:root{--brand-bg:#1A1916;--brand-fg:#FAF9F5;--brand-muted:#C2C0B6;--brand-orange:#FB521F;--link:#C23D0E;--link-hover:#9E300A;--bg:#fff;--fg:#1b1b1f;--muted:#5d5d66;--line:#dcdce2;--panel:#f6f6f8;--crit:#b3261e;--warn:#8a5a00;--ok:#1e6b34;--error:#6b1e9e;--info:#28509b;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--link:#D9824F;--link-hover:#FF8A5C;--bg:#141417;--fg:#ececf1;--muted:#a3a3ad;--line:#34343c;--panel:#1d1d22;--crit:#ff8a80;--warn:#ffcf70;--ok:#7ed69a;--error:#d7a6ff;--info:#9ab8ff;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:4px 20px 48px;overflow-wrap:anywhere}.scroll td,.scroll th{overflow-wrap:normal}h1{font-size:26px;margin:0 0 4px}
.brand{background:var(--brand-bg);color:var(--brand-fg);border-bottom:4px solid var(--brand-orange)}.brand-in{max-width:1000px;margin:0 auto;padding:22px 20px 18px}
.brand .ps-logo{display:block;height:30px;width:auto;max-width:100%;margin:0 0 14px}.brand h1{color:var(--brand-fg)}.brand .meta{color:var(--brand-muted);margin:0}
.brand a{color:var(--brand-fg)}h2{font-size:19px;margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:16px;margin:22px 0 6px}.meta{color:var(--muted);margin:0 0 18px}
.status{display:inline-flex;align-items:stretch;border-radius:4px;overflow:hidden;margin:2px 0 10px;font-size:14px;line-height:1.2}
.status .k{padding:7px 10px;background:rgba(250,249,245,.12);color:var(--brand-muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;display:flex;align-items:center}
.status .v{padding:7px 12px;color:#fff;font-weight:700}.s-compromise .v,.s-action .v{background:#b3261e}.s-review .v{background:#8a5a00}
.s-incomplete .v{background:#6b1e9e}.s-clean .v{background:#1e6b34}.s-empty .v{background:#55555f}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--panel)}
td.n{text-align:right;font-variant-numeric:tabular-nums}.item{border-left:4px solid var(--line);background:var(--panel);padding:8px 12px;margin:8px 0;border-radius:4px}
.item.crit{border-color:var(--crit)}.item.warn{border-color:var(--warn)}.item.error{border-color:var(--error)}.lvl{font-weight:700;letter-spacing:.04em;font-size:12px}
.lvl.crit{color:var(--crit)}.lvl.warn{color:var(--warn)}.lvl.error{color:var(--error)}.lvl.ok{color:var(--ok)}.lvl.info{color:var(--info)}
.sub{color:var(--muted);font-size:13px}code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
a{color:var(--link);text-decoration-thickness:1px;text-underline-offset:2px}a:hover{color:var(--link-hover);text-decoration-thickness:2px}
a:focus-visible{outline:2px solid var(--link);outline-offset:2px;border-radius:2px}
ul.ev{list-style:none;padding:0;margin:0}ul.ev li{padding:2px 0}details{margin:10px 0}summary{cursor:pointer;font-weight:600}footer{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}footer p{margin:6px 0}
@media print{body{background:#fff;color:#000}.brand{-webkit-print-color-adjust:exact;print-color-adjust:exact}details{display:block}details>summary{display:none}.item{break-inside:avoid}a{color:#C23D0E}}
"""


def render_html(runs, title, details):
    e = html.escape
    st = overall(runs)
    hosts = sorted({r["host"] for r in runs})
    o = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
         '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'">'
         '<meta name="referrer" content="no-referrer"><meta name="generator" content="%s %s, %s (%s)">' % (NAME, VERSION, BRAND_NAME, HOME_URL),
         "<title>%s</title><style>%s</style></head><body>" % (e(title), CSS),
         '<header class="brand"><div class="brand-in"><a href="%s" aria-label="PrivacySafe">%s</a><h1>%s</h1>' % (e(HOME_URL, quote=True), LOGO_SVG, e(title)),
         '<div class="status s-%s" role="status"><span class="k">Status</span><span class="v">%s</span></div>'
         '<p class="meta">%d run(s) on %d host(s): %s. Generated %s by %s %s.</p></div></header><main>' % (
             st, e(STATUS_TEXT[st]), len(runs), len(hosts), e(", ".join(hosts)), e(now_utc()), NAME, VERSION),
         "<h2>Runs</h2><div class=\"scroll\"><table><thead><tr><th>Host</th><th>Tool</th><th>Command</th><th>Result</th>"
         "<th>Crit</th><th>Warn</th><th>Applies here</th><th>Time</th></tr></thead><tbody>"]
    for run in runs:
        c = run["counts"]
        o.append("<tr><td>%s</td><td>%s <span class=\"sub\">%s</span></td><td>%s</td><td>%s</td><td class=\"n\">%d</td><td class=\"n\">%d</td><td>%s</td><td class=\"n\">%s</td></tr>" % (
            e(run["host"]), e(run["tool"]), e(run["version"]), e(run["command"] or "-"), e(run["result"]), c["crit"], c["warn"],
            applic(run), e("%ss" % run["duration"]) if run["duration"] is not None else "-"))
    o.append("</tbody></table></div><h2>Needs attention</h2>")
    items = attention(runs)
    if not items:
        o.append("<p>Nothing. No run reported a warning, a critical finding or an error.</p>")
    for run, r in items:
        lv = r["level"]
        kind = " <em>(%s)</em>" % e(r["kind"]) if r.get("kind") else ""
        sub = ["%s %s on <strong>%s</strong>" % (e(run["tool"]), e(run["command"]), e(run["host"]))]
        if r.get("cve"):
            sub.append("CVE: " + ", ".join(e(c) for c in r["cve"]))
        if r.get("code"):
            sub.append("code <code>%s</code>" % e(r["code"]))
        if r.get("path"):
            sub.append("path <code>%s</code>" % e(r["path"]))
        if r.get("fix", "").startswith(("https://", "http://")):
            sub.append('<a href="%s">what to do</a>' % e(r["fix"], quote=True))
        o.append('<div class="item %s"><span class="lvl %s">%s</span>%s %s<div class="sub">%s</div></div>' % (
            lv, lv, LABEL[lv], kind, e(clip(r["msg"])), " &middot; ".join(sub)))
    acc = accepted_items(runs)
    if acc:
        o.append("<h2>Accepted risks</h2><p>Listed in <code>%s</code>; not counted as needing attention.</p><ul>" % e(ACCEPT["source"]))
        for run, r in acc:
            o.append("<li><strong>Accepted</strong> on %s, %s %s: %s <em>Reason: %s</em>%s</li>" % (e(run["host"]), e(run["tool"]), e(run["command"]),
                     e(r["msg"]), e(r["accepted"]), (" CVE: " + ", ".join(e(c) for c in r["cve"])) if r.get("cve") else ""))
        o.append("</ul>")
    idx = cve_index(runs)
    if idx:
        o.append("<h2>CVEs behind the findings</h2><ul>")
        for c, where in idx.items():
            o.append("<li><strong>%s</strong>: %s</li>" % (e(c), e(", ".join(sorted(where)))))
        o.append("</ul>")
    if details:
        o.append("<h2>Details</h2>")
        for run in runs:
            o.append("<details%s><summary>%s %s %s on %s: %s</summary>" % (
                " open" if run["counts"]["crit"] or run["counts"]["warn"] else "", e(run["tool"]), e(run["version"]),
                e(run["command"] or ""), e(run["host"]), e(run["result"])))
            o.append('<p class="sub">Started %s; exit %s%s.</p><ul class="ev">' % (
                e(run["started"]), e(str(run["exit"])), "; nothing to check on this host" if run["applicable"] is False else ""))
            for r in run["events"]:
                if r["type"] == "section":
                    o.append("</ul><h3>%s</h3><ul class=\"ev\">" % e(r["msg"]))
                elif r["type"] == "event":
                    lv = r.get("level", "info")
                    o.append('<li><span class="lvl %s">%s</span> %s</li>' % (lv, LABEL.get(lv, "INFO"), e(clip(r["msg"]))))
                elif r["type"] == "applicable":
                    o.append('<li><span class="lvl info">N/A</span> %s</li>' % e(r["msg"]))
                elif r["type"] == "text":
                    o.append('<li class="sub">%s</li>' % e(r["msg"]))
            o.append("</ul></details>")
    o.append('<footer><p><strong>%s</strong>, <a href="%s">privacysafe.app</a>. Each finding links to its tool at <a href="%s">privacysafe.app/docs/security-patches</a>. %s</p>' % (
        e(BRAND_NAME), e(HOME_URL, quote=True), e(SITE_URL, quote=True), e(CAUTION)))
    o.append("<p>%s</p>" % e(STANDARDS_NOTE))
    o.append('<p>Questions and other issues: <a href="mailto:%s">%s</a> (GPG <code>%s</code>). Report security issues in these tools to <a href="mailto:%s">%s</a> (GPG <code>%s</code>).</p></footer></main></body></html>' % (
        e(HELP, quote=True), e(HELP), e(HELP_GPG), e(CONTACT, quote=True), e(CONTACT), e(CONTACT_GPG)))
    return "\n".join(o).replace("<a href=", '<a rel="noopener noreferrer" href=') + "\n"


# ---------- PDF (no dependencies: the standard Helvetica and Courier fonts, widths from Adobe's AFM files) ----
HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556,
        556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556,
        556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556,
         556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611,
         611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
FONTS = {"F1": HELV, "F2": HELVB, "F3": None}           # F3 is Courier: every character 600 units
ASCII_FOR = {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u00b7": "-", "\u2026": "...",
             "\u2713": "ok", "\u2714": "ok", "\u2717": "x", "\u2718": "x", "\u2192": "->", "\u2190": "<-", "\u00a0": " ",
             "\u2264": "<=", "\u2265": ">=", "\u00d7": "x"}
COLORS = {"crit": (0.70, 0.15, 0.12), "warn": (0.62, 0.42, 0.0), "error": (0.42, 0.12, 0.62), "ok": (0.12, 0.42, 0.20),
          "info": (0.16, 0.31, 0.61), "text": (0.11, 0.11, 0.12), "muted": (0.40, 0.40, 0.45), "band": (0.102, 0.098, 0.086),
          "brand_fg": (0.98, 0.976, 0.961), "brand_muted": (0.761, 0.753, 0.714), "orange": (0.984, 0.322, 0.122),
          "line": (0.84, 0.84, 0.87), "panel": (0.965, 0.965, 0.975), "white": (1, 1, 1)}


# ---- logo begin (generated by packaging/report-logo.py from packaging/site/img/privacysafe-logo.svg; do not edit) ----
LOGO_VIEWBOX = (1696.46, 192)
LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1696.4588 192" width="1696.459" height="192" role="img" aria-label="PrivacySafe" class="ps-logo"><defs><linearGradient id="ps-warm" x1="221.6782" y1="85.938" x2="1463.0474" y2="85.938" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ef2008"/><stop offset="1" stop-color="#ff6428"/></linearGradient><linearGradient id="ps-arch" x1="30.0736" y1="90.236" x2="181.7924" y2="90.236" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ef2008"/><stop offset="1" stop-color="#ff6428"/></linearGradient><linearGradient id="ps-bar" x1="10" y1="151.6399" x2="202" y2="151.6399" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#157ee9"/><stop offset="1" stop-color="#3ecc78"/></linearGradient><linearGradient id="ps-cap" x1="4.2557" y1="125.2152" x2="205.2494" y2="125.2152" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#157ee9"/><stop offset="1" stop-color="#3ecc78"/></linearGradient></defs><g transform="translate(8.472604,10.546284)" fill="#ef2008"><path d="m 1677.9864,31.29432 q 0,7.348114 -2.4205,13.226606 -2.4206,5.792043 -6.4837,9.855118 -4.063,3.976626 -9.4228,6.137836 -5.3598,2.074762 -11.2383,2.074762 -5.8785,0 -11.2383,-2.074762 -5.3598,-2.16121 -9.4229,-6.137836 -4.0631,-4.063075 -6.4836,-9.855118 -2.4206,-5.878492 -2.4206,-13.226606 0,-7.348114 2.4206,-13.140157 2.4205,-5.878491 6.4836,-9.8551178 4.0631,-4.0630749 9.4229,-6.1378366 5.3598,-2.161210011438 11.2383,-2.161210011438 5.8785,0 11.2383,2.161210011438 5.3598,2.0747617 9.4228,6.1378366 4.0631,3.9766268 6.4837,9.8551178 2.4205,5.792043 2.4205,13.140157 z m -6.3107,0 q 0,-5.705594 -1.729,-10.373808 -1.7289,-4.754662 -4.8411,-8.12615 -3.0257,-3.3714875 -7.3481,-5.186904 -4.236,-1.8154165 -9.3364,-1.8154165 -5.1005,0 -9.4229,1.8154165 -4.236,1.8154165 -7.3481,5.186904 -3.0257,3.371488 -4.7547,8.12615 -1.7289,4.668214 -1.7289,10.373808 0,5.705595 1.7289,10.460257 1.729,4.668214 4.7547,8.039701 3.1121,3.371488 7.3481,5.186905 4.3224,1.815416 9.4229,1.815416 5.1004,0 9.3364,-1.815416 4.3224,-1.815417 7.3481,-5.186905 3.1122,-3.371487 4.8411,-8.039701 1.729,-4.754662 1.729,-10.460257 z m -14.6962,17.203232 q -1.9883,-3.890178 -4.4954,-7.348114 -2.4205,-3.544384 -4.2359,-5.619146 h -5.7921 v 12.96726 h -6.1378 v -33.54198 q 2.3341,-0.51869 4.9276,-0.778035 2.5934,-0.259346 4.7546,-0.259346 7.4346,0 11.3248,2.766349 3.8901,2.766349 3.8901,8.385495 0,3.198591 -1.7289,5.619146 -1.6426,2.334107 -4.7547,3.630833 0.8645,1.037381 1.9883,2.593452 1.1238,1.556072 2.3341,3.457937 1.2103,1.901864 2.4206,3.976626 1.2103,2.074762 2.1612,4.149523 z m -14.5234,-17.981267 h 3.2851 q 3.8901,0 6.4836,-1.037381 2.5935,-1.123829 2.5935,-4.495317 0,-3.198591 -2.507,-4.408869 -2.4206,-1.296726 -5.8785,-1.296726 -0.951,0 -1.9884,0.08645 -1.0373,0 -1.9883,0.08645 z"/></g><g transform="matrix(0.99924018,0,0,1.0007604,8.472604,10.546284)" fill="url(#ps-warm)"><path d="m 221.67828,9.4045303 h 29.73871 V 162.47144 h -29.73871 z m 12.02669,76.0961187 h 40.23472 v 25.802711 h -40.23472 z m 40.23472,0 q 11.15202,0 19.02403,-1.968003 8.09068,-2.18667 12.24536,-7.434678 4.37334,-5.466676 4.37334,-15.744025 0,-10.277349 -4.37334,-15.525357 -4.15468,-5.466676 -12.24536,-7.434679 -7.87201,-2.18667 -19.02403,-2.18667 V 9.4045303 q 20.11737,0 34.98673,5.0293417 15.08802,4.810674 23.39737,15.962691 8.30934,11.152017 8.30934,29.95738 0,18.368029 -8.30934,29.738713 -8.30935,11.370684 -23.39737,16.400024 -14.86936,4.81068 -34.98673,4.81068 z M 233.70497,9.4045303 h 40.23472 V 35.207237 h -40.23472 z"/><path d="m 357.2516,9.4045303 h 29.73871 V 162.47144 H 357.2516 Z m 12.02668,73.9094487 h 40.89073 v 25.802711 h -40.89073 z m 40.89073,0 q 11.15202,0 19.02403,-2.18667 8.09068,-2.18667 12.24536,-7.434678 4.37334,-5.248009 4.37334,-14.432023 0,-9.402681 -4.37334,-14.432022 -4.15468,-5.248009 -12.24536,-7.434679 -7.87201,-2.18667 -19.02403,-2.18667 V 9.4045303 q 19.8987,0 34.76806,4.8106737 15.08802,4.592008 23.39737,15.525358 8.52801,10.93335 8.52801,29.520046 0,18.368029 -8.52801,29.520046 -8.30935,10.93335 -23.39737,15.744026 -14.86936,4.59201 -34.76806,4.59201 z M 369.27828,9.4045303 h 40.89073 V 35.207237 h -40.89073 z m 43.95207,82.4374617 h 29.73872 l 34.33072,70.629448 H 443.4064 Z"/><path d="m 497.85443,9.4045303 h 29.73871 V 162.47144 h -29.73871 z"/><path d="M 590.56894,162.47144 543.7742,9.4045303 h 30.39471 L 618.99565,162.47144 Z m 41.98406,0 H 604.12629 L 649.17169,9.4045303 h 30.61339 z"/><path d="m 717.39535,9.4045303 h 28.42671 L 700.99533,162.47144 h -30.39472 z m 41.98407,0 47.23207,153.0669097 H 775.99811 L 730.95271,9.4045303 Z m -62.3201,94.2454797 h 82.43746 v 25.80271 h -82.43746 z"/><path d="m 955.52325,100.15134 q -1.53067,19.68003 -10.05868,34.54939 -8.30935,14.86935 -23.39737,23.1787 -14.86936,8.09068 -36.51739,8.09068 -24.27204,0 -41.32806,-10.71469 -16.83736,-10.93335 -25.58404,-29.08271 -8.74668,-18.14936 -8.74668,-40.453394 0,-16.400026 4.81067,-30.832048 5.02934,-14.65069 14.65069,-25.58404 9.62135,-10.93335 23.61604,-17.056027 14.21335,-6.3413428 32.58138,-6.3413428 30.83205,0 48.10674,16.4000258 17.49336,16.181358 20.99203,43.733401 h -31.70671 q -1.09334,-7.434678 -3.71734,-13.338687 -2.624,-6.122676 -7.21601,-10.496017 -4.37334,-4.37334 -10.93335,-6.778677 -6.56001,-2.405337 -15.52536,-2.405337 -15.52536,0 -25.58404,7.653345 -9.84001,7.434679 -14.43202,19.461364 -4.59201,12.026685 -4.59201,25.58404 0,13.557354 4.59201,25.802704 4.59201,12.02669 14.43202,19.68003 10.05868,7.43468 25.58404,7.43468 9.84002,0 16.83736,-2.84267 6.99734,-2.84267 11.58935,-7.87201 4.81068,-5.24801 7.21601,-12.24535 2.40534,-6.99735 3.06134,-15.52536 z"/><path d="M 1008.2218,119.6127 955.74173,9.4045303 h 30.61338 l 36.73609,80.0321247 h -7.872 l 36.5173,-80.0321247 h 30.6134 L 1029.8698,119.6127 Z m -4.1547,-32.362715 h 29.9574 v 75.221455 h -29.9574 z"/><path d="m 1117.5548,113.70869 q 0.8746,7.65335 5.248,13.33869 4.3733,5.68534 11.3707,8.74668 7.216,2.84267 16.1813,2.84267 12.0267,0 20.1174,-4.15467 8.3093,-4.37334 8.3093,-13.33869 0,-6.34134 -5.0293,-9.84001 -4.8107,-3.71734 -13.12,-5.90401 -8.0907,-2.40534 -17.7121,-4.37334 -9.6213,-2.186674 -19.4613,-5.248012 -9.6214,-3.280005 -17.7121,-8.528013 -8.0906,-5.248008 -13.12,-13.994688 -4.8106,-8.746681 -4.8106,-22.304035 0,-13.120021 7.6533,-23.178703 7.6533,-10.277349 21.2107,-15.962692 13.776,-5.9040088 31.488,-5.9040088 16.8374,0 30.1761,6.7786768 13.3387,6.778678 21.2107,18.586696 7.872,11.808018 7.872,26.677375 h -31.488 q -0.8747,-11.808018 -8.0907,-18.368029 -6.9974,-6.56001 -20.7734,-6.56001 -13.776,0 -20.992,5.029341 -7.216,5.029341 -7.216,12.901354 0,6.997344 4.8106,10.93335 5.0294,3.717339 13.1201,6.341343 8.0906,2.405337 17.712,4.37334 9.84,1.968004 19.4614,5.029342 9.6213,2.842671 17.712,8.090679 8.3093,5.029341 13.12,13.557354 5.0293,8.52801 5.0293,21.8667 0,21.2107 -15.9627,33.01872 -15.9626,11.80802 -44.8267,11.80802 -17.712,0 -31.7067,-6.77868 -13.9947,-6.77868 -22.304,-18.5867 -8.3094,-11.80801 -8.9654,-26.89604 z"/><path d="m 1264.7173,9.4045303 h 28.4267 L 1248.3172,162.47144 h -30.3947 z m 41.984,0 47.2321,153.0669097 H 1323.32 L 1278.2746,9.4045303 Z m -62.3201,94.2454797 h 82.4375 v 25.80271 h -82.4375 z"/><path d="m 1369.8957,9.4045303 h 29.7387 V 162.47144 h -29.7387 z m 28.4267,67.5681057 h 67.1308 v 25.802704 h -67.1308 z m -16.4,-67.5681057 h 92.2774 V 35.425904 h -92.2774 z"/><path d="M 1491.6927,162.47144 V 9.4045303 h 106.0535 V 35.425904 h -76.3148 v 37.173391 h 67.5681 v 25.802707 h -67.5681 v 38.048058 h 77.1895 v 26.02138 z"/></g><path fill="url(#ps-arch)" d="M 105.93284,10 C 65.190154,10.0852 31.78716,44.19539 30.27561,87.258989 H 64.614084 C 66.303154,62.48373 84.423764,43.34171 106.24833,43.27803 c 21.82526,0.0626 39.94709,19.20488 41.63617,43.980959 h 33.83987 C 180.21078,44.14039 146.72745,10.00884 105.93284,10 Z"/><path fill="url(#ps-bar)" d="m 10,99.693739 v 22.240531 l 192,1e-5 V 99.693739 Z"/><path fill="url(#ps-cap)" d="M 30.27542,134.36903 C 44.74249,162.70491 73.219044,181.9324 105.92263,182 c 32.76194,-0.007 61.3104,-19.24776 75.80154,-47.63097 z"/></svg>'
LOGO_PARTS = [
    ((1, 0, 0, 1, 8.472604, 10.546284), '1677.99 31.29 m 1677.99 36.19 1677.18 40.6 1675.57 44.52 c 1673.95 48.38 1671.79 51.67 1669.08 54.38 c 1666.37 57.03 1663.23 59.07 1659.66 60.51 c 1656.09 61.9 1652.34 62.59 1648.42 62.59 c 1644.5 62.59 1640.76 61.9 1637.18 60.51 c 1633.61 59.07 1630.47 57.03 1627.76 54.38 c 1625.05 51.67 1622.89 48.38 1621.28 44.52 c 1619.66 40.6 1618.86 36.19 1618.86 31.29 c 1618.86 26.4 1619.66 22.02 1621.28 18.15 c 1622.89 14.24 1625.05 10.95 1627.76 8.3 c 1630.47 5.59 1633.61 3.54 1637.18 2.16 c 1640.76 0.72 1644.5 0 1648.42 0 c 1652.34 0 1656.09 0.72 1659.66 2.16 c 1663.23 3.54 1666.37 5.59 1669.08 8.3 c 1671.79 10.95 1673.95 14.24 1675.57 18.15 c 1677.18 22.02 1677.99 26.4 1677.99 31.29 c h 1671.68 31.29 m 1671.68 27.49 1671.1 24.03 1669.95 20.92 c 1668.79 17.75 1667.18 15.04 1665.11 12.79 c 1663.09 10.55 1660.64 8.82 1657.76 7.61 c 1654.93 6.4 1651.82 5.79 1648.42 5.79 c 1645.02 5.79 1641.88 6.4 1639 7.61 c 1636.17 8.82 1633.72 10.55 1631.65 12.79 c 1629.63 15.04 1628.05 17.75 1626.9 20.92 c 1625.74 24.03 1625.17 27.49 1625.17 31.29 c 1625.17 35.1 1625.74 38.58 1626.9 41.75 c 1628.05 44.87 1629.63 47.55 1631.65 49.79 c 1633.72 52.04 1636.17 53.77 1639 54.98 c 1641.88 56.19 1645.02 56.8 1648.42 56.8 c 1651.82 56.8 1654.93 56.19 1657.76 54.98 c 1660.64 53.77 1663.09 52.04 1665.11 49.79 c 1667.18 47.55 1668.79 44.87 1669.95 41.75 c 1671.1 38.58 1671.68 35.1 1671.68 31.29 c h 1656.98 48.5 m 1655.65 45.9 1654.16 43.45 1652.48 41.15 c 1650.87 38.79 1649.46 36.91 1648.25 35.53 c 1642.46 35.53 l 1642.46 48.5 l 1636.32 48.5 l 1636.32 14.96 l 1637.87 14.61 1639.52 14.35 1641.25 14.18 c 1642.97 14 1644.56 13.92 1646 13.92 c 1650.96 13.92 1654.73 14.84 1657.33 16.68 c 1659.92 18.53 1661.22 21.32 1661.22 25.07 c 1661.22 27.2 1660.64 29.08 1659.49 30.69 c 1658.39 32.25 1656.81 33.46 1654.73 34.32 c 1655.31 35.01 1655.97 35.88 1656.72 36.91 c 1657.47 37.95 1658.25 39.1 1659.05 40.37 c 1659.86 41.64 1660.67 42.96 1661.47 44.35 c 1662.28 45.73 1663 47.11 1663.64 48.5 c h 1642.46 30.52 m 1645.74 30.52 l 1648.33 30.52 1650.5 30.17 1652.22 29.48 c 1653.95 28.73 1654.82 27.23 1654.82 24.98 c 1654.82 22.85 1653.98 21.38 1652.31 20.57 c 1650.7 19.71 1648.74 19.28 1646.43 19.28 c 1645.8 19.28 1645.14 19.31 1644.44 19.36 c 1643.75 19.36 1643.09 19.39 1642.46 19.45 c h',
     ('solid', (0.9373, 0.1255, 0.0314))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '221.68 9.4 m 251.42 9.4 l 251.42 162.47 l 221.68 162.47 l h 233.7 85.5 m 273.94 85.5 l 273.94 111.3 l 233.7 111.3 l h 273.94 85.5 m 281.37 85.5 287.72 84.84 292.96 83.53 c 298.36 82.07 302.44 79.6 305.21 76.1 c 308.12 72.45 309.58 67.21 309.58 60.35 c 309.58 53.5 308.12 48.33 305.21 44.83 c 302.44 41.18 298.36 38.71 292.96 37.39 c 287.72 35.94 281.37 35.21 273.94 35.21 c 273.94 9.4 l 287.35 9.4 299.01 11.08 308.93 14.43 c 318.99 17.64 326.78 22.96 332.32 30.4 c 337.86 37.83 340.63 47.82 340.63 60.35 c 340.63 72.6 337.86 82.51 332.32 90.09 c 326.78 97.67 318.99 103.14 308.93 106.49 c 299.01 109.7 287.35 111.3 273.94 111.3 c h 233.7 9.4 m 273.94 9.4 l 273.94 35.21 l 233.7 35.21 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '357.25 9.4 m 386.99 9.4 l 386.99 162.47 l 357.25 162.47 l h 369.28 83.31 m 410.17 83.31 l 410.17 109.12 l 369.28 109.12 l h 410.17 83.31 m 417.6 83.31 423.95 82.59 429.19 81.13 c 434.59 79.67 438.67 77.19 441.44 73.69 c 444.35 70.19 445.81 65.38 445.81 59.26 c 445.81 52.99 444.35 48.18 441.44 44.83 c 438.67 41.33 434.59 38.85 429.19 37.39 c 423.95 35.94 417.6 35.21 410.17 35.21 c 410.17 9.4 l 423.43 9.4 435.02 11.01 444.94 14.22 c 455 17.28 462.79 22.45 468.33 29.74 c 474.02 37.03 476.86 46.87 476.86 59.26 c 476.86 71.51 474.02 81.35 468.33 88.78 c 462.79 96.07 455 101.32 444.94 104.52 c 435.02 107.59 423.43 109.12 410.17 109.12 c h 369.28 9.4 m 410.17 9.4 l 410.17 35.21 l 369.28 35.21 l h 413.23 91.84 m 442.97 91.84 l 477.3 162.47 l 443.41 162.47 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '497.85 9.4 m 527.59 9.4 l 527.59 162.47 l 497.85 162.47 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '590.57 162.47 m 543.77 9.4 l 574.17 9.4 l 619 162.47 l h 632.55 162.47 m 604.13 162.47 l 649.17 9.4 l 679.79 9.4 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '717.4 9.4 m 745.82 9.4 l 701 162.47 l 670.6 162.47 l h 759.38 9.4 m 806.61 162.47 l 776 162.47 l 730.95 9.4 l h 697.06 103.65 m 779.5 103.65 l 779.5 129.45 l 697.06 129.45 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '955.52 100.15 m 954.5 113.27 951.15 124.79 945.46 134.7 c 939.93 144.61 932.13 152.34 922.07 157.88 c 912.15 163.27 899.98 165.97 885.55 165.97 c 869.37 165.97 855.59 162.4 844.22 155.26 c 833 147.97 824.47 138.27 818.64 126.17 c 812.81 114.07 809.89 100.59 809.89 85.72 c 809.89 74.79 811.49 64.51 814.7 54.89 c 818.05 45.12 822.94 36.59 829.35 29.3 c 835.77 22.01 843.64 16.33 852.97 12.25 c 862.44 8.02 873.3 5.91 885.55 5.91 c 906.1 5.91 922.14 11.37 933.66 22.31 c 945.32 33.09 952.32 47.67 954.65 66.04 c 922.94 66.04 l 922.21 61.08 920.97 56.64 919.22 52.7 c 917.48 48.62 915.07 45.12 912.01 42.2 c 909.09 39.29 905.45 37.03 901.08 35.43 c 896.7 33.82 891.53 33.02 885.55 33.02 c 875.2 33.02 866.67 35.57 859.97 40.67 c 853.41 45.63 848.6 52.12 845.53 60.14 c 842.47 68.15 840.94 76.68 840.94 85.72 c 840.94 94.76 842.47 103.36 845.53 111.52 c 848.6 119.54 853.41 126.1 859.97 131.2 c 866.67 136.16 875.2 138.64 885.55 138.64 c 892.11 138.64 897.72 137.69 902.39 135.79 c 907.05 133.9 910.92 131.27 913.98 127.92 c 917.18 124.42 919.59 120.34 921.19 115.68 c 922.8 111.01 923.82 105.84 924.25 100.15 c h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '1008.22 119.61 m 955.74 9.4 l 986.36 9.4 l 1023.09 89.44 l 1015.22 89.44 l 1051.74 9.4 l 1082.35 9.4 l 1029.87 119.61 l h 1004.07 87.25 m 1034.02 87.25 l 1034.02 162.47 l 1004.07 162.47 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '1117.55 113.71 m 1118.14 118.81 1119.89 123.26 1122.8 127.05 c 1125.72 130.84 1129.51 133.75 1134.17 135.79 c 1138.98 137.69 1144.38 138.64 1150.35 138.64 c 1158.37 138.64 1165.08 137.25 1170.47 134.48 c 1176.01 131.57 1178.78 127.12 1178.78 121.14 c 1178.78 116.92 1177.11 113.64 1173.75 111.3 c 1170.55 108.83 1166.17 106.86 1160.63 105.4 c 1155.24 103.8 1149.33 102.34 1142.92 101.03 c 1136.51 99.57 1130.02 97.82 1123.46 95.78 c 1117.04 93.59 1111.14 90.75 1105.75 87.25 c 1100.35 83.75 1095.98 79.09 1092.63 73.26 c 1089.42 67.42 1087.82 59.99 1087.82 50.95 c 1087.82 42.2 1090.37 34.48 1095.47 27.77 c 1100.57 20.92 1107.64 15.6 1116.68 11.81 c 1125.86 7.87 1136.36 5.91 1148.17 5.91 c 1159.39 5.91 1169.45 8.17 1178.34 12.68 c 1187.24 17.2 1194.31 23.4 1199.55 31.27 c 1204.8 39.14 1207.43 48.04 1207.43 57.95 c 1175.94 57.95 l 1175.36 50.08 1172.66 43.95 1167.85 39.58 c 1163.18 35.21 1156.26 33.02 1147.07 33.02 c 1137.89 33.02 1130.89 34.7 1126.08 38.05 c 1121.27 41.4 1118.87 45.7 1118.87 50.95 c 1118.87 55.62 1120.47 59.26 1123.68 61.88 c 1127.03 64.36 1131.4 66.48 1136.8 68.23 c 1142.19 69.83 1148.1 71.29 1154.51 72.6 c 1161.07 73.91 1167.56 75.59 1173.97 77.63 c 1180.39 79.52 1186.29 82.22 1191.68 85.72 c 1197.22 89.07 1201.6 93.59 1204.8 99.28 c 1208.16 104.96 1209.83 112.25 1209.83 121.14 c 1209.83 135.28 1204.51 146.29 1193.87 154.16 c 1183.23 162.03 1168.29 165.97 1149.04 165.97 c 1137.23 165.97 1126.67 163.71 1117.34 159.19 c 1108.01 154.67 1100.57 148.48 1095.03 140.6 c 1089.49 132.73 1086.5 123.77 1086.07 113.71 c h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '1264.72 9.4 m 1293.14 9.4 l 1248.32 162.47 l 1217.92 162.47 l h 1306.7 9.4 m 1353.93 162.47 l 1323.32 162.47 l 1278.27 9.4 l h 1244.38 103.65 m 1326.82 103.65 l 1326.82 129.45 l 1244.38 129.45 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '1369.9 9.4 m 1399.63 9.4 l 1399.63 162.47 l 1369.9 162.47 l h 1398.32 76.97 m 1465.45 76.97 l 1465.45 102.78 l 1398.32 102.78 l h 1381.92 9.4 m 1474.2 9.4 l 1474.2 35.43 l 1381.92 35.43 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((0.99924, 0.0, 0.0, 1.00076, 8.472604, 10.546284), '1491.69 162.47 m 1491.69 9.4 l 1597.75 9.4 l 1597.75 35.43 l 1521.43 35.43 l 1521.43 72.6 l 1589 72.6 l 1589 98.4 l 1521.43 98.4 l 1521.43 136.45 l 1598.62 136.45 l 1598.62 162.47 l h',
     ('grad', (221.68, 85.94, 1463.05, 85.94), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((1, 0, 0, 1, 0, 0), '105.93 10 m 65.19 10.09 31.79 44.2 30.28 87.26 c 64.61 87.26 l 66.3 62.48 84.42 43.34 106.25 43.28 c 128.07 43.34 146.2 62.48 147.88 87.26 c 181.72 87.26 l 180.21 44.14 146.73 10.01 105.93 10 c h',
     ('grad', (30.07, 90.24, 181.79, 90.24), (0.9373, 0.1255, 0.0314), (1.0, 0.3922, 0.1569))),
    ((1, 0, 0, 1, 0, 0), '10 99.69 m 10 121.93 l 202 121.93 l 202 99.69 l h',
     ('grad', (10.0, 151.64, 202.0, 151.64), (0.0824, 0.4941, 0.9137), (0.2431, 0.8, 0.4706))),
    ((1, 0, 0, 1, 0, 0), '30.28 134.37 m 44.74 162.7 73.22 181.93 105.92 182 c 138.68 181.99 167.23 162.75 181.72 134.37 c h',
     ('grad', (4.26, 125.22, 205.25, 125.22), (0.0824, 0.4941, 0.9137), (0.2431, 0.8, 0.4706))),
]
# ---- logo end ----


def pdf_ascii(s):
    s = "".join(ASCII_FOR.get(ch, ch) for ch in str(s))
    return "".join(ch if 32 <= ord(ch) <= 126 else ("?" if ord(ch) > 126 else " ") for ch in s)


def text_width(s, font, size):
    t = FONTS[font]
    if t is None:
        return len(s) * 600 * size / 1000.0
    return sum(t[ord(ch) - 32] for ch in s) * size / 1000.0


def wrap(s, font, size, width):
    """Lines of s no wider than width; long words (paths, hashes) are broken."""
    out, line = [], ""
    for word in pdf_ascii(s).split(" "):
        cand = word if not line else line + " " + word
        if text_width(cand, font, size) <= width:
            line = cand
            continue
        if line:
            out.append(line)
            line = ""
        while text_width(word, font, size) > width:
            cut = len(word)
            while cut > 1 and text_width(word[:cut], font, size) > width:
                cut -= 1
            out.append(word[:cut])
            word = word[cut:]
        line = word
    out.append(line)
    return out


def pdf_str(s):
    return "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


class PDF:
    def __init__(self, paper, title):
        self.w, self.h = (595.28, 841.89) if paper == "a4" else (612.0, 792.0)
        self.m = 50.0
        self.title = title
        self.pages = []          # each: content operators, link annotations, and the structure element of each MCID
        self.y = 0
        # a tagged PDF (PDF/UA, for WCAG): every piece of text belongs to a structure element in reading order,
        # decoration is an artifact, and every link annotation belongs to a Link element
        self.root = {"tag": "Document", "kids": [], "attrs": {}}
        self.stack = [self.root]
        self.new_page(first=True)

    def begin(self, tag, **attrs):
        el = {"tag": tag, "kids": [], "attrs": attrs}
        self.stack[-1]["kids"].append(el)
        self.stack.append(el)
        return el

    def end(self):
        self.stack.pop()

    def new_page(self, first=False):
        self.pages.append({"ops": [], "links": [], "marks": []})
        self.y = self.h - self.m
        if first:
            band = 112.0
            self.rect(0, self.h - band, self.w, band, COLORS["band"])
            self.rect(0, self.h - band - 3, self.w, 3, COLORS["orange"])
            self.logo(self.m, self.h - 24, 22)
            self.begin("Link", alt="PrivacySafe home page")
            self.link(self.m, self.h - 46, 22 * LOGO_VIEWBOX[0] / LOGO_VIEWBOX[1], 22, HOME_URL)
            self.end()
            self.begin("H1")
            self.text(self.m, self.h - 74, "F2", 19, pdf_ascii(self.title), COLORS["brand_fg"])
            self.end()
            self.begin("P")
            self.text(self.m, self.h - 94, "F1", 9.5, "%s  |  generated %s" % (BRAND_NAME, now_utc()), COLORS["brand_muted"])
            self.end()
            self.y = self.h - band - 26

    def logo(self, x, ytop, height):
        """The PrivacySafe logo, its top left corner at (x, ytop), from the embedded drawing data."""
        s = height / LOGO_VIEWBOX[1]
        ops = ["q %.4f 0 0 %.4f %.2f %.2f cm" % (s, -s, x, ytop)]
        for i, (m, path, paint) in enumerate(LOGO_PARTS):
            ops.append("q %s cm" % " ".join("%.6g" % v for v in m))
            if paint[0] == "solid":
                ops.append("%.4f %.4f %.4f rg %s f" % (paint[1] + (path,)))
            else:
                ops.append("%s W n /Sh%d sh" % (path, i))
            ops.append("Q")
        ops.append("Q")
        self.ops.append("/Artifact BMC " + " ".join(ops) + " EMC")

    @property
    def ops(self):
        return self.pages[-1]["ops"]

    def need(self, height):
        if self.y - height < self.m + 24:
            self.new_page()

    def rect(self, x, y, w, h, color):
        self.ops.append("/Artifact BMC %.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f EMC" % (color + (x, y, w, h)))

    def hline(self, x1, x2, y, color=COLORS["line"], width=0.6):
        self.ops.append("/Artifact BMC %.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S EMC" % (color + (width, x1, y, x2, y)))

    def text(self, x, y, font, size, s, color=COLORS["text"]):
        el = self.stack[-1]
        own = el is self.root                     # text outside any block still gets an element of its own
        if own:
            el = self.begin("P")
        pg = self.pages[-1]
        mcid = len(pg["marks"])
        pg["marks"].append(el)
        el["kids"].append(("mcr", len(self.pages) - 1, mcid))
        self.ops.append("/%s << /MCID %d >> BDC BT %.3f %.3f %.3f rg /%s %.1f Tf %.2f %.2f Td %s Tj ET EMC" % (
            (el["tag"], mcid) + color + (font, size, x, y, pdf_str(s))))
        if own:
            self.end()

    def link(self, x, y, w, h, uri):
        el = self.stack[-1]
        if el["tag"] != "Link":                   # a link with no Link element open gets one, named by its address
            el = {"tag": "Link", "kids": [], "attrs": {"alt": uri}}
            self.stack[-1]["kids"].append(el)
        links = self.pages[-1]["links"]
        el["kids"].append(("objr", len(self.pages) - 1, len(links)))
        links.append((x, y, x + w, y + h, uri, el))

    def heading(self, s, size=14):
        self.need(size + 30)
        self.y -= 12
        self.begin("H2")
        self.text(self.m, self.y - size, "F2", size, pdf_ascii(s))
        self.end()
        self.y -= size + 6
        self.hline(self.m, self.w - self.m, self.y)
        self.y -= 10

    def para(self, s, font="F1", size=10, color=COLORS["text"], indent=0.0, gap=3.0):
        lead = size * 1.32
        self.begin("P")
        for line in wrap(s, font, size, self.w - 2 * self.m - indent):
            self.need(lead)
            self.text(self.m + indent, self.y - size, font, size, line, color)
            self.y -= lead
        self.end()
        self.y -= gap

    def linked(self, segments, size=9, color=COLORS["text"]):
        """Segments (text, link or None[, keep whole]) on as few lines as fit; a linked segment is blue and clickable
        where it stands, and a linked or kept segment is never broken across lines."""
        lead = size * 1.35
        width = self.w - 2 * self.m
        x = None
        self.begin("P")
        for seg in segments:
            text, url, keep = seg[0], seg[1], (len(seg) > 2 and seg[2])
            whole = url is not None or keep
            words = [pdf_ascii(text)] if whole else [w for w in pdf_ascii(text).split(" ") if w]
            for word in words:
                piece = word if whole else word + " "
                w = text_width(piece, "F1", size)
                if x is None or (x - self.m) + w > width:
                    self.need(lead)
                    self.y -= lead
                    x = self.m
                if url:
                    self.begin("Link", alt=url)
                self.text(x, self.y + lead - size - 1, "F1", size, piece, COLORS["info"] if url else color)
                if url:
                    self.link(x, self.y + lead - size - 3, w, size + 3, url)
                    self.end()
                x += w
        self.end()
        self.y -= 4

    def item(self, level, title, msg, sub, url=None):
        """A finding: a colored bar, its level, the message, a line of details and a link."""
        size, lead = 10, 13.2
        width = self.w - 2 * self.m - 14
        mlines = wrap(clip(msg), "F1", size, width)
        slines = wrap(sub, "F1", 8.5, width) if sub else []
        height = 15 + len(mlines) * lead + len(slines) * 11 + (11 if url else 0) + 8
        self.need(min(height, self.h - 2 * self.m - 40))
        top = self.y
        self.rect(self.m, top - height + 2, self.w - 2 * self.m, height - 2, COLORS["panel"])
        self.rect(self.m, top - height + 2, 3.5, height - 2, COLORS.get(level, COLORS["muted"]))
        x = self.m + 12
        self.begin("H3")
        self.text(x, top - 12, "F2", 8.5, pdf_ascii(title), COLORS.get(level, COLORS["muted"]))
        self.end()
        y = top - 15
        self.begin("P")
        for line in mlines:
            self.text(x, y - size, "F1", size, line)
            y -= lead
        self.end()
        if slines:
            self.begin("P")
            for line in slines:
                self.text(x, y - 8.5, "F1", 8.5, line, COLORS["muted"])
                y -= 11
            self.end()
        if url:
            s = pdf_ascii(url)
            self.begin("P")
            self.begin("Link", alt="What to do: " + url)
            self.text(x, y - 8.5, "F1", 8.5, s, COLORS["info"])
            self.link(x, y - 10, text_width(s, "F1", 8.5), 11, url)
            self.end()
            self.end()
        self.y = top - height - 4

    def table(self, headers, rows, widths, aligns):
        scale = (self.w - 2 * self.m) / sum(widths)
        widths = [w * scale for w in widths]
        size, lead = 8.5, 11.0

        def draw_row(cells, font, fill=None):
            self.begin("TR")
            wrapped = [wrap(c, font, size, w - 8) for c, w in zip(cells, widths)]
            hgt = max(len(c) for c in wrapped) * lead + 6
            self.need(hgt)
            if fill:
                self.rect(self.m, self.y - hgt, sum(widths), hgt, fill)
            x = self.m
            for lines, w, al in zip(wrapped, widths, aligns):
                if fill:
                    self.begin("TH", scope="Column")
                else:
                    self.begin("TD")
                yy = self.y - 3 - size
                for line in lines:
                    tx = x + w - 4 - text_width(line, font, size) if al == "r" else x + 4
                    self.text(tx, yy, font, size, line)
                    yy -= lead
                self.end()
                x += w
            self.y -= hgt
            self.hline(self.m, self.m + sum(widths), self.y)
            self.end()

        self.begin("Table")
        draw_row(headers, "F2", COLORS["panel"])
        for r in rows:
            draw_row(r, "F1")
        self.end()
        self.y -= 8

    def build(self, meta=None):
        n = len(self.pages)
        for i, p in enumerate(self.pages, 1):
            foot = "%s  |  page %d of %d" % (pdf_ascii(self.title), i, n)
            p["ops"].append("/Artifact << /Type /Pagination >> BDC BT %.3f %.3f %.3f rg /F1 8 Tf %.2f %.2f Td %s Tj ET EMC" % (
                COLORS["muted"] + (self.m, 28, pdf_str(foot))))
            fp = {"tag": "P", "kids": [], "attrs": {}}
            self.root["kids"].append(fp)
            parts = [("privacysafe.app", HOME_URL), ("  |  ", None), (HELP, "mailto:" + HELP), ("  |  ", None),
                     (CONTACT, "mailto:" + CONTACT)]
            x = self.w - self.m - sum(text_width(t, "F1", 8) for t, _ in parts)
            for t, url in parts:
                tw = text_width(t, "F1", 8)
                if url:
                    le = {"tag": "Link", "kids": [], "attrs": {"alt": t}}
                    fp["kids"].append(le)
                    mc = len(p["marks"]); p["marks"].append(le); le["kids"].append(("mcr", i - 1, mc))
                    le["kids"].append(("objr", i - 1, len(p["links"])))
                    p["ops"].append("/Link << /MCID %d >> BDC BT %.3f %.3f %.3f rg /F1 8 Tf %.2f %.2f Td %s Tj ET EMC" % (
                        (mc,) + COLORS["muted"] + (x, 28, pdf_str(t))))
                    p["links"].append((x, 25, x + tw, 37, url, le))
                else:
                    p["ops"].append("/Artifact BMC BT %.3f %.3f %.3f rg /F1 8 Tf %.2f %.2f Td %s Tj ET EMC" % (COLORS["muted"] + (x, 28, pdf_str(t))))
                x += tw
        objs = []

        def add(b):
            objs.append(b)
            return len(objs)

        catalog = add(b"")
        pages_id = add(b"")
        fonts = {"F1": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"),
                 "F2": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"),
                 "F3": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")}
        shadings = []
        for i, (m, path, paint) in enumerate(LOGO_PARTS):
            if paint[0] == "grad":
                (x1, y1, x2, y2), c0, c1 = paint[1], paint[2], paint[3]
                sid = add(("<< /ShadingType 2 /ColorSpace /DeviceRGB /Coords [%s %s %s %s] /Function << /FunctionType 2 "
                           "/Domain [0 1] /C0 [%s %s %s] /C1 [%s %s %s] /N 1 >> /Extend [true true] >>" % (
                               (x1, y1, x2, y2) + tuple(c0) + tuple(c1))).encode("latin-1"))
                shadings.append("/Sh%d %d 0 R" % (i, sid))
        res = "<< /Font << %s >>%s >>" % (" ".join("/%s %d 0 R" % (k, v) for k, v in fonts.items()),
                                          (" /Shading << %s >>" % " ".join(shadings)) if shadings else "")
        kids = []
        annot_id = {}            # (page index, link index) -> object number
        annot_parent = []        # (StructParent key, Link element), after the page keys
        for pi, p in enumerate(self.pages):
            data = zlib.compress("\n".join(p["ops"]).encode("latin-1"))
            cid = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            annots = []
            for li, (x1, y1, x2, y2, uri, el) in enumerate(p["links"]):
                key = len(self.pages) + len(annot_parent)
                a = add(("<< /Type /Annot /Subtype /Link /Rect [%.2f %.2f %.2f %.2f] /Border [0 0 0] /StructParent %d "
                         "/Contents %s /A << /S /URI /URI %s >> >>" % (x1, y1, x2, y2, key, pdf_str(pdf_ascii(el["attrs"].get("alt") or uri)),
                                                                     pdf_str(pdf_ascii(uri)))).encode("latin-1"))
                annots.append(a); annot_id[(pi, li)] = a; annot_parent.append((key, el))
            ann = " /Annots [%s]" % " ".join("%d 0 R" % a for a in annots) if annots else ""
            kids.append(add(("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Resources %s /Contents %d 0 R%s "
                             "/StructParents %d /Tabs /S >>" % (pages_id, self.w, self.h, res, cid, ann, pi)).encode("latin-1")))
        # the structure tree: an object for every element, then the parent tree that maps content back to them
        tree_root = add(b"")
        ids = {}
        def number(el):
            ids[id(el)] = add(b"")
            for k in el["kids"]:
                if isinstance(k, dict):
                    number(k)
        number(self.root)
        def write(el, parent):
            parts = []
            for k in el["kids"]:
                if isinstance(k, dict):
                    parts.append("%d 0 R" % ids[id(k)])
                elif k[0] == "mcr":
                    parts.append("<< /Type /MCR /Pg %d 0 R /MCID %d >>" % (kids[k[1]], k[2]))
                else:
                    parts.append("<< /Type /OBJR /Obj %d 0 R /Pg %d 0 R >>" % (annot_id[(k[1], k[2])], kids[k[1]]))
            extra = ""
            if el["attrs"].get("alt"):
                extra += " /Alt %s" % pdf_str(pdf_ascii(el["attrs"]["alt"]))
            if el["attrs"].get("scope"):
                extra += " /A << /O /Table /Scope /%s >>" % el["attrs"]["scope"]
            objs[ids[id(el)] - 1] = ("<< /Type /StructElem /S /%s /P %d 0 R /K [%s]%s >>" % (
                el["tag"], parent, " ".join(parts), extra)).encode("latin-1")
            for k in el["kids"]:
                if isinstance(k, dict):
                    write(k, ids[id(el)])
        write(self.root, tree_root)
        nums = []
        for pi, p in enumerate(self.pages):
            nums.append("%d [%s]" % (pi, " ".join("%d 0 R" % ids[id(e)] for e in p["marks"])))
        for key, el in annot_parent:
            nums.append("%d %d 0 R" % (key, ids[id(el)]))
        ptree = add(("<< /Nums [%s] >>" % " ".join(nums)).encode("latin-1"))
        objs[tree_root - 1] = ("<< /Type /StructTreeRoot /K %d 0 R /ParentTree %d 0 R /ParentTreeNextKey %d >>" % (
            ids[id(self.root)], ptree, len(self.pages) + len(annot_parent))).encode("latin-1")
        objs[pages_id - 1] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % k for k in kids), len(kids))).encode()
        meta = meta or {}
        now = report_time()
        stamp = now.strftime("D:%Y%m%d%H%M%S+00'00'")
        iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        fields = {
            "Title": self.title,
            "Author": "%s (%s)" % (BRAND_NAME, HOME_URL),
            "Subject": meta.get("subject", "Security check report"),
            "Keywords": meta.get("keywords", "PrivacySafe, security, vulnerability"),
            "Creator": "%s %s, %s (%s)" % (NAME, VERSION, BRAND_NAME, SITE_URL),
            "Producer": "%s %s (%s)" % (NAME, VERSION, HOME_URL),
        }
        x = lambda v: html.escape(pdf_ascii(v), quote=False)
        xmp = ('<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
               '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
               '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
               'xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:xmpRights="http://ns.adobe.com/xap/1.0/rights/">'
               '<dc:format>application/pdf</dc:format>'
               '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:title>'
               '<dc:creator><rdf:Seq><rdf:li>%s</rdf:li></rdf:Seq></dc:creator>'
               '<dc:description><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:description>'
               '<dc:publisher><rdf:Bag><rdf:li>%s</rdf:li></rdf:Bag></dc:publisher>'
               '<dc:language><rdf:Bag><rdf:li>en-US</rdf:li></rdf:Bag></dc:language>'
               '<xmp:CreatorTool>%s</xmp:CreatorTool><xmp:CreateDate>%s</xmp:CreateDate><xmp:ModifyDate>%s</xmp:ModifyDate>'
               '<xmp:MetadataDate>%s</xmp:MetadataDate><pdf:Producer>%s</pdf:Producer><pdf:Keywords>%s</pdf:Keywords>'
               '<xmpRights:WebStatement>%s</xmpRights:WebStatement>'
               '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>') % (
            x(fields["Title"]), x(fields["Author"]), x(fields["Subject"]), x(BRAND_NAME), x(fields["Creator"]),
            iso, iso, iso, x(fields["Producer"]), x(fields["Keywords"]), x(HOME_URL))
        xb = xmp.encode("utf-8")
        mid = add(b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xb) + xb + b"\nendstream")
        objs[catalog - 1] = ("<< /Type /Catalog /Pages %d 0 R /Metadata %d 0 R /Lang (en-US) /MarkInfo << /Marked true >> "
                             "/StructTreeRoot %d 0 R /ViewerPreferences << /DisplayDocTitle true >> >>" % (pages_id, mid, tree_root)).encode()
        info = add(("<< %s /CreationDate (%s) /ModDate (%s) >>" % (
            " ".join("/%s %s" % (k, pdf_str(pdf_ascii(v))) for k, v in fields.items()), stamp, stamp)).encode("latin-1"))
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, b in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj\n" % i + b + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, catalog, info, xref)
        return bytes(out)


def render_pdf(runs, title, details, paper):
    st = overall(runs)
    hosts = sorted({r["host"] for r in runs})
    d = PDF(paper, title)
    color = {"compromise": "crit", "action": "crit", "review": "warn", "incomplete": "error", "clean": "ok", "empty": "muted"}[st]
    d.text(d.m, d.y - 14, "F2", 14, "Status: " + STATUS_TEXT[st], COLORS.get(color, COLORS["muted"]))
    d.y -= 22
    d.para("%d run(s) on %d host(s): %s." % (len(runs), len(hosts), ", ".join(hosts)), color=COLORS["muted"])
    d.heading("Runs")
    rows = [[r["host"], "%s %s" % (r["tool"], r["version"]), r["command"] or "-", r["result"], str(r["counts"]["crit"]),
             str(r["counts"]["warn"]), applic(r), "%ss" % r["duration"] if r["duration"] is not None else "-"] for r in runs]
    d.table(["Host", "Tool", "Command", "Result", "Crit", "Warn", "Applies", "Time"], rows,
            [13, 27, 10, 11, 6, 6, 9, 8], ["l", "l", "l", "l", "r", "r", "l", "r"])
    d.heading("Needs attention")
    items = attention(runs)
    if not items:
        d.para("Nothing. No run reported a warning, a critical finding or an error.")
    for run, r in items:
        title_s = LABEL[r["level"]] + ("  (%s)" % r["kind"] if r.get("kind") else "") + "  |  %s %s on %s" % (run["tool"], run["command"], run["host"])
        sub = []
        if r.get("cve"):
            sub.append("CVE: " + ", ".join(r["cve"]))
        if r.get("code"):
            sub.append("code " + r["code"])
        if r.get("path"):
            sub.append("path " + r["path"])
        url = r.get("fix") if str(r.get("fix", "")).startswith(("https://", "http://")) else None
        d.item(r["level"], title_s, r["msg"], "; ".join(sub), url)
    acc = accepted_items(runs)
    if acc:
        d.para("Accepted risks (%d), listed in %s and not counted as needing attention:" % (len(acc), ACCEPT["source"]))
        for run, r in acc:
            d.item("info", "Accepted  |  %s %s on %s" % (run["tool"], run["command"], run["host"]), r["msg"],
                   "Reason: " + r["accepted"] + (("; CVE: " + ", ".join(r["cve"])) if r.get("cve") else ""), None)
    idx = cve_index(runs)
    if idx:
        d.heading("CVEs behind the findings")
        for c, where in idx.items():
            d.para("%s: %s" % (c, ", ".join(sorted(where))), size=9.5, gap=1)
    if details:
        d.heading("Details")
        for run in runs:
            d.para("%s %s %s on %s: %s (exit %s)%s" % (run["tool"], run["version"], run["command"], run["host"], run["result"], run["exit"],
                                                        "; nothing to check on this host" if run["applicable"] is False else ""),
                   font="F2", size=10.5, gap=2)
            for r in run["events"]:
                if r["type"] == "section":
                    d.para(r["msg"], font="F2", size=9, color=COLORS["muted"], indent=6, gap=1)
                elif r["type"] == "event":
                    lv = r.get("level", "info")
                    d.para("%s  %s" % (LABEL.get(lv, "INFO"), r["msg"]), size=9, indent=12, gap=1,
                           color=COLORS["text"] if lv in ("ok", "info") else COLORS.get(lv, COLORS["text"]))
                elif r["type"] == "applicable":
                    d.para("N/A  " + r["msg"], size=9, indent=12, gap=1, color=COLORS["muted"])
            d.y -= 6
    d.heading("About this report", size=12)
    d.para("%s made this report from the records its tools wrote with --output jsonl. %s" % (BRAND_NAME, CAUTION), size=9)
    d.para(STANDARDS_NOTE, size=9)
    d.linked([("Questions and other issues: ", None), (HELP, "mailto:" + HELP), (" ", None, True), ("(GPG %s)." % HELP_GPG, None, True)])
    d.linked([("Report security issues in these tools to ", None), (CONTACT, "mailto:" + CONTACT), (" ", None, True),
              ("(GPG %s)." % CONTACT_GPG, None, True)])
    d.linked([("Tools, guides and every finding's page: ", None), (SITE_URL, SITE_URL)])
    cves = list(cve_index(runs))
    meta = {"subject": "%s: %d run(s) on %d host(s) (%s), generated %s" % (STATUS_TEXT[st], len(runs), len(hosts), ", ".join(hosts), now_utc()),
            "keywords": ", ".join(["PrivacySafe", "security check", "vulnerability"] + sorted({r["tool"] for r in runs}) + cves[:20])}
    return d.build(meta)


# ---------- main -------------------------------------------------------------------------------
def usage():
    text = open(os.path.abspath(__file__), encoding="utf-8").read().split("\n")
    out = []
    for line in text[1:]:
        if not line.startswith("#"):
            break
        out.append(line[2:] if line.startswith("# ") else "")
    return "\n".join(out[3:]).strip() + "\n"


def main(argv):
    refuse_untrusted_root([__file__])
    fmt, out, title, paper, details, fail_on, paths, accept = "summary", None, "Security check report", "letter", True, None, [], None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            sys.stdout.write(usage())
            return 0
        if a in ("-V", "--version"):
            print("%s %s (%s)" % (NAME, VERSION, DATE))
            return 0
        if a in ("--format", "--out", "--title", "--paper", "--fail-on", "--accept"):
            if i + 1 >= len(argv):
                print("%s needs a value" % a, file=sys.stderr)
                return 2
            v = argv[i + 1]
            i += 2
            if a == "--format":
                if v not in ("summary", "text", "md", "html", "pdf", "jsonl", "ecs"):
                    print("--format: summary, text, md, html, pdf, jsonl or ecs", file=sys.stderr)
                    return 2
                fmt = v
            elif a == "--out":
                out = v
            elif a == "--title":
                title = v
            elif a == "--accept":
                accept = v
            elif a == "--paper":
                if v not in ("letter", "a4"):
                    print("--paper: letter or a4", file=sys.stderr)
                    return 2
                paper = v
            else:
                if v not in ("crit", "warn"):
                    print("--fail-on: crit or warn", file=sys.stderr)
                    return 2
                fail_on = v
            continue
        if a == "--no-details":
            details = False
            i += 1
            continue
        if a.startswith("-") and a != "-":
            print("unknown option: %s" % a, file=sys.stderr)
            return 2
        paths.append(a)
        i += 1
    root_note("psf-report only reads records and writes a report, and needs root only for records readable by root "
              "alone; for other records, run it as a regular account")
    if accept:
        try:
            load_accepted(accept)
        except ConfigError as e:
            print("--accept: %s" % e, file=sys.stderr)
            return 2
    try:
        runs, skipped = read_inputs([p for p in paths if p != "-"])
    except OSError as e:
        print("cannot read: %s" % e, file=sys.stderr)
        return 2
    if skipped:
        print("%d line(s) were not records and were skipped" % skipped, file=sys.stderr)
    if not runs:
        print("no records: give the output of a script run with --output jsonl", file=sys.stderr)
        return 2
    if fmt == "pdf":
        data = render_pdf(runs, title, details, paper)
    elif fmt == "jsonl":
        data = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for run in runs for r in run["records"]).encode()
    elif fmt == "ecs":
        data = render_ecs(runs)
    else:
        data = {"summary": render_summary, "text": render_text, "md": render_md, "html": render_html}[fmt](runs, title, details).encode("utf-8")
    if out:
        write_private(out, data)
    else:
        if fmt == "pdf" and sys.stdout.isatty():
            print("a PDF is not written to a terminal: use --out FILE or redirect", file=sys.stderr)
            return 2
        sys.stdout.buffer.write(data)
    if fail_on:
        levels = ("crit",) if fail_on == "crit" else ("crit", "warn")
        if any(run["counts"][lv] for run in runs for lv in levels):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# Assisted-by: Claude Opus 5.5
