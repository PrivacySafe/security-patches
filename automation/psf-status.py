#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: psf-status shows, at a glance, what the newest security check logs say.
# Donate: https://privacysafe.foundation/donate
#
# Usage:
#   psf-status.py [options] [FOLDER|FILE ...]
#
#   With no FOLDER or FILE it reads LOG_DIR from /etc/psf-security-patches/psf.conf (PSF_LOG_DIR overrides it; the
#   default is /var/log/psf-security-patches), in the layout psf-run writes: one folder per day (YYYY-MM-DD)
#   holding a .jsonl file per tool. It shows the newest run of each tool on each host that day, and
#   a line for each earlier day. A folder of .jsonl files, or .jsonl files, are read as they are.
#
#   -n, --lines N       findings to list, most serious first (default 10; 0 lists none)
#   --days N            earlier days to show on the history line (default 7; 0 shows none)
#   --tool NAME         only runs of this tool (magento-check, expat-check, ...); repeat for more
#   --host NAME         only runs on this host; repeat for more
#   --stale HOURS       call the logs stale when the newest run is older than this (default 36)
#   -l, --full          do not shorten lines to the width of the terminal
#   --color WHEN        auto (default: on a terminal, unless NO_COLOR is set), always or never
#   --now TIME          judge ages as of TIME (UTC, 2026-11-25T06:00:00Z) instead of now
#   -h, --help          this help
#   -V, --version       the version
#
# Exit 0 = the newest runs are clean and recent, 1 = something needs attention (a warning, a critical
# finding, an error, a run that could not decide, or stale logs), 2 = a usage or read error, 3 = no records
# found. It reads records only: it runs no check and no program, reads nothing from the network and writes
# nothing. Text from
# the records is shown with control characters removed, so a record cannot send commands to the terminal.
import datetime
import importlib.util
import os
import re
import shutil
import stat
import sys

NAME, VERSION, DATE = "psf-status.py", "1.0.0", "2026-11-25"
DEFAULT_DIR = "/var/log/psf-security-patches"     # LOG_DIR from psf.conf or PSF_LOG_DIR replaces it in main()
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# psf-report.py sits beside this file (also when this file is reached through a link such as /usr/bin/psf-status).
# Loading it must not write a bytecode cache beside it: psf-status writes nothing, least of all into /opt as root.
sys.dont_write_bytecode = True
_here = os.path.dirname(os.path.realpath(__file__))
R = None


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


def load_report():
    """psf-report.py, beside this file, loaded once its files have passed the root check."""
    global R
    refuse_untrusted_root([__file__, os.path.join(_here, "psf-report.py")])
    spec = importlib.util.spec_from_file_location("psf_report", os.path.join(_here, "psf-report.py"))
    R = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(R)

COLOR = {"red": "\033[1;31m", "yellow": "\033[1;33m", "magenta": "\033[1;35m", "green": "\033[1;32m",
         "grey": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}
STATUS_COLOR = {"compromise": "red", "action": "red", "review": "yellow", "incomplete": "magenta", "clean": "green",
                "empty": "grey", "stale": "yellow"}


def usage():
    out = []
    for line in open(os.path.realpath(__file__), encoding="utf-8").read().split("\n")[1:]:
        if not line.startswith("#"):
            break
        out.append(line[2:] if line.startswith("# ") else "")
    return "\n".join(out[3:]).strip() + "\n"


def jsonl_in(folder):
    return sorted(os.path.join(folder, f) for f in os.listdir(folder)
                  if f.endswith(".jsonl") and os.path.isfile(os.path.join(folder, f)))


def find_sets(paths):
    """(label, newest set of files, [(label, files) of earlier days, newest first])."""
    if not paths:
        if not os.path.exists(DEFAULT_DIR):
            return DEFAULT_DIR, [], []              # nothing has written logs here yet: no records, not an error
        paths = [DEFAULT_DIR]
    if len(paths) == 1 and os.path.isdir(paths[0]) and not jsonl_in(paths[0]):
        top = paths[0]
        days = sorted((d for d in os.listdir(top) if DAY.match(d) and os.path.isdir(os.path.join(top, d))), reverse=True)
        days = [(os.path.join(top, d), jsonl_in(os.path.join(top, d))) for d in days]
        days = [(d, f) for d, f in days if f]
        if not days:
            return None, [], []
        return days[0][0], days[0][1], days[1:]
    files = []
    for p in paths:
        files.extend(jsonl_in(p) if os.path.isdir(p) else [p])
    return ", ".join(paths), files, []


def parse_ts(s):
    """A time, read as leniently as psf-report reads it (RFC 3339 or ISO 8601, any offset or fraction, or epoch)."""
    return R.parse_time(s)


def ago(delta):
    s = int(delta.total_seconds())
    if s < 0:
        return "in the future"
    if s < 60:
        return "%ds ago" % s
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return "%dd %dh ago" % (d, h)
    if h:
        return "%dh %dmin ago" % (h, m)
    return "%dmin ago" % m


def load(files, tools, hosts):
    runs, skipped = R.read_inputs(files) if files else ([], 0)
    runs = R.latest_runs(runs)
    if tools:
        runs = [r for r in runs if r["tool"] in tools]
    if hosts:
        runs = [r for r in runs if r["host"] in hosts]
    return runs, skipped


def main(argv):
    global DEFAULT_DIR
    load_report()
    try:
        _conf = R.load_config()[0]
        DEFAULT_DIR = _conf["LOG_DIR"]
    except (R.ConfigError, OSError) as e:
        print("configuration: %s" % e, file=sys.stderr)
        return 2
    if _conf["ACCEPT_FILE"]:
        try:
            R.load_accepted(_conf["ACCEPT_FILE"])
        except R.ConfigError as e:
            print("ACCEPT_FILE: %s; every finding is shown as found" % e, file=sys.stderr)
    lines_n, days_n, tools, hosts, stale_h, full, color, now, paths = 10, 7, [], [], 36.0, False, "auto", None, []
    i = 1
    try:
        while i < len(argv):
            a = argv[i]
            if a in ("-h", "--help"):
                sys.stdout.write(usage())
                return 0
            if a in ("-V", "--version"):
                print("%s %s (%s)" % (NAME, VERSION, DATE))
                return 0
            if a in ("-l", "--full"):
                full = True
                i += 1
                continue
            if a in ("-n", "--lines", "--days", "--tool", "--host", "--stale", "--color", "--now"):
                if i + 1 >= len(argv):
                    raise ValueError("%s needs a value" % a)
                v = argv[i + 1]
                i += 2
                if a in ("-n", "--lines"):
                    lines_n = int(v)
                elif a == "--days":
                    days_n = int(v)
                elif a == "--tool":
                    tools.append(v[:-3] if v.endswith(".sh") else v)
                elif a == "--host":
                    hosts.append(v)
                elif a == "--stale":
                    stale_h = float(v)
                elif a == "--color":
                    if v not in ("auto", "always", "never"):
                        raise ValueError("--color: auto, always or never")
                    color = v
                else:
                    now = parse_ts(v)
                    if now is None:
                        raise ValueError("--now: a UTC time such as 2026-11-25T06:00:00Z")
                if (a in ("-n", "--lines", "--days") and int(v) < 0) or (a == "--stale" and float(v) <= 0):
                    raise ValueError("%s must not be negative" % a)
                continue
            if a.startswith("-"):
                raise ValueError("unknown option: %s" % a)
            paths.append(a)
            i += 1
    except ValueError as e:
        print(str(e).replace("invalid literal for int() with base 10", "not a whole number"), file=sys.stderr)
        return 2

    root_note("psf-status only reads, and needs root only because the logs are readable by root alone")
    use_color = color == "always" or (color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    enc = (sys.stdout.encoding or "").lower().replace("-", "")
    dot, ring, sep = ("\u25cf", "\u25cb", " \u00b7 ") if enc == "utf8" else ("*", "o", " | ")
    width = None if (full or not sys.stdout.isatty()) else shutil.get_terminal_size((100, 24)).columns
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def c(name, text):
        return COLOR[name] + text + COLOR["off"] if use_color else text

    ansi = re.compile(r"\033\[[0-9;]*m")

    def fit(text):
        """text no wider than the terminal, counting only what shows: color codes are kept whole."""
        if width is None or len(ansi.sub("", text)) <= width:
            return text
        keep, out, shown, i = max(width - 3, 10), [], 0, 0
        while i < len(text) and shown < keep:
            m = ansi.match(text, i)
            if m:
                out.append(m.group(0)); i = m.end(); continue
            out.append(text[i]); shown += 1; i += 1
        return "".join(out) + (COLOR["off"] if use_color else "") + "..."

    try:
        label, files, earlier = find_sets(paths)
        runs, skipped = load(files, tools, hosts)
    except PermissionError as e:
        print("cannot read %s: %s. The logs are readable by root only: run it with sudo." % (e.filename, e.strerror), file=sys.stderr)
        return 2
    except OSError as e:
        print("cannot read %s: %s" % (getattr(e, "filename", "") or "the logs", e.strerror or e), file=sys.stderr)
        return 2
    if not runs:
        where = label or (", ".join(paths) if paths else DEFAULT_DIR)
        print("No security check records in %s." % where, file=sys.stderr)
        print("psf-run writes them there every night (see the automation guide), or run a tool with --output jsonl.", file=sys.stderr)
        return 3

    st = R.overall(runs)
    hosts_seen = sorted({r["host"] for r in runs})
    times = [t for t in (r.get("started_dt") or parse_ts(r["started"]) for r in runs) if t]
    newest = max(times) if times else None
    stale = newest is not None and (now - newest).total_seconds() > stale_h * 3600
    shown = "stale" if stale and st == "clean" else st
    head = R.STATUS_TEXT[st] + (", but the logs are stale" if stale and st == "clean" else "")
    who = R.clip(hosts_seen[0]) if len(hosts_seen) == 1 else "%d hosts" % len(hosts_seen)
    out = [fit("%s Security checks on %s: %s" % (c(STATUS_COLOR[shown], dot), who, c("bold", head)))]
    out.append(fit("      Logs: %s (%d run%s)%s" % (R.clip(label), len(runs), "" if len(runs) == 1 else "s",
                                                 (", newest of %d days" % (len(earlier) + 1)) if earlier else "")))
    if newest:
        out.append(fit("  Last run: %s; %s" % (newest.strftime("%a %Y-%m-%d %H:%M:%S UTC"), ago(now - newest))))
    if stale:
        out.append(c("yellow", fit("     Stale: no run in the last %g hours: is the daily check still running?" % stale_h)))
    if len(hosts_seen) > 1:
        out.append(fit("     Hosts: %s" % R.clip(", ".join(hosts_seen))))
    tot = {k: sum(r["counts"][k] for r in runs) for k in ("crit", "warn", "error")}
    flagged = sum(1 for r in runs if r["counts"]["crit"] or r["counts"]["warn"] or r["counts"]["error"])
    na = sum(1 for r in runs if r["applicable"] is False)
    parts = []
    for k, one, many in (("crit", "critical finding", "critical findings"), ("warn", "warning", "warnings"), ("error", "error", "errors")):
        if tot[k]:
            parts.append("%d %s" % (tot[k], one if tot[k] == 1 else many))
    nruns = "%d run%s" % (len(runs), "" if len(runs) == 1 else "s")
    summary = (", ".join(parts) + " in %d of %s" % (flagged, nruns)) if parts else "nothing found in %s" % nruns
    acc = sum(r["counts"].get("accepted", 0) for r in runs)
    if acc:
        summary += "; %d accepted (%s)" % (acc, R.ACCEPT["source"])
    if na:
        summary += "; %d found nothing to check here" % na
    if skipped:
        summary += "; %d line(s) were not records" % skipped
    out.append(fit("   Summary: %s" % summary))
    out.append("")

    tw = min(max([len(R.clip(r["tool"] + " " + r["version"])) for r in runs] + [4]), 34)
    hw = min(max([len(R.clip(r["host"])) for r in runs] + [4]), 24)
    out.append(fit("    %-*s  %-7s  %-9s  %4s  %4s  %-8s  %s" % (tw, "TOOL", "COMMAND", "RESULT", "CRIT", "WARN", "WHEN", "HOST")))
    for r in sorted(runs, key=lambda x: (-(x["counts"]["crit"] > 0), -(x["counts"]["warn"] > 0), x["applicable"] is False, x["tool"], x["host"])):
        if r["counts"]["crit"] or any(e.get("kind") == "compromise" for e in r["events"]):
            mark = c("red", dot)
        elif r["counts"]["warn"]:
            mark = c("yellow", dot)
        elif r["counts"]["error"] or r["result"] in ("undecided", "incomplete"):
            mark = c("magenta", dot)
        elif r["applicable"] is False:
            mark = c("grey", ring)
        else:
            mark = c("green", dot)
        t = r.get("started_dt") or parse_ts(r["started"])
        line = "  %s %-*s  %-7s  %-9s  %4d  %4d  %-8s  %s" % (
            mark, tw, R.clip(r["tool"] + " " + r["version"])[:tw], R.clip(r["command"])[:7], R.clip(r["result"])[:9],
            r["counts"]["crit"], r["counts"]["warn"], t.strftime("%H:%M:%S") if t else "?", R.clip(r["host"])[:hw])
        if r["applicable"] is False:
            line += "  " + c("grey", "nothing to check here")
        out.append(fit(line))
    items = R.attention(runs)
    if lines_n and items:
        out.append("")
        out.append(fit("Needs attention, most serious first (%d of %d):" % (min(lines_n, len(items)), len(items))))
        lc = {"crit": "red", "error": "magenta", "warn": "yellow"}
        for run, r in items[:lines_n]:
            kind = " (%s)" % R.clip(r["kind"]) if r.get("kind") else ""
            text = "  %-5s%s %s %s: %s" % (R.LABEL[r["level"]], kind, R.clip(run["host"]), R.clip(run["tool"]), R.clip(r["msg"]))
            out.append(fit(c(lc[r["level"]], text[:7]) + text[7:]))
    if earlier and days_n:
        hist = []
        for d, f in earlier[:days_n]:
            try:
                er, _ = load(f, tools, hosts)
            except OSError:
                hist.append("%s unreadable" % os.path.basename(d))
                continue
            if not er:
                continue
            est = R.overall(er)
            n = {k: sum(x["counts"][k] for x in er) for k in ("crit", "warn")}
            extra = ", ".join("%d %s" % (n[k], k) for k in ("crit", "warn") if n[k])
            hist.append("%s %s%s" % (os.path.basename(d), c(STATUS_COLOR[est], R.STATUS_TEXT[est]), " (%s)" % extra if extra else ""))
        if hist:
            out.append("")
            out.append(fit("Earlier: " + sep.join(hist)))
    out.append("")
    target = label if (label and os.path.exists(label)) else " ".join(paths)
    report = os.path.join(_here, "psf-report.py")
    rel = os.path.relpath(report)
    report = "psf-report" if shutil.which("psf-report") else (rel if not rel.startswith("..") else report)
    out.append(fit(c("grey", "Full report: %s --format text %s" % (report, R.clip(target)))))
    sys.stdout.write("\n".join(out) + "\n")
    return 0 if st == "clean" and not stale else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.exit(1)

# Assisted-by: Claude Opus 5.5
