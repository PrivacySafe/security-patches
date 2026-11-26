#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: psf-run runs the security checks /etc/psf-security-patches/psf.conf names, keeps
# their records and the reports it asks for, removes logs past their retention, and alerts when it matters.
# Donate: https://privacysafe.foundation/donate
#
# Usage:
#   psf-run.py [run]            run the checks now (what cron calls every night: psf-run --quiet)
#   psf-run.py show-config      every setting, where its value came from, and the tools a run would use
#
#   --dry-run           say what a run would do and change nothing
#   -q, --quiet         print only what needs a person (an alert or a problem); for cron, which mails it
#   --config FILE       another configuration file (default /etc/psf-security-patches/psf.conf, or PSF_CONFIG)
#   --now DATE          with --dry-run: plan as of DATE (2026-11-25) instead of today (UTC)
#   -h, --help          this help
#   -V, --version       the version
#
# Settings (all optional; psf.conf.example beside this file explains each): LOG_DIR, KEEP_DAYS, FORMATS (summary,
# text, md, html, pdf; the .jsonl records are always kept), TOOLS (auto: every tool that writes records), ALERT_ON
# (crit, warn or never), ALERT_COMMAND, TIMEOUT (seconds per tool) and ENV (NAME=value settings for the tools).
#
# Each tool runs with PSF_READ_ONLY=1, a fixed PATH, no input, and its own time limit. As root a tool runs only when
# its file and every folder above it are root's and writable by no other account, and the configuration file must
# be root's too: whoever can change either would decide what runs as root. The log folder must be a real folder
# that only its owner can write; each day's records are written into a new folder of their own, never through a
# link. One run at a time: a second waits for nothing and stops.
#
# Exit 0 = the checks ran and nothing needs attention, 1 = something needs attention (ALERT_ON, or a tool failed),
# 2 = a usage or configuration error or a refusal.
import datetime
import fcntl
import importlib.util
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
NAME, VERSION, DATE = "psf-run.py", "1.0.0", "2026-11-25"
_here = os.path.dirname(os.path.realpath(__file__))
INSTALL = os.path.dirname(_here)
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MARKER = open(os.path.join(_here, "output-block.bash"), encoding="utf-8").readline().rstrip("\n")   # the block's first line
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
    global R
    refuse_untrusted_root([__file__, os.path.join(_here, "psf-report.py"), os.path.join(_here, "psf-logs.py")])
    spec = importlib.util.spec_from_file_location("psf_report", os.path.join(_here, "psf-report.py"))
    R = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(R)


def usage():
    out = []
    for line in open(os.path.realpath(__file__), encoding="utf-8").read().split("\n")[1:]:
        if not line.startswith("#"):
            break
        out.append(line[2:] if line.startswith("# ") else "")
    return "\n".join(out[4:]).strip() + "\n"


def writes_records(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return MARKER in f.read()
    except OSError:
        return False


ACCEPT_PROBLEM = []  # why ACCEPT_FILE could not be used, reported with the run
DECLARED = re.compile(r"^# psf-run: (\S+)(?:\s+\((.*)\))?\s*$")
MANUAL = []          # [(relative path, reason)]: tools that declare themselves out of automatic runs


def declared(path):
    """A tool's own word on how psf-run should run it, from a '# psf-run: ...' line near its top: a command
    (check when there is none), none (run with no command), or manual (reason) when it needs input a nightly
    run cannot give. (command, reason) or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for _, line in zip(range(80), fh):
                m = DECLARED.match(line.rstrip("\n"))
                if m:
                    return m.group(1), m.group(2) or ""
    except OSError:
        pass
    return None


def tools(conf):
    """[(relative path, command, why it cannot run or None)] for the run."""
    out = []
    del MANUAL[:]
    if conf["TOOLS"] == "auto":
        for top in ("servers", "system", "runtimes", "web-apps", "developer", "threats"):
            for root, dirs, files in os.walk(os.path.join(INSTALL, top)):
                dirs.sort()
                for f in sorted(files):
                    p = os.path.join(root, f)
                    if f.endswith(".sh") and writes_records(p):
                        d = declared(p)
                        if d and d[0] == "manual":
                            MANUAL.append((os.path.relpath(p, INSTALL), d[1] or "it needs input"))
                        else:
                            out.append((os.path.relpath(p, INSTALL), d[0] if d else "check", None))
        return out
    for t in conf["TOOLS"].replace(",", " ").split():
        rel, _, cmd = t.partition(":")
        p = os.path.join(INSTALL, rel)
        why = None if os.path.isfile(p) else "not found in %s" % INSTALL
        if not why and not writes_records(p):
            why = "does not write records yet (no --output jsonl)"
        out.append((rel, cmd or "check", why))
    return out


def own_folder(path, create):
    """A folder fd for path: a real folder (never a link), this account's, writable by no other. Made, private,
    when missing and create is set (its parent must exist)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise ValueError("%s does not exist" % path)
        os.mkdir(path, 0o700)
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("%s is %s, not a folder: refusing to write through it" % (path, "a symbolic link" if stat.S_ISLNK(st.st_mode) else "not a folder"))
    if st.st_uid != os.geteuid():
        raise ValueError("%s belongs to uid %d, not to this account" % (path, st.st_uid))
    if st.st_mode & 0o022:
        raise ValueError("%s can be written by other accounts (mode %o)" % (path, stat.S_IMODE(st.st_mode)))
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def show_config(conf, src, cfg):
    print("Configuration: %s%s" % (cfg, "" if os.path.exists(cfg) else " (not there: every setting is its default)"))
    for k in R.CONFIG_DEFAULTS:
        v = conf[k] if conf[k] != "" else "(none)"
        print("  %-14s %-40s %s" % (k, v, src[k]))
    print("")
    ts = tools(conf)
    print("Tools a run would use (%d), from %s:" % (sum(1 for t in ts if not t[2]), INSTALL))
    w = max([len(t[0]) for t in ts] + [40]) + 2       # the longest path sets the column
    for rel, cmd, why in ts:
        trust = untrusted_as_root([os.path.join(INSTALL, rel)]) if not why else None
        print("  %-*s %-6s %s" % (w, rel, cmd, why or ("refused as root: " + trust if trust else "ready")))
    if not ts:
        print("  (none: no tool here writes records yet)")
    if MANUAL:
        print("")
        print("Left out of automatic runs, to run by hand (%d):" % len(MANUAL))
        for rel, why in MANUAL:
            print("  %-*s %s" % (w, rel, why))
    return 0


def run_tool(path, cmd, env, day_fd, name, timeout):
    """Run one tool, its records into a new file in the day folder. (exit code or None, problem or None, file)."""
    fd = None
    for n in [name] + ["%s-%s" % (name[:-6], time.strftime("%H%M%S", time.gmtime())) + ".jsonl"]:
        try:
            fd = os.open(n, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=day_fd)
            name = n
            break
        except FileExistsError:
            continue
    if fd is None:
        return None, "cannot make a new records file for it", None
    try:
        p = subprocess.Popen([path] + ([] if cmd == "none" else [cmd]) + ["--output", "jsonl"], stdin=subprocess.DEVNULL, stdout=fd,
                             stderr=subprocess.PIPE, env=env, cwd=INSTALL, start_new_session=True)
        # cwd: the install folder, so a tool that looks in the current folder by default (the GhostAction check
        # scans it for repositories) looks somewhere small and known, never the whole filesystem from /
        try:
            _, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            return None, "stopped after %d seconds (TIMEOUT)" % timeout, name
    finally:
        os.close(fd)
    if p.returncode not in (0, 1):
        first = (err or b"").decode("utf-8", errors="replace").strip().splitlines()[:1]
        return p.returncode, "exit %d%s" % (p.returncode, (": " + R.clip(first[0])[:200]) if first else ""), name
    return p.returncode, None, name


def alert_command(conf, status, host):
    """The ALERT_COMMAND argv, its program found in the system folders only and, as root, root's."""
    if not conf["ALERT_COMMAND"]:
        return None, None
    argv = [a.replace("%h", host).replace("%s", status) for a in shlex.split(conf["ALERT_COMMAND"])]
    prog = argv[0] if "/" in argv[0] else shutil.which(argv[0], path=SAFE_PATH)
    if not prog or not os.access(prog, os.X_OK):
        return None, "ALERT_COMMAND: %s not found in %s" % (argv[0], SAFE_PATH)
    why = untrusted_as_root([prog])
    if why:
        return None, "ALERT_COMMAND refused as root: %s" % why
    return [prog] + argv[1:], None


def main(argv):
    load_report()
    cmd, dry, quiet, cfg, now = "run", False, False, None, None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            sys.stdout.write(usage())
            return 0
        if a in ("-V", "--version"):
            print("%s %s (%s)" % (NAME, VERSION, DATE))
            return 0
        if a in ("run", "show-config"):
            cmd = a
        elif a == "--dry-run":
            dry = True
        elif a in ("-q", "--quiet"):
            quiet = True
        elif a == "--config" and i + 1 < len(argv):
            cfg = argv[i + 1]
            i += 1
        elif a == "--now" and i + 1 < len(argv) and re.match(r"^\d{4}-\d{2}-\d{2}$", argv[i + 1]):
            now = argv[i + 1]
            i += 1
        else:
            print("unknown command or option: %s (--help says more)" % a, file=sys.stderr)
            return 2
        i += 1
    cfg = cfg or R.config_path()
    try:
        conf, src = R.load_config(cfg)
    except (R.ConfigError, OSError) as e:
        print("configuration: %s" % e, file=sys.stderr)
        return 2
    if conf["ACCEPT_FILE"]:
        # a broken accepted-risk file never stops the checks: they run with nothing accepted, and the run reports it
        try:
            R.load_accepted(conf["ACCEPT_FILE"])
        except R.ConfigError as e:
            ACCEPT_PROBLEM.append("ACCEPT_FILE: %s; nothing is accepted in this run" % e)
            print("ACCEPT_FILE: %s; nothing is accepted in this run" % e, file=sys.stderr)
    if cmd == "show-config":
        return show_config(conf, src, cfg)

    root_note("the checks need it to read everything they look at; every tool runs with PSF_READ_ONLY=1, so a run "
              "changes nothing but its own log folder")
    if os.geteuid() != 0 and not quiet:
        print("[!] Not running as root: the checks read only what this account can, so a clean result covers only that.", file=sys.stderr)
    host = socket.gethostname()
    today = now if (now and dry) else datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    log_dir, keep = conf["LOG_DIR"], conf["KEEP_DAYS"]
    formats = conf["FORMATS"].replace(",", " ").split()
    ts = tools(conf)
    logs_tool = [sys.executable, "-I", "-S", os.path.join(_here, "psf-logs.py"), "--dir", log_dir, "--keep-days", keep]

    if dry:
        print("A run now would:")
        print("  remove days older than %s days in %s (psf-logs prune)" % (keep, log_dir))
        print("  write the records into %s/%s/ (a new, private folder)" % (log_dir, today))
        for rel, c, why in ts:
            trust = untrusted_as_root([os.path.join(INSTALL, rel)]) if not why else None
            print("    %s %s --output jsonl%s" % (rel, c, ("  (skipped: %s)" % (why or "refused as root: " + trust)) if (why or trust) else ""))
        print("  write %s" % (", ".join(R.REPORT_FORMATS[f] for f in formats) or "no reports (FORMATS is empty)"))
        print("  alert %s%s" % ({"crit": "on a critical finding or a failed tool", "warn": "on a warning, a critical finding or a failed tool",
                                "never": "never (a failed tool is still reported)"}[conf["ALERT_ON"]],
                               (" through: %s" % conf["ALERT_COMMAND"]) if conf["ALERT_COMMAND"] else " on standard output (cron mails it)"))
        subprocess.run(logs_tool[:4] + ["prune", "--dry-run", "--now", today] + logs_tool[4:], env={"PATH": SAFE_PATH, "PSF_CONFIG": cfg, "PSF_NO_ROOT_NOTE": "1"})
        return 0

    # the log folder, a lock, retention, then today's folder
    try:
        base_fd = own_folder(log_dir, create=True)
    except (ValueError, OSError) as e:
        print("LOG_DIR: %s" % e, file=sys.stderr)
        return 2
    lock = os.open(".psf-run.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=base_fd)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another psf-run is still running in %s: this one stops" % log_dir, file=sys.stderr)
        return 2
    problems = list(ACCEPT_PROBLEM)
    pr = subprocess.run(logs_tool[:4] + ["prune", "--quiet"] + logs_tool[4:], capture_output=True, text=True,
                        env={"PATH": SAFE_PATH, "PSF_CONFIG": cfg, "PSF_NO_ROOT_NOTE": "1"})
    for line in (pr.stdout + pr.stderr).strip().splitlines():
        problems.append("psf-logs: " + line)
    try:
        st = os.lstat(today, dir_fd=base_fd)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            print("%s/%s is not a private folder of this account: refusing to write into it" % (log_dir, today), file=sys.stderr)
            return 2
    except FileNotFoundError:
        os.mkdir(today, 0o700, dir_fd=base_fd)
    day_fd = os.open(today, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
    day_path = os.path.join(log_dir, today)

    env = {"PATH": SAFE_PATH, "HOME": "/root" if os.geteuid() == 0 else os.environ.get("HOME", "/"),
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PSF_READ_ONLY": "1", "PSF_NO_ROOT_NOTE": "1"}
    for item in conf["ENV"].split():
        k, _, v = item.partition("=")
        env[k] = v
    ran, written = 0, []
    for rel, c, why in ts:
        path = os.path.join(INSTALL, rel)
        trust = untrusted_as_root([path]) if not why else None
        if why or trust:
            problems.append("%s: skipped: %s" % (rel, why or "refused as root: " + trust))
            continue
        name = os.path.basename(rel)[:-3] + ("" if c in ("check", "none") else "-" + c) + ".jsonl"
        rc, problem, wrote = run_tool(path, c, env, day_fd, name, int(conf["TIMEOUT"]))
        ran += 1
        if wrote:
            written.append(os.path.join(day_path, wrote))
        if problem:
            problems.append("%s %s: %s" % (rel, c, problem))
        elif not quiet:
            print("  %s %s: %s" % (rel, c, {0: "clean", 1: "findings"}.get(rc, "exit %s" % rc)))
    os.close(day_fd)

    # The reports show the day: the newest run of every tool on this host today. The alert is about this run.
    runs, _ = R.read_inputs([day_path]) if ran else ([], 0)
    runs = R.latest_runs(runs)            # a rerun the same day replaces the earlier result
    now_runs = R.read_inputs(written)[0] if written else []
    status = R.overall(now_runs) if now_runs else "empty"
    for f in (formats if runs else []):         # no records, no reports: the alert says why
        try:
            if f == "pdf":
                data = R.render_pdf(runs, "Security check report", True, "letter")
            elif f == "ecs":
                data = R.render_ecs(runs)
            else:
                data = {"summary": R.render_summary, "text": R.render_text, "md": R.render_md, "html": R.render_html}[f](
                    runs, "Security check report", True).encode("utf-8")
            R.write_private(os.path.join(day_path, R.REPORT_FORMATS[f]), data)
        except Exception as e:        # a report that fails must not hide the run: say so and go on
            problems.append("%s report: %s" % (f, e))
    lvl = {"crit": ("compromise", "action"), "warn": ("compromise", "action", "review", "incomplete"), "never": ()}[conf["ALERT_ON"]]
    alerting = status in lvl or bool(problems)
    if alerting:
        text = (R.render_summary(now_runs, "Security check on %s" % host, True) if now_runs else "Security check on %s: no run wrote records\n" % host)
        if problems:
            text += "\nProblems with the run itself:\n" + "".join("  %s\n" % p for p in problems)
        sys.stdout.write(text)
        argv2, err = alert_command(conf, R.STATUS_TEXT[status], host)
        if err:
            print(err, file=sys.stderr)
        elif argv2:
            try:
                subprocess.run(argv2, input=text.encode("utf-8"), env={"PATH": SAFE_PATH}, timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as e:
                print("ALERT_COMMAND failed: %s" % e, file=sys.stderr)
    elif not quiet:
        print("%s: %s; records and reports in %s" % (host, R.STATUS_TEXT[status], day_path))
    os.close(lock)
    os.close(base_fd)
    return 1 if alerting else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.exit(1)

# Assisted-by: Claude Opus 5.5
