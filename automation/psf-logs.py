#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: psf-logs lists the security check logs, keeps them for as long as you choose,
# and clears them.
# Donate: https://privacysafe.foundation/donate
#
# Usage:
#   psf-logs.py list                       every day folder: its status, runs, files and size, and the total
#   psf-logs.py prune [--keep-days N]      remove the day folders older than N days (default: KEEP_DAYS in psf.conf,
#                                          else 90); keep the rest
#   psf-logs.py clear --yes                remove every day folder
#
#   --dir FOLDER        the log folder (default: LOG_DIR in /etc/psf-security-patches/psf.conf, PSF_LOG_DIR, or
#                       /var/log/psf-security-patches)
#   --dry-run           prune and clear: say what would be removed, remove nothing
#   -q, --quiet         prune and clear: print only what needs a person (a folder left in place, an error);
#                       for cron, which mails whatever a job prints. Removals still go to syslog
#   --now DATE          judge ages as of DATE (2026-11-25) instead of today (UTC)
#   --color WHEN        list: auto (default: on a terminal, unless NO_COLOR is set), always or never
#   -h, --help          this help
#   -V, --version       the version
#
# The folder is the layout psf-run writes: one folder per day, named
# YYYY-MM-DD, holding the .jsonl records and the reports of that day. Only such day folders, holding plain
# files, are removed: anything else in the log folder, a day folder holding a folder or another kind of file,
# and every symbolic link are reported and left alone (a link inside a day folder is removed as a link; what it
# points to is never touched). The log folder must be a real folder that only its owner can write to. Every
# removal is written to syslog (facility authpriv) as well as to the output: removing logs is a security event.
# PSF_READ_ONLY=1 refuses prune and clear.
#
# Exit 0 = done (or nothing to do), 1 = something could not be removed and was left in place, 2 = a usage error
# or a refusal (an unsafe log folder, read-only mode, clear without --yes).
import datetime
import importlib.util
import os
import re
import stat
import sys

sys.dont_write_bytecode = True          # psf-logs writes nothing but the removals it is asked for
NAME, VERSION, DATE = "psf-logs.py", "1.0.0", "2026-11-25"
DEFAULT_DIR = "/var/log/psf-security-patches"     # LOG_DIR from psf.conf or PSF_LOG_DIR replaces it in main()
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DEFAULT_KEEP = 90

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


def usage():
    out = []
    for line in open(os.path.realpath(__file__), encoding="utf-8").read().split("\n")[1:]:
        if not line.startswith("#"):
            break
        out.append(line[2:] if line.startswith("# ") else "")
    return "\n".join(out[4:]).strip() + "\n"


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def note(msg):
    """A removal goes to syslog as well as to the output."""
    try:
        import syslog
        syslog.openlog("psf-logs", 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE, msg)
        syslog.closelog()
    except (ImportError, OSError):
        pass


def safe_base(base, changing):
    """The log folder's file descriptor, opened without following a link, or (None, why not)."""
    try:
        st = os.lstat(base)
    except FileNotFoundError:
        return None, "no log folder at %s: nothing has been logged here yet" % base
    except PermissionError:
        return None, "cannot read %s: permission denied. The logs are readable by root only: run it with sudo." % base
    if stat.S_ISLNK(st.st_mode):
        return None, "%s is a symbolic link: refusing to work through it" % base
    if not stat.S_ISDIR(st.st_mode):
        return None, "%s is not a folder" % base
    if changing and st.st_mode & 0o022:
        return None, "%s can be written by accounts other than its owner (mode %o): refusing to remove anything in it" % (
            base, stat.S_IMODE(st.st_mode))
    if changing and os.geteuid() == 0 and st.st_uid != 0:
        return None, "%s is not owned by root: refusing to remove anything in it as root" % base
    try:
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except PermissionError:
        return None, "cannot read %s: permission denied. The logs are readable by root only: run it with sudo." % base
    return fd, None


def day_folders(base_fd):
    """(name, kind) for each entry: kind is 'day' for a real YYYY-MM-DD folder, else why it is left alone."""
    out = []
    for e in sorted(os.listdir(base_fd)):
        st = os.lstat(e, dir_fd=base_fd)
        if not DAY.match(e):
            out.append((e, "not a day folder"))
        elif stat.S_ISLNK(st.st_mode):
            out.append((e, "a symbolic link, not a folder"))
        elif not stat.S_ISDIR(st.st_mode):
            out.append((e, "not a folder"))
        else:
            out.append((e, "day"))
    return out


def day_contents(base_fd, name):
    """(plain files, links, other entries, total bytes) in a day folder, without following anything."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
    try:
        files, links, other, size = [], [], [], 0
        for e in os.listdir(fd):
            st = os.lstat(e, dir_fd=fd)
            if stat.S_ISLNK(st.st_mode):
                links.append(e)
            elif stat.S_ISREG(st.st_mode):
                files.append(e)
                size += st.st_size
            else:
                other.append(e)
        return files, links, other, size
    finally:
        os.close(fd)


def remove_day(base_fd, name, base, dry):
    """Remove one day folder: its plain files and links, then the folder. Returns (removed?, message)."""
    files, links, other, size = day_contents(base_fd, name)
    if other:
        return False, "%s left in place: it holds %s, which psf-logs does not remove" % (name, ", ".join(sorted(other)))
    if dry:
        return True, "would remove %s (%d file%s, %s)" % (name, len(files) + len(links), "" if len(files) + len(links) == 1 else "s", human(size))
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
    try:
        for e in files + links:
            os.unlink(e, dir_fd=fd)             # a link is removed as a link: what it points to is not touched
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=base_fd)
    msg = "removed %s/%s (%d file%s, %s)" % (base, name, len(files) + len(links), "" if len(files) + len(links) == 1 else "s", human(size))
    note(msg)
    return True, msg


COLOR = {"compromise": "\033[1;31m", "action": "\033[1;31m", "review": "\033[1;33m", "incomplete": "\033[1;35m",
         "clean": "\033[1;32m", "empty": "\033[2m"}


def cmd_list(base, base_fd, use_color=False):
    rows, total, n = [], 0, 0
    for name, kind in day_folders(base_fd):
        if kind != "day":
            rows.append("  %-10s  %s: left alone" % (name, kind))
            continue
        files, links, other, size = day_contents(base_fd, name)
        total += size
        n += 1
        recs = [os.path.join(base, name, f) for f in sorted(files) if f.endswith(".jsonl")]
        try:
            runs, _ = R.read_inputs(recs) if recs else ([], 0)
            runs = R.latest_runs(runs)
            key = R.overall(runs) if runs else "empty"
            st = R.STATUS_TEXT[key] if runs else "no records"
        except OSError:
            runs, st, key = [], "unreadable", "incomplete"
        crit = sum(r["counts"]["crit"] for r in runs)
        warn = sum(r["counts"]["warn"] for r in runs)
        shown = ("%s%-20s\033[0m" % (COLOR[key], st)) if use_color else "%-20s" % st
        rows.append("  %-10s  %s  %3d run%s  %3d crit  %3d warn  %3d file%s  %9s%s" % (
            name, shown, len(runs), " " if len(runs) == 1 else "s", crit, warn, len(files) + len(links),
            " " if len(files) + len(links) == 1 else "s", human(size), ("  also holds: " + ", ".join(sorted(other))) if other else ""))
    print("Security check logs in %s: %d day%s, %s" % (base, n, "" if n == 1 else "s", human(total)))
    if rows:
        print("")
        print("\n".join(reversed(rows)))
    return 0


def cmd_remove(base, base_fd, cutoff, dry, everything, quiet=False):
    removed, left, out = 0, 0, []
    for name, kind in day_folders(base_fd):
        if kind != "day":
            if DAY.match(name):
                out.append("%s left in place: %s" % (name, kind))
            continue
        if not everything and name >= cutoff:
            continue
        ok, msg = remove_day(base_fd, name, base, dry)
        out.append(msg)
        if ok:
            removed += 1
        else:
            left += 1
    if quiet:
        for m in out:
            if " left in place" in m:
                print(m)
        return 1 if left else 0
    if not out:
        print("nothing to remove in %s" % base + ("" if everything else " (nothing older than %s)" % cutoff))
    else:
        print("\n".join(out))
        print("%s %d day folder%s%s" % ("would remove" if dry else "removed", removed, "" if removed == 1 else "s",
                                        ("; %d left in place" % left) if left else ""))
    return 1 if left else 0


def main(argv):
    global DEFAULT_DIR, DEFAULT_KEEP
    load_report()
    try:
        conf = R.load_config()[0]
        DEFAULT_DIR, DEFAULT_KEEP = conf["LOG_DIR"], int(conf["KEEP_DAYS"])
    except (R.ConfigError, OSError) as e:
        print("configuration: %s" % e, file=sys.stderr)
        return 2
    cmd, base, keep, dry, yes, now, color, quiet = None, DEFAULT_DIR, DEFAULT_KEEP, False, False, None, "auto", False
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
            if a in ("list", "prune", "clear") and cmd is None:
                cmd = a
            elif a == "--dry-run":
                dry = True
            elif a == "--yes":
                yes = True
            elif a in ("-q", "--quiet"):
                quiet = True
            elif a in ("--keep-days", "--dir", "--now", "--color"):
                if i + 1 >= len(argv):
                    raise ValueError("%s needs a value" % a)
                v = argv[i + 1]
                i += 1
                if a == "--keep-days":
                    keep = int(v)
                    if keep < 1:
                        raise ValueError("--keep-days must be 1 or more: today's logs are always kept")
                elif a == "--dir":
                    base = v
                elif a == "--color":
                    if v not in ("auto", "always", "never"):
                        raise ValueError("--color: auto, always or never")
                    color = v
                else:
                    now = datetime.datetime.strptime(v, "%Y-%m-%d").date()
            else:
                raise ValueError("unknown command or option: %s" % a)
            i += 1
    except ValueError as e:
        print(str(e).replace("invalid literal for int() with base 10", "not a whole number"), file=sys.stderr)
        return 2
    if cmd is None:
        print("give a command: list, prune or clear (--help says more)", file=sys.stderr)
        return 2
    changing = cmd in ("prune", "clear") and not dry
    if changing:
        root_note("removing logs that root owns needs it; psf-logs removes only YYYY-MM-DD day folders of plain files, "
                  "never follows a link, and records each removal in syslog")
    else:
        root_note("psf-logs %s only reads, and needs root only because the logs are readable by root alone" % cmd)
    if changing and os.environ.get("PSF_READ_ONLY") == "1":
        print("read-only mode (PSF_READ_ONLY=1): %s refused; nothing was removed" % cmd, file=sys.stderr)
        return 2
    if cmd == "clear" and not yes and not dry:
        print("clear removes every day of logs: add --yes to do it, or --dry-run to see what it would remove", file=sys.stderr)
        return 2
    base_fd, why = safe_base(base, changing)
    if base_fd is None:
        if why.startswith("no log folder"):
            if not quiet:
                print(why, file=sys.stderr)
            return 0
        print(why, file=sys.stderr)
        return 2
    try:
        if cmd == "list":
            use = color == "always" or (color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
            return cmd_list(base, base_fd, use)
        today = now or datetime.datetime.now(datetime.timezone.utc).date()
        cutoff = (today - datetime.timedelta(days=keep - 1)).isoformat()   # keep today and the N-1 days before it
        return cmd_remove(base, base_fd, cutoff, dry, cmd == "clear", quiet)
    except PermissionError as e:
        print("permission denied: %s. The logs are readable by root only: run it with sudo." % (e.filename or base), file=sys.stderr)
        return 2
    finally:
        os.close(base_fd)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.exit(1)

# Assisted-by: Claude Opus 5.5
