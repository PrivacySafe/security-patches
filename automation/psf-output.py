#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: keep the structured-output block identical in every script.
# Donate: https://privacysafe.foundation/donate
#
#   automation/psf-output.py --check [SCRIPT...]   exit 1 if a script's block differs from the source
#   automation/psf-output.py --write SCRIPT...      add the block to these scripts, or refresh it
#
# The block (automation/output-block.bash) goes right after the script's last one-line output helper
# (ok, info, inf, warn, caution, step, bad, die and the rest), so that it can redefine them. Inside
# lock_for_change, right after the line that decides the command changes the host and just before the lock
# is taken, it adds psf_refuse_change: read-only mode then stops every command the script itself treats as a
# change, even one the block does not know by name, and never a command that only reads.
# Without SCRIPT arguments, --check looks at every script that already has the block.
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BLOCK = open(os.path.join(HERE, "output-block.bash"), encoding="utf-8").read()
BEGIN = BLOCK.splitlines()[0]
END = BLOCK.rstrip("\n").splitlines()[-1]
HELPERS = r"(ok|pass|info|inf|inf_hunt|note|tip|warn|caution|bad|fail|step|section|die)"
HELPER_LINE = re.compile(r"^" + HELPERS + r"\(\)\s*\{.*\}\s*$")
GUARD = '    psf_refuse_change "lock_for_change"'
CATEGORIES = ("servers", "system", "runtimes", "web-apps", "developer", "threats")


def apply(text):
    """The script's text with the block and the guard in place."""
    lines = text.split("\n")
    if BEGIN in lines:
        b = lines.index(BEGIN)
        e = lines.index(END, b)
        lines[b:e + 1] = BLOCK.rstrip("\n").split("\n")
    else:
        last = None
        for i, l in enumerate(lines[:400]):
            if HELPER_LINE.match(l):
                last = i
        if last is None:
            raise SystemExit("no one-line output helpers in the first 400 lines")
        lines[last + 1:last + 1] = [""] + BLOCK.rstrip("\n").split("\n")
    # The guard goes inside lock_for_change right after the line that decides the command changes the host
    # (every other command returns there without the lock), so read-only commands are never refused.
    lines = [l for l in lines if l != GUARD]
    out, in_lock, placed = [], False, 0
    for l in lines:
        out.append(l)
        if re.match(r"^lock_for_change\(\)\s*\{\s*$", l):
            in_lock = True
        elif in_lock and re.match(r"^\s+\[\[ \$lk_hit -eq 1 \]\] \|\| return 0\s*$", l):
            out.append(GUARD)
            placed += 1
            in_lock = False
        elif in_lock and l.startswith("}"):
            raise SystemExit("lock_for_change has no '[[ $lk_hit -eq 1 ]] || return 0' line to place the read-only guard after")
    if any(re.match(r"^lock_for_change\(\)", l) for l in lines) and placed != 1:
        raise SystemExit("the read-only guard was not placed exactly once in lock_for_change")
    return "\n".join(out)


def scripts_with_block():
    found = []
    for c in CATEGORIES:
        for dp, _, fs in os.walk(os.path.join(ROOT, c)):
            for f in fs:
                p = os.path.join(dp, f)
                if f.endswith(".sh") and BEGIN in open(p, encoding="utf-8", errors="replace").read():
                    found.append(p)
    return sorted(found)


def main(argv):
    if len(argv) < 2 or argv[1] not in ("--check", "--write"):
        print(__doc__ or "usage: psf-output.py --check|--write [SCRIPT...]", file=sys.stderr)
        return 2
    paths = argv[2:] or (scripts_with_block() if argv[1] == "--check" else [])
    if not paths:
        print("no scripts given", file=sys.stderr)
        return 2
    stale = []
    for p in paths:
        old = open(p, encoding="utf-8").read()
        new = apply(old)
        if new != old:
            if argv[1] == "--write":
                st = os.stat(p)
                fd, tmp = tempfile.mkstemp(prefix=".psf-output.", suffix=".tmp", dir=os.path.dirname(os.path.abspath(p)))
                with os.fdopen(fd, "w", encoding="utf-8") as f:   # a new file of its own: never a planted link
                    f.write(new)
                os.chmod(tmp, st.st_mode & 0o7777)
                os.replace(tmp, p)
            stale.append(os.path.relpath(p, ROOT))
    if argv[1] == "--check":
        for p in stale:
            print("out of date: " + p)
        print("%d of %d scripts carry the current block" % (len(paths) - len(stale), len(paths)))
        return 1 if stale else 0
    print("written: %d of %d scripts changed" % (len(stale), len(paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# Assisted-by: Claude Opus 5.5
