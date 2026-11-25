#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: the example records and reports in automation/examples/.
# Donate: https://privacysafe.foundation/donate
#
#   packaging/report-examples.py --write     render the example reports from automation/examples/example-records.jsonl
#   packaging/report-examples.py --check     exit 1 if a rendered example differs from what psf-report gives now
#   packaging/report-examples.py --import --old-host NAME [--path OLD=NEW]... HOST=FILE[,FILE]... [HOST=FILE...]
#                                            make example-records.jsonl from real runs (--output jsonl), then --write
#
# --import keeps every record a tool wrote and replaces only what identifies the machine it ran on: the host name
# (in the host field, the run id and the banner line), the paths given with --path, and the times, which move to
# 25 November 2026 from 06:00 UTC with each run's own spacing kept. It stops if the old host name or an old path
# is still in the result. The reports are rendered with SOURCE_DATE_EPOCH set to a minute after the last record,
# so the same records always give the same files, byte for byte.
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(ROOT, "automation", "examples")
RECORDS = os.path.join(EX, "example-records.jsonl")
REPORT = os.path.join(ROOT, "automation", "psf-report.py")
OUTPUTS = [("summary", "example-summary.txt"), ("text", "example-report.txt"), ("md", "example-report.md"),
           ("html", "example-report.html"),
           ("pdf", "example-report.pdf")]
START = datetime.datetime(2026, 11, 25, 6, 0, 0, tzinfo=datetime.timezone.utc)


def ts_parse(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def ts_fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def import_runs(old_host, paths, groups):
    out, clock, pid = [], START, 4701
    for host, files in groups:
        for f in files:
            recs = [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]
            if not recs or recs[0].get("type") != "start" or recs[-1].get("type") != "verdict":
                raise SystemExit("%s is not one whole run written with --output jsonl" % f)
            t0, t_end = ts_parse(recs[0]["ts"]), ts_parse(recs[-1]["ts"])   # read before the times are rewritten
            run = "%s-%s-%s-%d" % (host, recs[0]["tool"], clock.strftime("%Y%m%dT%H%M%SZ"), pid)
            for r in recs:
                new = clock + (ts_parse(r["ts"]) - t0)
                r["host"], r["run"], r["ts"] = host, run, ts_fmt(new)
                for k in ("msg", "path"):
                    if k in r:
                        v = re.sub(r" on %s at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ" % re.escape(old_host),
                                   " on %s at %s" % (host, ts_fmt(new)), r[k])
                        for a, b in paths:
                            v = v.replace(a, b)
                        r[k] = v
                out.append(r)
            clock = clock + (t_end - t0) + datetime.timedelta(seconds=2)
            pid += 1
    text = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in out)
    leftovers = [w for w in [old_host] + [a for a, _ in paths] if re.search(r"(?<![\w.-])%s(?![\w-])" % re.escape(w), text)]
    if leftovers:
        raise SystemExit("still in the records after the import: %s" % ", ".join(leftovers))
    os.makedirs(EX, exist_ok=True)
    with open(RECORDS, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote %s: %d records from %d runs" % (os.path.relpath(RECORDS, ROOT), len(out), sum(len(f) for _, f in groups)))


def render(folder):
    last = max(ts_parse(json.loads(l)["ts"]) for l in open(RECORDS, encoding="utf-8") if l.strip())
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(int(last.timestamp()) + 60))
    env["PATH"] = "/usr/bin:/bin"         # psf-status names psf-report by its path in the tree, wherever it is installed
    env["PYTHONIOENCODING"] = "utf-8"     # the same dots whatever the locale of the machine that renders it
    with open(os.path.join(folder, "example-status.txt"), "w", encoding="utf-8") as f:
        subprocess.run([sys.executable, os.path.join(ROOT, "automation", "psf-status.py"), "--color", "never",
                        "--now", ts_fmt(last + datetime.timedelta(seconds=60)), os.path.relpath(RECORDS, ROOT)],
                       stdout=f, env=env, cwd=ROOT)
    for fmt, name in OUTPUTS:
        args = [sys.executable, REPORT, "--format", fmt, "--title", "Example security check report", "--out",
                os.path.join(folder, name), RECORDS]
        subprocess.run(args, check=True, env=env)


def main(argv):
    if len(argv) >= 2 and argv[1] == "--import":
        old_host, paths, groups, i = None, [], [], 2
        while i < len(argv):
            a = argv[i]
            if a == "--old-host":
                old_host = argv[i + 1]; i += 2
            elif a == "--path":
                o, n = argv[i + 1].split("=", 1); paths.append((o, n)); i += 2
            else:
                h, files = a.split("=", 1); groups.append((h, files.split(","))); i += 1
        if not old_host or not groups:
            print("--import needs --old-host and at least one HOST=FILE", file=sys.stderr)
            return 2
        import_runs(old_host, paths, groups)
        render(EX)
        print("rendered %d example reports" % len(OUTPUTS))
        return 0
    if len(argv) != 2 or argv[1] not in ("--write", "--check"):
        print("usage: report-examples.py --write | --check | --import ...", file=sys.stderr)
        return 2
    if argv[1] == "--write":
        render(EX)
        print("rendered %d example reports" % len(OUTPUTS))
        return 0
    with tempfile.TemporaryDirectory() as t:
        render(t)
        stale = [n for n in [n for _, n in OUTPUTS] + ["example-status.txt"] if not os.path.exists(os.path.join(EX, n))
                 or open(os.path.join(t, n), "rb").read() != open(os.path.join(EX, n), "rb").read()]
    for n in stale:
        print("out of date: automation/examples/" + n)
    if stale:
        print("run packaging/report-examples.py --write")
        return 1
    print("the %d example reports match what psf-report and psf-status give now" % (len(OUTPUTS) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# Assisted-by: Claude Opus 5.5
