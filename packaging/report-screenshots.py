#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# PrivacySafe Security Patches: the screenshots in automation/examples/screenshots/.
# Donate: https://privacysafe.foundation/donate
#
#   packaging/report-screenshots.py --write    take every screenshot again from the example records and reports
#   packaging/report-screenshots.py --check    exit 1 if a screenshot is missing, is not a PNG, or was taken from
#                                              examples or code that have changed since (MANIFEST.txt says which)
#
# --write needs what a maintainer's machine has and a server does not: Python's playwright with its Chromium
# (the HTML report and the terminal), pdftoppm from poppler-utils (the PDF pages), script from util-linux (a real
# terminal for psf-status) and Pillow (to make the images small). --check needs Python alone.
#
# The terminal shots are psf-status and psf-report run in a 120-column terminal with their real colors and
# line trimming, on the example records laid out as the daily check lays them out; only the folder they were
# read from is shown as /var/log/psf-security-patches. A browser does not draw a page byte for byte the same
# from one version to the next, so --check compares what each screenshot was made from (MANIFEST.txt), not
# the pixels.
import datetime
import hashlib
import html
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(ROOT, "automation", "examples")
SHOTS = os.path.join(EX, "screenshots")
MANIFEST = os.path.join(SHOTS, "MANIFEST.txt")
INPUTS = ["automation/examples/example-records.jsonl", "automation/examples/example-report.html",
          "automation/examples/example-report.pdf", "automation/psf-status.py", "automation/psf-report.py", "automation/psf-logs.py", "automation/psf-run.py",
          "packaging/report-screenshots.py", "web-apps/drupal/drupal-installer-check.sh",
          "system/linux-kernel/linux-kernel-noisytcp-check.sh"]
SHOT_FILES = ["check-drupal-installer.png", "check-noisytcp.png", "psf-status.png", "psf-status-clean.png", "psf-logs.png", "psf-run.png", "psf-report-summary.png", "html-report-light.png",
              "html-report-dark.png", "pdf-report-page-1.png", "pdf-report-last-page.png"]
NOW = "2026-11-25T08:10:00Z"
LOGS = "/var/log/psf-security-patches"


def sha(path):
    return hashlib.sha256(open(os.path.join(ROOT, path), "rb").read()).hexdigest()


def manifest_text():
    lines = ["# What the screenshots were taken from. packaging/report-screenshots.py --check compares these.",
             "# Take them again with packaging/report-screenshots.py --write when one of these files changes."]
    lines += ["%s  %s" % (sha(p), p) for p in INPUTS]
    return "\n".join(lines) + "\n"


def png_size(path):
    b = open(path, "rb").read(33)
    if len(b) < 24 or b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", b[16:24])


def check():
    bad = []
    for f in SHOT_FILES:
        p = os.path.join(SHOTS, f)
        if not os.path.exists(p):
            bad.append("missing: automation/examples/screenshots/" + f)
        elif not png_size(p) or min(png_size(p)) < 100:
            bad.append("not a usable PNG: automation/examples/screenshots/" + f)
    if not os.path.exists(MANIFEST):
        bad.append("missing: automation/examples/screenshots/MANIFEST.txt")
    elif open(MANIFEST, encoding="utf-8").read() != manifest_text():
        old = dict(reversed(l.split("  ", 1)) for l in open(MANIFEST, encoding="utf-8").read().splitlines() if l and not l.startswith("#"))
        changed = [p for p in INPUTS if old.get(p) != sha(p)]
        bad.append("taken from older files: %s changed since" % ", ".join(changed))
    for b in bad:
        print(b)
    if bad:
        print("run packaging/report-screenshots.py --write")
        return 1
    print("the %d screenshots are there and were taken from the current examples and code" % len(SHOT_FILES))
    return 0


ANSI_CSS = {"1;31": "color:#ff6b5e;font-weight:700", "1;33": "color:#f5c542;font-weight:700",
            "1;35": "color:#d38cff;font-weight:700", "1;32": "color:#45c870;font-weight:700",
            "2": "color:#8c8a84", "1": "font-weight:700",
            # the normal-intensity colors the check scripts use (RED, GREEN, YELLOW, CYAN in their common helpers)
            "0;31": "color:#ff6b5e", "0;32": "color:#45c870", "0;33": "color:#f5c542", "0;35": "color:#d38cff", "0;36": "color:#5fc7d8",
            "31": "color:#ff6b5e", "32": "color:#45c870", "33": "color:#f5c542", "35": "color:#d38cff", "36": "color:#5fc7d8"}


COLS = 120     # a common terminal width; psf-status trims its lines to it, as on a real terminal


def ansi_html(text):
    out, depth = [], 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", text.replace("\r", "")):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            if m.group(1) in ("0", ""):
                out.append("</span>" * depth)
                depth = 0
            else:
                out.append('<span style="%s">' % ANSI_CSS.get(m.group(1), ""))
                depth += 1
        else:
            out.append(html.escape(part))
    out.append("</span>" * depth)
    return "".join(out).rstrip("\n")


def terminal_html(prompt, text, more=()):
    """A terminal window, COLS wide: each command after a prompt, its output with its colors carried over."""
    shown = [(prompt, text)] + list(more)
    style = ("body{margin:0;padding:24px;background:#e9e7e1}"
             ".win{display:inline-block;border-radius:10px;overflow:hidden;box-shadow:0 8px 28px rgba(0,0,0,.28);background:#1A1916}"
             ".bar{height:30px;background:#2b2a27;display:flex;align-items:center;padding:0 12px;gap:8px;color:#a9a6a0;"
             "font:12px system-ui,sans-serif}.d{width:12px;height:12px;border-radius:50%}"
             "pre{margin:0;padding:14px 18px 16px;color:#ECEAE4;font:13.5px/1.5 'DejaVu Sans Mono','Liberation Mono',monospace;"
             "width:calc(" + str(COLS) + "ch + 1px);white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all}"
             ".p{color:#FB521F}")
    bar = ("<div class='bar'><span class='d' style='background:#ff5f57'></span><span class='d' style='background:#febc2e'></span>"
           "<span class='d' style='background:#28c840'></span><span style='margin-left:10px'>root@web1: ~</span></div>")
    body = "\n\n".join("<span class='p'>$</span> " + html.escape(p) + "\n" + ansi_html(t) for p, t in shown)
    return "<!doctype html><meta charset='utf-8'><style>" + style + "</style><div class='win'>" + bar + "<pre>" + body + "</pre></div>"


def run_in_terminal(cmd, env, cols=None):
    cols = cols or COLS
    t = subprocess.run(["script", "-qc", "stty cols %d rows 50; %s" % (cols, cmd), "/dev/null"],
                       capture_output=True, text=True, env=env)
    return t.stdout


def lay_out_logs(base, records, clean_only=False, older=()):
    """The example records in the daily check's layout: a folder per day, a .jsonl file per tool."""
    src = [json.loads(l) for l in open(records, encoding="utf-8") if l.strip()]
    keep = ("nginx-oct2026-check", "agentic-attack-check")
    days = {"2026-11-25": [r for r in src if not clean_only or r["tool"] in keep],
            "2026-11-24": [r for r in src if r["tool"] in keep],
            "2026-11-23": [r for r in src if not clean_only or r["tool"] in keep]}
    for day in older:
        days[day] = src
    for day, recs in days.items():
        d = os.path.join(base, day)
        os.makedirs(d)
        by = {}
        for r in recs:
            r = dict(r, ts=r["ts"].replace("2026-11-25", day), run=r["run"].replace("20261125", day.replace("-", "")))
            by.setdefault(r["tool"] + "-" + r["host"], []).append(r)
        for k, rs in by.items():
            with open(os.path.join(d, k + ".jsonl"), "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(x) + "\n" for x in rs))


def small_png(path):
    from PIL import Image
    im = Image.open(path).convert("RGB")
    im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)


def write():
    missing = [t for t in ("pdftoppm", "script") if not shutil.which(t)]
    try:
        from playwright.sync_api import sync_playwright
        import PIL  # noqa: F401
    except ImportError as e:
        missing.append(str(e.name))
    if missing:
        print("--write needs %s (see the top of this file)" % ", ".join(missing), file=sys.stderr)
        return 2
    os.makedirs(SHOTS, exist_ok=True)
    with tempfile.TemporaryDirectory() as t:
        bin_dir = os.path.join(t, "bin")
        os.makedirs(bin_dir)
        os.symlink(os.path.join(ROOT, "automation", "psf-report.py"), os.path.join(bin_dir, "psf-report"))
        os.symlink(os.path.join(ROOT, "automation", "psf-status.py"), os.path.join(bin_dir, "psf-status"))
        os.symlink(os.path.join(ROOT, "automation", "psf-logs.py"), os.path.join(bin_dir, "psf-logs"))
        env = dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", PYTHONIOENCODING="utf-8", LANG="C.UTF-8", TERM="xterm-256color")
        env.pop("NO_COLOR", None)
        pages = {}
        for name, clean in (("psf-status.png", False), ("psf-status-clean.png", True)):
            fake = os.path.join(t, "logs-clean" if clean else "logs", "var", "log", "psf-security-patches")
            lay_out_logs(fake, os.path.join(EX, "example-records.jsonl"), clean_only=clean)
            out = run_in_terminal("psf-status --now %s %s" % (NOW, fake), env)
            out = out.replace(os.path.dirname(os.path.dirname(os.path.dirname(fake))), "")
            pages[name] = terminal_html("sudo psf-status", out)
        fake = os.path.join(t, "logs-five", "var", "log", "psf-security-patches")
        lay_out_logs(fake, os.path.join(EX, "example-records.jsonl"), older=("2026-10-30", "2026-08-15"))
        lenv = dict(env, PSF_LOG_DIR=fake)
        prefix = os.path.join(t, "logs-five")
        a = run_in_terminal("psf-logs list", lenv).replace(prefix, "")
        b2 = run_in_terminal("psf-logs prune --keep-days 90 --dry-run --now 2026-11-25", lenv).replace(prefix, "")
        pages["psf-logs.png"] = terminal_html("sudo psf-logs list", a, [("sudo psf-logs prune --keep-days 90 --dry-run", b2)])
        # psf-run pads its columns, so the folder shown as /var/log/psf-security-patches must be as long as that path
        same = tempfile.mkdtemp(prefix="psf-", dir="/tmp")
        same_len = same + "/" + "l" * (len(LOGS) - len(same) - 1)
        shutil.copytree(fake, same_len)
        cfg = os.path.join(t, "psf.conf")
        with open(cfg, "w", encoding="utf-8") as fc:
            # a short TOOLS list, as an admin who picks the checks writes it: with auto, the screenshot would list all 77
            fc.write("LOG_DIR = %s\nKEEP_DAYS = 90\nFORMATS = summary text pdf\nALERT_COMMAND = mail -s \"Security check on %%h: %%s\" root\n"
                     "TOOLS = web-apps/drupal/drupal-installer-check.sh system/linux-kernel/linux-kernel-noisytcp-check.sh "
                     "servers/nginx/nginx-oct2026-check.sh web-apps/magento/magento-check.sh threats/agentic-attacks/agentic-attack-check.sh\n" % same_len)
        renv = dict(env, PSF_CONFIG=cfg)
        os.symlink(os.path.join(ROOT, "automation", "psf-run.py"), os.path.join(bin_dir, "psf-run"))
        def shown(text):
            return text.replace(cfg, "/etc/psf-security-patches/psf.conf").replace(same_len, LOGS).replace(ROOT, "/opt/psf-security-patches")
        c1 = shown(run_in_terminal("psf-run show-config", renv))
        c2 = shown(run_in_terminal("psf-run --dry-run --now 2026-11-25", renv))
        pages["psf-run.png"] = terminal_html("psf-run show-config", c1, [("sudo psf-run --dry-run", c2)])
        shutil.rmtree(same)
        # two of the checks themselves, as an admin runs them: stand-in sites and a stand-in host
        def banner(text):
            return re.sub(r" on \S+ at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", " on web1 at 2026-11-25T08:10:00Z", text)
        www = os.path.join(t, "drupal", "var", "www")
        for name, ver, inst in (("shop", "11.4.12", True), ("news", "11.4.14", False)):
            d = os.path.join(www, name)
            os.makedirs(os.path.join(d, "core", "lib")); os.makedirs(os.path.join(d, "sites", "default"))
            open(os.path.join(d, "core", "lib", "Drupal.php"), "w").write("<?php\nclass Drupal {\n  const VERSION = '%s';\n}\n" % ver)
            if inst:
                open(os.path.join(d, "core", "install.php"), "w").write("<?php\n")
            open(os.path.join(d, "sites", "default", "settings.php"), "w").write("<?php\n")
        denv = dict(env, DRUPAL_ROOTS=www, NGINX_CONF=os.path.join(t, "none"), APACHE_CONF=os.path.join(t, "none"))
        out = run_in_terminal("bash %s check" % os.path.join(ROOT, "web-apps", "drupal", "drupal-installer-check.sh"), denv)
        pages["check-drupal-installer.png"] = terminal_html("sudo ./drupal-installer-check.sh check",
                                                            banner(out.replace(os.path.join(t, "drupal"), "")))
        k = os.path.join(t, "kernel")
        os.makedirs(os.path.join(k, "sys", "net", "ipv4")); os.makedirs(os.path.join(k, "sys", "net", "core"))
        open(os.path.join(k, "sys", "net", "ipv4", "tcp_syncookies"), "w").write("1\n")
        open(os.path.join(k, "sys", "net", "core", "rps_sock_flow_entries"), "w").write("0\n")
        for q in range(4):
            qd = os.path.join(k, "net", "eth0", "queues", "rx-%d" % q); os.makedirs(qd)
            open(os.path.join(qd, "rps_cpus"), "w").write("00000000\n"); open(os.path.join(qd, "rps_flow_cnt"), "w").write("0\n")
        open(os.path.join(k, "os-release"), "w").write("ID=debian\nVERSION_ID=\"12\"\n")
        kenv = dict(env, KERNEL_RELEASE="6.1.0-40-amd64", KERNEL_VERSION_STRING="#1 SMP PREEMPT_DYNAMIC Debian 6.1.191-1 (2026-11-05)",
                    KERNEL_ARCH="x86_64", KERNEL_PROC_SYS=os.path.join(k, "sys"), KERNEL_SYS_NET=os.path.join(k, "net"),
                    OS_RELEASE_FILE=os.path.join(k, "os-release"), KERNEL_CHANGELOG="/dev/null", KERNEL_INSTALLED_RELEASES="none")
        # the stand-in host's listeners, so the count describes the example rather than the machine taking the shot
        ssb = os.path.join(bin_dir, "ss")
        open(ssb, "w").write("#!/bin/sh\nprintf 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\\n"
                             "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\\nLISTEN 0 4096 127.0.0.1:3306 0.0.0.0:*\\n'\n")
        os.chmod(ssb, 0o755)
        out = run_in_terminal("/bin/bash %s check" % os.path.join(ROOT, "system", "linux-kernel", "linux-kernel-noisytcp-check.sh"), kenv)
        pages["check-noisytcp.png"] = terminal_html("sudo ./linux-kernel-noisytcp-check.sh check", banner(out))
        out = run_in_terminal("psf-report %s/2026-11-25" % os.path.join(t, "logs", "var", "log", "psf-security-patches"),
                              dict(env, SOURCE_DATE_EPOCH=str(int(datetime.datetime.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ").replace(
                                  tzinfo=datetime.timezone.utc).timestamp()))))
        pages["psf-report-summary.png"] = terminal_html("psf-report %s/2026-11-25" % LOGS,
                                                        out.replace(os.path.join(t, "logs"), ""))
        with sync_playwright() as p:
            b = p.chromium.launch()
            for name, page in pages.items():
                f = os.path.join(t, name + ".html")
                open(f, "w", encoding="utf-8").write(page)
                pg = b.new_page(viewport={"width": 1200, "height": 900}, device_scale_factor=1)
                pg.goto("file://" + f)
                pg.locator(".win").screenshot(path=os.path.join(SHOTS, name))
                pg.close()
            for scheme in ("light", "dark"):
                pg = b.new_page(viewport={"width": 1100, "height": 1000}, color_scheme=scheme, device_scale_factor=1)
                pg.goto("file://" + os.path.join(EX, "example-report.html"))
                pg.screenshot(path=os.path.join(SHOTS, "html-report-%s.png" % scheme))
                pg.close()
            b.close()
        pdf = os.path.join(EX, "example-report.pdf")
        info = subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout
        last = int(re.search(r"Pages:\s+(\d+)", info).group(1))
        for page, name in ((1, "pdf-report-page-1"), (last, "pdf-report-last-page")):
            subprocess.run(["pdftoppm", "-r", "100", "-f", str(page), "-l", str(page), "-singlefile", "-png", pdf,
                            os.path.join(SHOTS, name)], check=True)
    for f in SHOT_FILES:
        small_png(os.path.join(SHOTS, f))
    open(MANIFEST, "w", encoding="utf-8").write(manifest_text())
    print("took %d screenshots into automation/examples/screenshots/" % len(SHOT_FILES))
    return 0


def main(argv):
    if len(argv) != 2 or argv[1] not in ("--write", "--check"):
        print("usage: report-screenshots.py --write | --check", file=sys.stderr)
        return 2
    return write() if argv[1] == "--write" else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# Assisted-by: Claude Opus 5.5
