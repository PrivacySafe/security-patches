# nginx: October 2026 security release

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="nginx-october-2026-check"></a>

## nginx October 2026 Check

**Script:** [`nginx/nginx-oct2026-check.sh`](nginx-oct2026-check.sh)

nginx 1.30.6 (stable) and 1.31.7 (mainline), released 14 October 2026, [fix five flaws](https://nginx.org/en/security_advisories.html). Three are memory bugs in a worker process (a crash, and possibly code execution): CVE-2026-15176 (`alias` with a `rewrite`), CVE-2026-93479 (a regex `map` whose captures are used by `root` or `log_format`), and CVE-2026-97205 (`aio` with SSI). One forges a TLS session that can bypass client-certificate checks (CVE-2026-97629, in the automatic rotation of session-ticket keys). One slips extra bytes into a proxied request (CVE-2026-95101, HTTP/3). The `njs` JavaScript module separately shipped 1.0.2 with two XML-module fixes (CVE-2026-101019, CVE-2026-101025). nginx rates all five medium. F5 scores the three memory bugs 9.2 (critical), the TLS flaw 8.3, and the HTTP/3 flaw 6.9. None was reported exploited as of mid-October 2026.

Each flaw needs a specific directive, so a vulnerable nginx version is not necessarily reachable. `check` and `hunt` change nothing. `check` reports the nginx and njs versions on the host and in containers, and audits the running configuration with `nginx -T` for the directive combination each flaw needs, printing F5's workaround for the ones you are exposed to. The fix is to upgrade to 1.30.6 or 1.31.7 (or your distribution's backport) and reload. Nginx publishes fixes for those two branches only, so an older branch such as 1.28 stays in the affected range unless your distribution backported the patches. `mitigate` applies the three simple workarounds for you, with a backup and an automatic undo; the others need an administrator to read the configuration.

### nginx quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/nginx/nginx-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/nginx/nginx-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less nginx-oct2026-check.sh
   chmod +x nginx-oct2026-check.sh
   ```

3. See what's exposed. Run as root so `nginx -T` can read the full config and the package checks work.

   ```bash
   sudo ./nginx-oct2026-check.sh check
   ```

4. Look for worker crashes.

   ```bash
   sudo ./nginx-oct2026-check.sh hunt
   ```

### nginx commands

| Command | What it does |
|---|---|
| `check` (default) | Reports the nginx and njs versions on the host and in running containers, and audits the running configuration (`nginx -T`) for the five flaws' trigger directives, printing F5's workaround for each one you are exposed to. Changes nothing, root recommended. Exits `0` if nothing is exposed, `1` if a vulnerable nginx/njs is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for nginx worker crashes (workers exited on a crash signal, segfaults, use-after-free/heap aborts), the likely symptom of the memory bugs. Exits `0` if nothing matched, `1` if it found something |
| `mitigate --tickets-off \| --aio-off \| --proxy-buffering-off [--force] [--dry-run] [--reload]` | **Changes the host (root).** Applies three of F5's workarounds, only for flaws the same configuration audit as `check` reports as exposed (a patched build, or a flaw your configuration cannot reach, is left alone unless you add `--force`). With no option it applies `--tickets-off` and `--aio-off`, the two low-impact measures; `--proxy-buffering-off` is added on request (see below). Every file is copied first and checked with `nginx -t` before and after; if nginx rejects the result the originals are put back at once. Reloads nothing unless you add `--reload` |
| `rollback [--dry-run] [--reload]` | Puts back every file `mitigate` changed |
| `version` | Prints the script version. Every command prints it on its first line too |

### nginx patch detection

nginx fixes land on the two current branches only: 1.30.6 (stable) and 1.31.7 (mainline). The script judges a version accordingly. A 1.30.x build is fixed at 1.30.6, a 1.31.x build at 1.31.7, and anything 1.32.0 or newer is fixed. An older branch (1.28 and earlier) upgrades to 1.30.6 or 1.31.7. For an nginx installed from a Debian or Ubuntu package, the package build and changelog are checked first (`FIXED_BUILDS` plus the changelog naming one of the CVEs), because a distribution can backport the fix while keeping the upstream version number. `njs` is judged against 1.0.2.

### nginx configuration audit

The valuable part. Each of the five flaws needs a particular directive combination, so the script runs `nginx -T` and reports, per flaw, whether your configuration reaches it:

- CVE-2026-15176: `alias` with a `rewrite` and a reference to `$request_filename`.
- CVE-2026-93479: a regex `map` whose captures are read by `root` or `log_format`.
- CVE-2026-97205: `aio` enabled together with SSI pages.
- CVE-2026-95101: HTTP/3 (`quic`) with `proxy_request_buffering` on (the default).
- CVE-2026-97629: `ssl_session_cache shared` without `ssl_session_ticket_key` (and not `ssl_session_tickets off`).

For each, it prints F5's workaround. The matches cover the whole dumped config, so check that the directives share a server or location block; the permanent fix is upgrading.

### nginx configuration

| Variable | Default | Purpose |
|---|---|---|
| `NGINX_STABLE_FIXED` | `1.30.6` | First fixed stable release |
| `NGINX_MAINLINE_FIXED` | `1.31.7` | First fixed mainline release |
| `NJS_FIXED` | `1.0.2` | First fixed njs release |
| `FIXED_BUILDS` | *(empty)* | Distro nginx builds known to carry the backported fix, space-separated full versions |
| `NGINX_T` | `1` | `0` skips the `nginx -T` config audit |
| `SCAN_CONTAINERS` | `1` | `0` skips reading nginx inside running containers |
| `HUNT_SINCE` | `2026-10-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### nginx workarounds: `mitigate`

| Option | Flaw | What it does | What it changes |
|---|---|---|---|
| `--tickets-off` | CVE-2026-97629 | Where `ssl_session_cache` is `shared`, adds `ssl_session_tickets off` (an explicit `on` becomes `off`) | TLS session resumption through the shared cache still works; ticket resumption stops |
| `--aio-off` | CVE-2026-97205 | Replaces `aio on` and `aio threads` with `aio off` | Slower file serving under load; nothing breaks |
| `--proxy-buffering-off` | CVE-2026-95101 | Sets `proxy_request_buffering off` at the `http` level, or turns an explicit `on` into `off` (only when the configuration sets it nowhere else) | Request bodies are streamed to the upstream: retries stop, and an upstream that needs `Content-Length` may fail |

CVE-2026-15176 (`alias` with a `rewrite` and `$request_filename`) and CVE-2026-93479 (a regex `map` whose captures feed `root` or `log_format`) are **not** automated, because they need someone to read the configuration. `mitigate` prints F5's advice for them when they are exposed. After a change it re-runs the audit and says what is still exposed. `STATE_DIR` (default `/var/lib/psf-security-patches/nginx`) holds the backups and manifest. `NGINX_BIN`, `NGINX_MAIN_CONF` and `NGINX_CONF_FILES` point it at a binary, a non-default main file and the files to edit.

Verified on nginx 1.24 serving TLS: the audit reported CVE-2026-97629 and CVE-2026-97205. After `mitigate --tickets-off --aio-off` and a reload the TLS 1.2 handshake no longer issued a session ticket, pages were served as before and the audit reported nothing exposed. `rollback` restored the file exactly. A configuration that does not validate is left untouched.

## Before you run it

- The fix. Upgrade to 1.30.6 or 1.31.7 (or your distribution's backport) and reload. Upgrade njs to 1.0.2. The config audit tells you which workarounds apply in the meantime.
- A vulnerable version is not always reachable. Each flaw needs its directive, which is why the config audit matters. A build with none of the five directives configured is not a path, though upgrading is still the right move.
- `check` reads the configuration with `nginx -T`, which is nginx's own configuration test. If the configuration does not pass that test, nginx writes the error to its own error log, exactly as it does when you run the command yourself.
- The config audit matches directives across the whole `nginx -T` output and cannot prove they share one server or location, so treat an "exposed" line as "review this," not a verdict.
- `nginx -T` needs root and a valid config. Without them the audit is skipped and reported as unknown; the version checks still run.
- Distribution backports read correctly. A package can carry the fix under the old upstream number. Add a known-fixed build to `FIXED_BUILDS` if its changelog doesn't name a CVE.
- GNU/Linux only.

---

## ⚠️ Important notice

These scripts are used on our production systems and undergo testing, but they may require adaptation for other environments. Review the source code before running any script, test changes in a non-production environment where possible, and maintain current backups. This software is provided without warranty.

## 🏛️ Support PrivacySafe Foundation

[PrivacySafe Foundation](https://privacysafe.foundation) is a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, decentralized technology, documentation, standards work, and public-interest privacy and security research.

Security work doesn't stop when a disclosure drops at midnight. If this repository helped you protect your users, please help us keep doing it:

* **[Donate directly to the Foundation](https://privacysafe.foundation)**
* [Open Collective](https://opencollective.com/privacysafe)
* [Ko-fi](https://ko-fi.com/R6R1194HN7)
* [Liberapay](https://liberapay.com/PrivacySafe/donate)

The Foundation website provides options for card donations, PayPal/Venmo, cryptocurrency, checks, and other forms of support. Donations are often tax-deductible in the USA. Federal EIN: 41-5237617.

## 🤝 Contributing

Found a bug in a script, or have a mitigation that belongs here? Please fork and submit a focused pull request.

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../NOTICE) and [`LICENSE`](../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
