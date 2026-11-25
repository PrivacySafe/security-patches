# Apache HTTP Server security releases

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="mod-http2"></a>

## mod_http2: CVE-2026-119618, unauthenticated RCE in HTTP/2 request handling

**Script:** [`servers/apache/apache-mod-http2-check.sh`](apache-mod-http2-check.sh)

Apache HTTP Server 2.4.71, released 11 November 2026, fixes CVE-2026-119618, a critical (CVSS 3.1 9.8, CWE-362) flaw in `mod_http2`: two HTTP/2 worker threads can race on a connection-level memory allocator in `assign_headers()`, corrupting heap memory in a way public research says reliably leads to code execution. It was discovered by Anthropic's OSS Scanner and Google Cloud's Vulnerability Research team, and needs nothing beyond HTTP/2 being turned on: no authentication, no application behind the server, no specific request handler. Affected versions are httpd 2.4.55 through 2.4.70. The standalone `mod_h2` project on GitHub, the same vulnerable code before it was merged into httpd itself, covers versions 2.0.8 through 2.0.42 and was archived by its owner on 9 June 2026; it has received no fix, and moving off it entirely is the only remedy for a site still using it.

Loading `mod_http2` is not, by itself, enough to be exposed: Apache's own documentation says HTTP/2 must also be turned on with a `Protocols` directive naming `h2` or `h2c`, at server level or inside a `VirtualHost`. Both conditions are common in practice, since several distributions' own "enable HTTP/2" instructions, and `a2enmod http2`'s own shipped configuration on Debian and Ubuntu, set `Protocols h2 h2c http/1.1` as part of turning the module on.

Red Hat's own httpd packaging for RHEL 9 and RHEL 10 allocates each HTTP/2 stream from a separate allocator, which Red Hat says substantially raises the bar to exploit this, without calling it fixed there. RHEL 8 and earlier ship no `mod_http2` package at all, so they are unaffected for that reason, not because of a patch.

`check` and `hunt` change nothing and need no privilege. `check` reports the Apache version, whether `mod_http2` is loaded (preferring the live module list from `apache2ctl -M` / `apachectl -M` when the server is running, falling back to the config files otherwise), and whether an active, uncommented `Protocols` directive anywhere in the config tree it walks offers `h2` or `h2c`. `hunt` greps the error log for the worker-crash and APR allocator-corruption signatures public write-ups associate with this flaw; finding none is not proof nothing happened, since a successful exploit need not crash a worker or log anything. `mitigate` and `rollback` change the host and require root, stopping with a clear message (and a `sudo` suggestion) otherwise; `mitigate --dry-run` doesn't change anything and so doesn't require it. `mitigate` comments out every active `LoadModule http2_module` line and every active `Protocols` directive naming `h2`/`h2c` across the config tree (resolving Debian/Ubuntu's `conf-enabled`/`mods-enabled` symlinks to the real file first, so it edits `conf-available`/`mods-available` rather than silently turning a symlink into a plain file), backs up every file it touches, verifies the result with `apache2ctl -t` / `apachectl -t`, and rolls back automatically if the test fails. `rollback` restores every backed-up file. Neither command reloads the server unless you pass `--reload` (graceful, via `systemctl reload` where that unit exists, otherwise `apache2ctl -k graceful`); without it, reload the server yourself once you're satisfied with the result.

There is no configuration workaround that keeps HTTP/2 usable and closes this. The fix is upgrading to 2.4.71; `mitigate` is for buying time until you can, at the cost of dropping every client to HTTP/1.1.

Verified on Apache 2.4.58 (Ubuntu): with `mod_http2` and `Protocols h2 h2c http/1.1` both off, `check` reported CLEAR (exit 0); after `a2enmod http2` plus a `Protocols` directive, it correctly reported EXPOSED (exit 1), finding the directive through both a conf file and `a2enmod`'s own shipped `mods-available/http2.conf`. `mitigate` commented out all three directives, `apache2ctl -t` passed, and the re-check returned to CLEAR; `rollback` restored all three files to their original content and the exposed state returned exactly as before. A server with `mod_http2` loaded but no matching `Protocols` directive is reported as undetermined, not clear, since this script's config-file walk is not a full guarantee of what an unusually structured include tree resolves to. A non-root user running `mitigate` or `rollback` is stopped with a clear message instead of a raw permission error; `mitigate --reload` and `rollback --reload` were each verified to actually reload a running Apache (starting it first when it wasn't running) and leave the server answering requests afterward.

### mod_http2 quick start

1. Download the script.

   ```sh
   curl -O https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/servers/apache/apache-mod-http2-check.sh
   chmod +x apache-mod-http2-check.sh
   ```

2. Check whether you're exposed.

   ```sh
   ./apache-mod-http2-check.sh check
   ```

3. If you can upgrade to 2.4.71, do that and skip the rest. If not, mitigate:

   ```sh
   sudo ./apache-mod-http2-check.sh mitigate --dry-run
   sudo ./apache-mod-http2-check.sh mitigate --reload
   ```

4. Once you've upgraded, undo the mitigation:

   ```sh
   sudo ./apache-mod-http2-check.sh rollback --reload
   ```

### mod_http2 commands

| Command | Changes the system? | What it does |
|---|---|---|
| `check` | no | Version, module, and `Protocols` directive audit; exit 0 clear, 1 exposed, 2 undetermined |
| `hunt` | no | Greps the error log for crash/corruption signatures |
| `mitigate [--dry-run] [--reload]` | yes (unless `--dry-run`) | Comments out `LoadModule http2_module` and any `Protocols h2`/`h2c` line; backs up first, tests the config, rolls back on failure. `--reload` gracefully reloads the server afterward |
| `rollback [--dry-run] [--reload]` | yes (unless `--dry-run`) | Restores every file `mitigate` backed up; `--dry-run` lists what it would restore; `--reload` gracefully reloads the server afterward |
| `rules` | no | Prints the explanation above |
| `version` | no | Prints the script's version |

Environment override: `APACHE_HTTP2_FIXED` (default `2.4.71`) if you need to compare against a different fixed version, such as a vendor backport with its own numbering. `PSF_BACKUP_DIR` (default `/var/backups/psf-security-patches/apache-mod-http2`) to change where `mitigate` keeps its backups.

What this script can't see: a `Protocols` directive reached only through an `Include` this script's config-tree walk does not follow (it reads the standard Debian/Ubuntu and RHEL/Fedora/SUSE layouts directly, plus one level of symlink resolution, but does not recursively resolve arbitrary nested `Include`/`IncludeOptional` chains), and a server started with a non-standard `-f`/`-d` path. In either case `check` says the result is undetermined rather than reporting clear.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

Red Hat ships HTTP/2 support as the separate mod_http2 package; the JBoss Core Services and Dev Spaces advisories are for builds that bundle their own httpd.

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:98953](https://access.redhat.com/errata/RHSA-2026:98953) | 2026-11-11 | Important | `mod_http2-2.0.29-2.el10_0.3` (RHEL 10.0) | CVE-2026-119618 |
| [RHSA-2026:98954](https://access.redhat.com/errata/RHSA-2026:98954) | 2026-11-11 | Important | `mod_http2-2.0.26-4.el9_6.3` (RHEL 9.6) | CVE-2026-119618 |
| [RHSA-2026:98968](https://access.redhat.com/errata/RHSA-2026:98968) | 2026-11-11 | Important | `mod_http2-2.0.26-2.el9_4.4` (RHEL 9.4) | CVE-2026-119618 |
| [RHSA-2026:98978](https://access.redhat.com/errata/RHSA-2026:98978) | 2026-11-11 | Important | `mod_http2-2.0.29-5.el10_3.1` (RHEL 10.3) | CVE-2026-119618 |
| [RHSA-2026:98979](https://access.redhat.com/errata/RHSA-2026:98979) | 2026-11-11 | Important | `mod_http2-2.0.29-4.el10_2.3` (RHEL 10.2) | CVE-2026-119618 |
| [RHSA-2026:98981](https://access.redhat.com/errata/RHSA-2026:98981) | 2026-11-11 | Important | `mod_http2-2.0.26-7.el9_9.1` (RHEL 9.9) | CVE-2026-119618 |
| [RHSA-2026:98982](https://access.redhat.com/errata/RHSA-2026:98982) | 2026-11-11 | Important | `mod_http2-2.0.26-6.el9_8.3` (RHEL 9.8) | CVE-2026-119618 |
| [RHSA-2026:100552](https://access.redhat.com/errata/RHSA-2026:100552) | 2026-11-17 | Critical |  | CVE-2026-119618 |
| [RHSA-2026:100550](https://access.redhat.com/errata/RHSA-2026:100550) | 2026-11-18 | Critical | `jbcs-httpd24-httpd-2.4.62-19.el8jbcs` (RHEL 8 (el8jbcs)); `jbcs-httpd24-mod_http2-2.0.29-16.el8jbcs` (RHEL 8 (el8jbcs)); `jbcs-httpd24-mod_jk-1.2.50-20.redhat_1.el8jbcs` (RHEL 8 (el8jbcs)); and 3 more | CVE-2026-119618 |
| [RHSA-2026:100811](https://access.redhat.com/errata/RHSA-2026:100811) | 2026-11-20 | Critical | `devspaces/code-rhel9` (container image); `devspaces/code-sshd-rhel9` (container image); `devspaces/configbump-rhel9` (container image); and 13 more | CVE-2026-119618 |
| [RHSA-2026:102591](https://access.redhat.com/errata/RHSA-2026:102591) | 2026-11-23 | Critical | `openshift-gitops-1/argo-rollouts-rhel9` (container image); `openshift-gitops-1/argocd-rhel9` (container image); `openshift-gitops-1/argocd-agent-rhel9` (container image); and 11 more | CVE-2026-119618 |
| [RHSA-2026:102593](https://access.redhat.com/errata/RHSA-2026:102593) | 2026-11-23 | Critical | `openshift-gitops-1/argo-rollouts-rhel9` (container image); `openshift-gitops-1/argocd-rhel9` (container image); `openshift-gitops-1/argocd-agent-rhel9` (container image); and 8 more | CVE-2026-119618 |
| [RHSA-2026:102596](https://access.redhat.com/errata/RHSA-2026:102596) | 2026-11-23 | Critical | `openshift-gitops-1/argo-rollouts-rhel9` (container image); `openshift-gitops-1/argocd-rhel9` (container image); `openshift-gitops-1/argocd-agent-rhel9` (container image); and 8 more | CVE-2026-119618 |

<!-- rhsa:end -->

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../../NOTICE) and [`LICENSE`](../../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
