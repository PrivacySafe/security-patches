# vsftpd: CVE-2026-119568 FTPS data channel hijack

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="vsftpd-ftps-data-channel-hijack"></a>

## vsftpd FTPS data channel hijack

**Script:** [`vsftpd/vsftpd-ftps-ticket-check.sh`](vsftpd-ftps-ticket-check.sh)

vsftpd 3.0.5 and older, built with SSL and running FTPS, has a flaw in how it ties a data connection to its user (CVE-2026-119568). It accepts any resumed TLS session ticket as proof that the data connection belongs to the logged-in user, without checking that the ticket came from that user's control connection. Anyone who shares the victim's IP address can use that to take over a transfer: they receive the victim's download, or the server takes the victim's upload from them.

This tool tells you whether your vsftpd is exposed, protects it until upstream publishes a fixed release, and can apply optional baseline hardening. A second CVE, CVE-2025-14242, is a denial of service in Red Hat family packages and is covered further down.

| | |
|---|---|
| CVE | CVE-2026-119568 (published 30 October 2026) |
| Affected | vsftpd through 3.0.5 |
| Severity | 9.1 Critical in the VulnCheck advisory (CVSS v4, attack complexity high). The researcher scored 7.4 High (CVSS v3.1) |
| Remedy | Run `mitigate` now and install the upstream release that fixes it when it is published ([vendor page](https://security.appspot.com/vsftpd.html)) |
| Impact | The content of one transfer can be read, or supplied, by someone who is not the user. Not a login bypass and not code execution |
| Research | [Abraxas Labs write-up](https://abraxaslabs.tech/research/vsftpd-ssl-data-any-ticket) with a loopback lab and proof of concept; [VulnCheck advisory](https://www.vulncheck.com/advisories/vsftpd-through-3.0.5-require-ssl-reuse-bypass-via-ftps-data-channel-hijacking) |

## What exposes you

All of these have to be true (the researcher's conditions):

1. The binary was built with SSL support. The stock tarball has it off. Most distribution packages turn it on. The script reads this from whether the binary links OpenSSL.
2. `ssl_enable=YES` in the configuration (the default is `NO`).
3. A standalone listener: `listen=YES` or `listen_ipv6=YES`. Debian's default configuration sets `listen_ipv6=YES`, which counts.
4. `require_ssl_reuse=YES`, which is the default. Setting it to `NO` removes the ticket requirement entirely, so the data connection is no longer tied to the control connection at all. The script reports that as exposed too (our reading, not the advisory's).
5. The attacker shares the victim's source IP address. Passive connections must come from the control connection's address unless `pasv_promiscuous=YES`, so this means a shared NAT address, a shared proxy or the same host.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/vsftpd/vsftpd-ftps-ticket-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/vsftpd/vsftpd-ftps-ticket-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less vsftpd-ftps-ticket-check.sh
   chmod +x vsftpd-ftps-ticket-check.sh
   ```

3. Check this host. The script finds vsftpd on `PATH`, in the usual locations and from running processes, and reads each configuration file it finds. To check a specific binary or configuration, pass the binary and set `VSFTPD_CONF`.

   ```bash
   ./vsftpd-ftps-ticket-check.sh check
   ./vsftpd-ftps-ticket-check.sh check /opt/vsftpd/sbin/vsftpd
   VSFTPD_CONF=/etc/vsftpd/ftps.conf ./vsftpd-ftps-ticket-check.sh check
   ```

`check` is read-only and sends no network traffic. Only `mitigate` and `rollback` change anything, and neither restarts vsftpd unless you add `--restart`.

Exit codes of `check`: **0** nothing exposed, **1** an exposed vsftpd, or one that cannot be judged (a version or configuration that cannot be read is treated as exposed, so that you review it), **2** bad usage.

What it reports for each binary:

| Finding | Verdict |
|---|---|
| Version above 3.0.5 | Outside the published range. Confirm against the vendor page |
| Package changelog mentions CVE-2026-119568 | Possibly backported by the distribution |
| Binary does not link OpenSSL | Not exposed: FTPS is not available |
| `ssl_enable` is not YES | Not exposed |
| Neither `listen` nor `listen_ipv6` is YES | Not exposed on the researcher's reading (no shared ticket keys between connections) |
| `require_cert=YES` | Mitigated by configuration (researcher's reading; needs a certificate on every client) |
| Everything else, on 3.0.5 or older | **Exposed** |

Several configuration files (for example `/etc/vsftpd/*.conf`, or the file named on a running process's command line) are each judged separately.

## CVE-2025-14242: authenticated denial of service (Red Hat family packages)

The check also reports a second vsftpd flaw that has nothing to do with FTPS.

| | |
|---|---|
| CVE | CVE-2025-14242 (published 14 January 2026 by Red Hat) |
| Weakness | CWE-190, integer overflow in the parsing of `ls` parameters, reached through a crafted `STAT` command |
| Severity | 6.5 Medium (CVSS v3.1: network, low complexity, low privileges, availability high). CISA's SSVC entry: exploitation none, automatable no. Not known to be exploited |
| Needs | **A valid login.** An anonymous-only server needs the attacker to be able to log in anonymously |
| Affected | Red Hat's own vsftpd packages (RHEL 8, 9 and 10 and their update-service streams). Fixed in RHSA-2026:0605, 0606 and 0608 and later errata, for example 3.0.3-36.el8_10.3 (RHEL 8), 3.0.5-6.el9_7.2 (RHEL 9) and 3.0.5-10.el10_1.1 (RHEL 10) |
| Open question | A comment on [Red Hat's bug](https://bugzilla.redhat.com/show_bug.cgi?id=2419826) asks whether the flaw comes from a patch only Red Hat carries (support for square brackets in `ls`). That is not confirmed, so **this tool does not claim that upstream 3.0.5 or Debian and Ubuntu builds are affected or safe** |

What the check does: for each vsftpd it finds, it asks the package manager. A package whose changelog names CVE-2025-14242 is reported fixed. A Red Hat family package (Red Hat, AlmaLinux, Rocky, CentOS, Oracle) whose changelog does not name it is reported as affected. RHEL 7 builds are not listed by Red Hat and are noted, not reported. Anything else (Debian, Ubuntu, a source build) is not reported, with the open question above. It decides by the package, not by the version number, because Red Hat backports under old version numbers.

What to do: install your distribution's vsftpd update. Until then, `mitigate --allow` limits who can reach the port and removing accounts that do not need FTP limits who can log in. `harden --limits` caps sessions per address, which is a generic suggestion from a third-party summary and not Red Hat's advice. It does not remove the bug.

## Optional hardening: `harden`

`harden` is separate from both CVEs: it applies baseline hardening, and only the measures you choose, because each can change how clients connect. It needs root, copies every file first, restarts nothing unless you add `--restart`, and `rollback` undoes it together with `mitigate`. Each directive is written only if the installed vsftpd build knows it, because an unknown directive stops vsftpd from starting (the Ubuntu 3.0.5 build, for example, does not recognize `ssl_tlsv1_1` or `ssl_tlsv1_2`). A numeric limit that is already set and at least as strict is never loosened.

```bash
sudo ./vsftpd-ftps-ticket-check.sh harden --baseline --dry-run
sudo ./vsftpd-ftps-ticket-check.sh harden --baseline --restart
sudo ./vsftpd-ftps-ticket-check.sh harden --force-tls --no-anon --pasv-range 40000-40100
sudo ./vsftpd-ftps-ticket-check.sh rollback
```

| Option | What it sets | What it can break |
|---|---|---|
| `--baseline` | `--logging`, `--limits` and `--tls` together | See each |
| `--logging` | `xferlog_enable=YES` | Nothing; the log grows |
| `--limits` | Standalone listeners: `max_clients=50`, `max_per_ip=5`. Everywhere: `idle_session_timeout=300`, `data_connection_timeout=120` | `max_per_ip` locks out many users behind one NAT address. Slow transfers can hit the timeouts. `max_clients` and `max_per_ip` are ignored when vsftpd runs once per connection, and are left alone |
| `--tls` | Where `ssl_enable=YES`: `ssl_ciphers=HIGH`, SSLv2, SSLv3, TLSv1 and TLSv1.1 off, TLSv1.2 on (each only if the build knows it) | Very old FTPS clients |
| `--force-tls` | Where `ssl_enable=YES`: `force_local_logins_ssl` and `force_local_data_ssl` (vsftpd's default is already YES for both, so this makes it explicit), and where `allow_anon_ssl=YES` also `force_anon_logins_ssl` and `force_anon_data_ssl` | Every client must speak FTPS |
| `--no-anon` | `anonymous_enable=NO` (vsftpd's default is YES) | Anonymous FTP stops |
| `--chroot` | Where `local_enable=YES`: `chroot_local_user=YES` | vsftpd refuses a login when the user's home directory is writable. The tool does not set `allow_writeable_chroot`, which weakens the jail |
| `--pasv-range A-B` | `pasv_min_port` and `pasv_max_port` | Your firewall and NAT must allow the range or passive transfers hang. `mitigate --allow` opens it for the listed addresses |

`harden` does not switch FTPS on, because that needs a certificate of your choosing: set `ssl_enable=YES` and the certificate paths first, then use `--tls` and `--force-tls`. For the firewall item in the usual hardening guides, use `mitigate --allow`. Updates are what `check` is for.

Verified on vsftpd 3.0.5 (Ubuntu build) with a local user and FTPS clients. After `harden --baseline --force-tls --no-anon` and a restart, plain FTP was refused for anonymous and local users, FTPS for the local user still worked, and TLS 1.2 was accepted. `ssl_tlsv1_1` and `ssl_tlsv1_2` were skipped because the build does not know them, and `rollback` restored the file exactly. With anonymous TLS allowed, `--force-tls` refused plain anonymous FTP and left anonymous FTPS working. With `--chroot`, a local user with a writable home could not log in. TLS 1.0 was already refused on that host, so the protocol settings made no visible difference there.

## Mitigating it

`mitigate` applies the protective measures for you. It needs root, copies every file it edits first, restarts nothing unless you add `--restart` (vsftpd reads its configuration at start, and a restart ends transfers in progress), and `rollback` undoes it. Use `--dry-run` first.

```bash
sudo ./vsftpd-ftps-ticket-check.sh mitigate --dry-run
sudo ./vsftpd-ftps-ticket-check.sh mitigate                       # safe step only
sudo ./vsftpd-ftps-ticket-check.sh mitigate --require-cert        # if your clients present certificates
sudo ./vsftpd-ftps-ticket-check.sh mitigate --allow 203.0.113.0/24,198.51.100.7
sudo ./vsftpd-ftps-ticket-check.sh rollback
```

| Option | What it does | Cost and trust |
|---|---|---|
| (none) | Sets `pasv_promiscuous=NO` in each FTPS configuration that has it on. That setting lets passive data connections come from any address, which removes the same-IP precondition of the attack | Safe unless you rely on FXP (server to server) transfers. A clear tightening, not a complete fix |
| `--require-cert` | Also sets `require_cert=YES` and `ssl_request_cert=YES`: every client must present a certificate and the data connection is matched against it | It **refuses clients that have no certificate**, which is most FTPS clients, so use it where every client presents one |
| `--allow LIST` | nftables (or iptables): only the listed addresses or CIDRs, plus loopback, may reach the control port (`listen_port`, default 21) and the passive range if `pasv_min_port` and `pasv_max_port` are set. IPv6 is dropped entirely unless you list an IPv6 source | Does not survive a reboot. Cannot stop an attacker who shares an allowed address, which is the attack's precondition. Useful against everyone else |
| `--restart` | Restarts vsftpd through systemd afterwards | Ends transfers in progress |

The ports to protect are read from each FTPS-enabled configuration (`ssl_enable=YES`). With none, only port 21 is protected, and the script says so. Verified with vsftpd 3.0.5 and a client in a separate network namespace: with `--allow 192.0.2.0/24` the client's connection to the control port timed out while loopback still worked. With the client's own network in the list it connected. `rollback` removed the rules. The nftables rule and the iptables fallback behaved the same.

Not automated: running vsftpd per connection from xinetd or a systemd socket (the researcher's other suggestion) replaces how the service is started, so it stays your decision. Moving transfers to SFTP is a migration, not a setting. `require_ssl_reuse=YES` shows that some ticket the server can decrypt was presented. It does not tie the data connection to the same session.

State (backups of the first original of each file, and a manifest) is kept in `STATE_DIR`, default `/var/lib/psf-security-patches/vsftpd`. Running `mitigate` twice keeps the first original, so `rollback` always restores the real original.

## Sources

- [Hackviser: vsftpd hardening guide](https://hackviser.com/tactics/hardening/vsftpd): the source of the baseline items (FTPS, anonymous login, ciphers, chroot, logging, connection limits, passive range, firewall, updates)
- [CyRisk: mitigation instructions for vsftpd](https://cyrisk.com/security/mitigation-instructions-for-vsftpd/): generic advice written for vsftpd 2.0.6. Nothing version-specific was taken from it
- [Rapid7 vulnerability database: CVE-2026-119568](https://www.rapid7.com/db/) and [the CVE record](https://www.cve.org/CVERecord?id=CVE-2026-119568): CVSS v4 9.1 and v3.1 7.4. Not in the CISA KEV catalog on 30 October 2026
- [Red Hat: CVE-2025-14242](https://access.redhat.com/security/cve/CVE-2025-14242) and [bug 2419826](https://bugzilla.redhat.com/show_bug.cgi?id=2419826): affected packages, the fixed errata and the open question about the source of the flaw. A third-party summary page of the same CVE says it was generated with AI, so its details were checked against Red Hat's data before use

## Before you run it

- The fix. Install the upstream vsftpd release that fixes CVE-2026-119568 when it is published ([vendor page](https://security.appspot.com/vsftpd.html)). Until then, `mitigate` is a clear tightening, not a complete fix.
- The impact is one transfer. Someone who shares your source IP address can read or supply the content of a transfer. It is not a login bypass and not code execution.
- `mitigate` and `harden` edit your vsftpd configuration. They copy every file first, restart nothing unless you add `--restart`, and `rollback` undoes both. Use `--dry-run` first.
- `mitigate --require-cert` refuses clients that have no certificate, which is most FTPS clients.
- `harden` is separate from both CVEs and applies only the measures you choose, because each can change how clients connect.
- Containers are not scanned. Run the script inside the container, or pass the binary and set `VSFTPD_CONF` to a copy of its configuration.
- The configuration parser follows vsftpd's rules (a later line wins, `#` starts a comment, no spaces around `=` are needed here) but does not follow `include`-style tricks from distribution wrappers.
- Whether a standalone vsftpd was started by a supervisor that ignores `listen` cannot be seen from the configuration. If neither `listen` nor `listen_ipv6` is set the script reports "not exposed (per connection)". Set `listen=YES` in a copy of the file to see how it would be reported.
- `harden` cannot start vsftpd to prove a configuration works: it relies on the build knowing each directive and on `--dry-run`. Try a login from each kind of client after a restart.
- Whether CVE-2025-14242 affects builds that are not Red Hat family packages is unconfirmed (see above), so such builds are not reported.
- The affected range is the one published on 30 October 2026. The CVE text names `ssl_data_accept()` and the researcher's write-up names `ssl_accept()`. They describe the same missing check.

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
