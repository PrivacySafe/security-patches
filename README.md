<p align="center">
  <a href="https://privacysafe.app"><img src="privacysafe_horizontal_logo_lock_reg_padded.svg" width="600" /></a>
</p>
<h1 align="center">Security Patches</h1>

<h3 align="center">
Security mitigations and auditing tools shared for the public good.
</h3>

<p align="center">
  <a href="https://privacysafe.foundation"><strong>❤️ Support PrivacySafe Foundation</strong></a>
  &nbsp;|&nbsp;
  <a href="https://privacysafe.app/docs/security-patches/"><strong>📚 Read the Documentation</strong></a>
</p>

This repository contains security mitigations, system-hardening scripts, and auditing tools developed for PrivacySafe and Ivy Cyber infrastructure. We publish these tools so that others can study, adapt, and use them to protect their own systems, including when upstream security fixes are not yet available.

**59 scripts addressing 137 CVEs across 68 software projects and 10 programming languages, plus 5 other global security incidents.**

> 💚 If this work is helpful, please consider [supporting PrivacySafe Foundation](https://privacysafe.foundation), a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, and public-interest privacy and security research.

---

## 📦 Available tools

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [PHP2Shell](php/README.md#php2shell-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 | Mitigation |
| [PHP2Shell live watch](php/README.md#watching-live) | PHP-FPM, Apache and nginx logs on any GNU/Linux; optional systemd unit | CVE-2026-109618, CVE-2026-109619 | Read-only live monitor |
| [PHP2Shell on cPanel](php/README.md#php2shell-on-cpanel-easyapache-4) | cPanel/WHM servers running EasyApache 4 PHP (ea-php74 to ea-php85), any handler | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 | Mitigation, check and audit |
| [PHP session audit](php/README.md#php-session-audit-cve-2026-115560) | Any PHP host | CVE-2026-115560 | Read-only audit |
| [PHP2Shell edge guards](php/edge/README.md) | Apache httpd (server configuration or `.htaccess`) and nginx in front of PHP, with request body and header limits, and a curl tester | CVE-2026-109618, CVE-2026-109619 | Compensating controls (log-only first) |
| [PHP2Shell detection rules](php/detect/README.md) | auditd, Tetragon and nftables on GNU/Linux | CVE-2026-109618, CVE-2026-109619 | Detection content |
| [Node.js October 2026](node/README.md#nodejs-october-2026-mitigation) | Node.js on GNU/Linux; systemd for the guard | CVE-2026-111497 (Brotli) and 9 Node CVEs | Mitigation (Node only) |
| [Brotli checker](brotli/README.md#brotli-checker-quick-start) | libbrotli and the processes using it, plus Node/Bun/Python/Ruby/PHP/Envoy/Istio/cdxgen and containers on GNU/Linux | CVE-2026-111497 (Broccoli2Shell) | Read-only check and audit |
| [Ruby and GitLab Regexp](ruby/README.md#ruby-and-gitlab-regexp-check) | Ruby runtimes, Ruby apps and GitLab on GNU/Linux | CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264 | Read-only check and audit |
| [libheif HEIF/AVIF Decoder](heif/README.md#libheif-heifavif-decoder-check) | libheif, ImageMagick and Discourse on GNU/Linux | [writeup](https://www.hacktron.ai/blog/hacking-openai); DSA-6417-1 | Check, audit and ImageMagick coder mitigation |
| [eMudhra CA Compromise](pki/README.md#emudhra-intermediate-ca-compromise-mitigation) | System CA store on Debian/Ubuntu/Trisquel and derivatives | [disclosure](https://emudhra.we-have-a-problem.com/); Go: CVE-2026-111943 | Mitigation |
| [curl HTTP/2 upload](curl/README.md#curl-http2-upload-use-after-free-check) | curl and libcurl on GNU/Linux | CVE-2026-92392 | Read-only check and audit |
| [openapi-typescript-codegen](openapi/README.md#openapi-typescript-codegen-code-injection-check) | Projects, CI jobs and generated TypeScript clients on GNU/Linux | CVE-2026-108551 | Read-only check and generated-code scan |
| [Nextcloud Collabora Built-in CODE](nextcloud/README.md#nextcloud-collabora-built-in-code-command-injection) | Nextcloud with the richdocumentscode app on GNU/Linux | CVE-2026-110447 | Mitigation, check and hunt |
| [nginx October 2026](nginx/README.md#nginx-october-2026-check) | nginx and njs on GNU/Linux | CVE-2026-15176, CVE-2026-93479, CVE-2026-97205, CVE-2026-95101, CVE-2026-97629; njs: CVE-2026-101019, CVE-2026-101025 | Check, config audit, hunt, three workarounds (`mitigate`) and rollback |
| [LiteLLM supply-chain compromise](litellm/README.md#litellm-11070-supply-chain-compromise) | litellm in Python environments and containers on GNU/Linux | [incident](https://github.com/BerriAI/litellm/issues/47826) (litellm 1.107.0, no CVE) | Detect, hunt and contain |
| [Plex Media Server Plex2Shell](plex/README.md#plex-media-server-plex2shell-rce-chain) | Plex Media Server on GNU/Linux | CVE-2026-96651, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656 | Read-only check and hunt |
| [GhostAction developer-machine stealer](ghostaction/README.md#ghostaction-developer-machine-stealer) | Git repositories and developer machines on GNU/Linux | [incident](https://opensourcemalware.com/blog/ghostaction-attack-escalates) (campaign, no CVE) | Scan, hunt and contain |
| [Claude Code extension SSH backdoor](claude-code-vsx/README.md#claude-code-extension-ssh-backdoor) | Claude Code extension 2.1.312 and 2.1.313 served by the Cursor marketplace (29 October 2026); developer machines on GNU/Linux and macOS (Cursor's notice publishes scripts for macOS and Windows only) | [incident](https://cursor.com/blog/claude-code-extension-security-notice) (no CVE) | Check, hunt, clean and block |
| [vsftpd FTPS data channel hijack](vsftpd/README.md#vsftpd-ftps-data-channel-hijack) | vsftpd 3.0.5 and older with FTPS enabled on a standalone listener, GNU/Linux | CVE-2026-119568, CVE-2025-14242 (Red Hat family packages) | Check, mitigation, optional hardening and rollback |
| [WordPress XSS2Shell](wordpress/README.md#wordpress-xss2shell-check) | WordPress Core sites and their web server logs on GNU/Linux | CVE-2026-64638 | Read-only check, audit and hunt |
| [WordPress plugins October 2026](wordpress/README.md#wordpress-plugins-october-2026-check) | LiteSpeed Cache, Rank Math PRO, OttoKit, SureCart, LatePoint, Amelia, Profile Builder and Bricksforge (exploited upload to code execution) in WordPress installs on GNU/Linux | CVE-2026-113500, CVE-2026-111862, CVE-2026-110372, CVE-2026-112241, CVE-2026-110653, CVE-2026-112327, CVE-2026-112242, CVE-2026-85097 | Check, hunt, plugin deactivation (`mitigate`) and rollback |
| [Apache Tomcat October 2026](tomcat/README.md#apache-tomcat-october-2026-check) | Apache Tomcat 9.0, 10.1 and 11.0 on GNU/Linux | CVE-2026-103119, CVE-2026-101356 | Check, mitigation (`mitigate --ajp\|--http2`) and rollback |
| [Laravel TokenGuard](laravel/README.md#laravel-tokenguard-check) | Laravel apps on GNU/Linux | CVE-2026-114509 | Read-only check and protective middleware |
| [Pillow 13.0.0](pillow/README.md#pillow-13-security-release-check) | Pillow in Python environments and lock files on GNU/Linux | CVE-2026-96639, CVE-2026-112900 | Read-only check |
| [Drupal Webform](drupal/README.md#drupal-webform-check) | Drupal sites with the Webform module on GNU/Linux | CVE-2026-96355 | Read-only check |
| [Roundcube Webmail October 2026](roundcube/README.md#roundcube-webmail-october-2026-check) | Roundcube on GNU/Linux, including copies bundled by hosting panels | CVE-2026-114716 | Read-only check and hunt |
| [Next.js Server Actions](nextjs/README.md#nextjs-server-actions-check) | Next.js projects on GNU/Linux | CVE-2026-94482 | Read-only check |
| [Craft CMS](craft/README.md#craft-cms-check) | Craft CMS 4.x and 5.x projects on GNU/Linux | CVE-2026-112777 | Read-only check |
| [libexpat billion laughs](expat/README.md#libexpat-billion-laughs-check) | libexpat, Python's pyexpat and programs that embed expat on GNU/Linux | CVE-2026-115506 | Read-only check and embedded-copy scan |
| [HAProxy HTTP/2 PING](haproxy/README.md#haproxy-http2-ping-check) | HAProxy 3.1 to 3.4 on GNU/Linux | CVE-2026-110353 | Check, config audit, vendor workaround (`mitigate`) and rollback |
| [Drupal core Field UI and Entity List](drupal/README.md#drupal-core-check) | Drupal 8.9 to 12 sites on GNU/Linux (end-of-life branches move to a supported branch) and the contributed Entity List module | CVE-2026-108097, CVE-2026-108099 | Check, Drupal's Field UI workaround (`mitigate`) and rollback |
| [Apache CouchDB](couchdb/README.md#couchdb-check) | Apache CouchDB 3.5.2 and earlier on GNU/Linux | CVE-2026-86471 | Read-only check |
| [Django REST framework](django/README.md#drf-check) | DRF installs and pinned dependencies on GNU/Linux | CVE-2026-114138, CVE-2026-114137 | Check, nginx rule (`mitigate`) and rollback |
| [YOOtheme Pro](yootheme/README.md#yootheme-check) | YOOtheme Pro 5 on WordPress and Joomla (CVSS 10.0) | CVE-2026-102785 | Check, hunt, web server rule (`mitigate`) and rollback |
| [ISC BIND 9](bind/README.md#bind-check) | BIND 9 name servers on GNU/Linux (9.18 and older get no upstream fix) | CVE-2026-94300 | Read-only check |
| [rsyslog dynaFile](rsyslog/README.md#rsyslog-dynafile-audit) | rsyslog configurations on GNU/Linux | CVE-2026-92709 | Configuration audit, secure-path fix (`mitigate`) and rollback |
| [Gitea](gitea/README.md#gitea-check) | Gitea up to 28.1.0 that trusts a user SSH certificate authority | CVE-2026-109553 | Read-only check |
| [Apache Traffic Server](trafficserver/README.md#trafficserver-check) | Traffic Server 8.x to 10.2.0 that loads the experimental magick or tsmemcache plugin (CVSS 10) | CVE-2026-111813, CVE-2026-111811 | Read-only check |
| [Grav Login plugin](grav/README.md#grav-login-check) | Grav CMS sites with Login 3.6.0 to 3.9.12 | CVE-2026-114658 | Read-only check and hunt |
| [Grav core allowlist bypass](grav/README.md#grav-core-check) | Grav 2.0.15 to 2.2.12: a page editor can run arbitrary public static methods | CVE-2026-116019 | Read-only check and hunt |
| [Sentry for Next.js](sentry/README.md#sentry-nextjs-check) | Next.js apps using `@sentry/nextjs` with `tunnelRoute` on a webpack build | CVE-2026-114139 | Read-only check |
| [Jupyter Server and nbconvert](jupyter/README.md#jupyter-check) | Jupyter Server 2.0 to 2.5 with a gateway and a custom authorizer, and nbconvert 5.4 to 7.17.1 | CVE-2026-114135, CVE-2026-114140 | Read-only check |
| [Storybook](storybook/README.md#storybook-check) | Storybook 8 to 11-alpha dev servers reachable from the network | CVE-2026-114126 | Read-only check |
| [Apache Pulsar and Pulsar Manager](pulsar/README.md#pulsar-check) | Pulsar brokers with the MultiRoles authorization provider and an anonymous role, or a proxy role; and any Pulsar Manager (retired) | CVE-2026-105869, CVE-2026-105942, CVE-2026-105944 | Read-only check |
| [Amazon SageMaker Python SDK](sagemaker/README.md#sagemaker-check) | SageMaker SDK V2 before 2.257.3 and V3 before 3.10.0 (default bucket takeover) | CVE-2026-112408 | Read-only check |
| [Incus](incus/README.md#incus-check) | Incus 6.0 before 6.0.7, 7.0 before 7.0.2 and 7.1 to 7.4: a confined client can write to the host as root | CVE-2026-115375, CVE-2026-115377, CVE-2026-115372 | Read-only check |
| [LiteLLM proxy admin escalation](litellm/README.md#litellm-proxy-admin-escalation) | LiteLLM proxy 1.87.0 up to the fixed release on each line | CVE-2026-114612 | Read-only check |
| [WordPress page-template path traversal](wordpress-pt/README.md#wordpress-pt-check) | WordPress core 4.7.0 to 7.1.1: unauthenticated path traversal, local PHP file inclusion, exploited in the wild | CVE-2026-87902 | Read-only check and hunt |
| [Magento, Adobe Commerce and Mage-OS BlockStrap](magento/README.md#magento-check) | Magento and Adobe Commerce 2.4.4 to 2.4.9, and Mage-OS below 3.6.0: a CVSS 10.0 unauthenticated email-template engine flaw | CVE-2026-103849 | Read-only check |
| [Zammad session hijack and privilege escalation](zammad/README.md#zammad-check) | Zammad 6.3.0 to 6.5.4: session hijack to code execution as the zammad user, chained to root, exploited in the wild | CVE-2026-102489, CVE-2026-102490 | Read-only check and hunt |
| [Linux kernel ebtables SNAT](linux-kernel/README.md#linux-kernel-check) | The Linux kernel on every distribution: out-of-bounds write in the ebtables SNAT ARP rewrite, exploited in the wild | CVE-2026-53266 | Read-only check |
| [Linux kernel local root quartet](linux-kernel/README.md#linux-kernel-lpe-check) | The Linux kernel on every distribution: four local privilege escalations with public exploits (IPsec AH6, TUN/TAP, PPPoE, SCTP), each fixed at a different release per branch | CVE-2026-80844, CVE-2026-81000, CVE-2026-68121, CVE-2026-74469 | Check, opt-in protective measures (`mitigate`) and rollback |
| [nginx-ui restricted-directive bypass](nginx-ui/README.md#nginx-ui-check) | nginx-ui below 2.4.1: a logged-in user can bypass the restricted-directive check, which leads to code execution where nginx loads njs, Perl or Lua | CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319 | Read-only check and hunt |
| [Joomla core, September 2026 release](joomla/README.md#joomla-check) | Joomla 4.0.0 to 5.4.8 and 6.0.0 to 6.1.3: 16 core fixes, two rated High (directory deletion, SSRF) | CVE-2026-90915, CVE-2026-92222, CVE-2026-92227 and others | Check, administrator path restriction (`mitigate --allow`) and rollback |
| [OpenSSL DTLS heap disclosure](openssl/README.md#openssl-check) | OpenSSL 4.0, 3.6, 3.5, 3.4, 3.0, 1.1.1 and 1.0.2 before their fixed releases: a High flaw reachable through DTLS | CVE-2026-84782 | Read-only check |
| [Jenkins plugins, advisory of 16 September 2026](jenkins/README.md#jenkins-check) | 13 Jenkins plugins including Script Security (eight High sandbox bypasses) | CVE-2026-92122 to CVE-2026-92141 | Read-only check |
| [GitLab security releases, October 2026](gitlab/README.md#gitlab-check) | Self-managed GitLab: seven High flaws from the 12 and 21 October releases (cross-site scripting, pipeline authorization, cache poisoning, an LDAP account takeover, a Duo prompt injection). 19.2.9 is not a full fix | CVE-2026-92883, CVE-2026-16301, CVE-2026-14814, CVE-2026-81839, CVE-2026-96893, CVE-2026-15723, CVE-2026-112212 | Read-only check |
| [baserCMS 5](basercms/README.md#basercms-check) | baserCMS 5.0.0 to 5.4.1 (before 5.3.2 and 5.4.2): admin SQL injection, path traversal, and deserialization leading to command execution | CVE-2026-114621, CVE-2026-114622, CVE-2026-114624 | Read-only check |
| [nginx-ui directive injection](nginx-ui/README.md#nginx-ui-check) | nginx-ui below 2.4.1: authenticated directive injection leading to RCE when nginx loads njs/Perl/Lua | CVE-2026-84316, CVE-2026-84317, CVE-2026-84318 | Read-only check |
| [wp2shell, WordPress core RCE](wordpress/README.md#wp2shell-check) | WordPress core 6.8.0 to 6.8.5, 6.9.0 to 6.9.4 and 7.0.0 to 7.0.1: unauthenticated remote code execution, exploited in the wild | CVE-2026-63030, CVE-2026-60137 | Check, hunt, batch-route block (`mitigate`) and rollback |

## 📥 Install from a package

Each release ships three files, all named `psf-security-patches` and versioned by release date, `YY.MM.DD-X.Y.Z` (for example `26.10.30-1.0.0`). Download them from the releases page on [Codeberg](https://codeberg.org/PrivacySafe/security-patches/releases) or [GitHub](https://github.com/PrivacySafe/security-patches/releases).

| File | For |
|---|---|
| `psf-security-patches_26.10.30-1.0.0_all.deb` | Debian, Ubuntu, Trisquel and derivatives |
| `psf-security-patches-26.10.30-1.0.0.noarch.rpm` | RHEL, Alma, Rocky, Fedora, CloudLinux and derivatives |
| `psf-security-patches-26.10.30-1.0.0.tar.gz` | Any GNU/Linux: the source tree, plus the scripts to rebuild the packages |

Check the files against the release's `SHA256SUMS-<version>.txt` before installing, then:

```bash
sha256sum -c SHA256SUMS-26.10.30-1.0.0.txt
sudo apt install ./psf-security-patches_26.10.30-1.0.0_all.deb       # Debian family
sudo dnf install ./psf-security-patches-26.10.30-1.0.0.noarch.rpm    # RPM family
/opt/psf-security-patches/php/php2shell-mitigate.sh check             # read only
```

Each file also has a detached GPG signature, `FILE.asc`. Import the release key from the release page and confirm its fingerprint reads `4BAD A1D9 A399 352C D651 B1D7 4D36 5028 B8E5 6739` before you trust a signature.

### Where things go

- **`/opt/psf-security-patches/`** holds the whole tree: each tool in its own folder (`php/`, `nginx/`, `curl/` and so on) with its README, plus the governance documents and a `VERSION` file. Run the scripts from there.
- **`/usr/lib/systemd/system/php2shell-watch.service`** is the live watcher's unit, pointed at the `/opt` path. It is installed but not enabled; see [Watching live](php/README.md#watching-live).
- **Manual pages and an info manual:** `man psf-security-patches` is the overview, and every tool has its own page named after its script, such as `man psf-haproxy-check`. `info psf-security-patches` has the same material as one manual. The pages are generated from each script's own `--help` text, so they always match the tool, and the sources are in [`man/`](man/).
- **Documentation website:** it is online at [privacysafe.app/docs/security-patches](https://privacysafe.app/docs/security-patches/), and the packages install an offline copy: open `/usr/share/doc/psf-security-patches/html/index.html` in a browser (on RPM systems the folder is `psf-security-patches-<version>`). It starts with the newest vulnerabilities, groups the tools by kind of software, has a CVE index, a page on how the tools work, a glossary, one page per tool and per manual page, and a search that works offline. The offline copy loads nothing from other sites. The source is the [`site/`](site/) folder of the repository, built by `packaging/gen-site.py`.
- **License files:** `LICENSE` and `NOTICE` come with the package (`/usr/share/doc/psf-security-patches/` on Debian, `/usr/share/licenses/` on RPM systems), and the `.deb` carries a `copyright` file. Everything is CC0 1.0 Universal.

Installing runs nothing: there are no install or removal scripts. The only dependencies are bash 4.0 or newer and coreutils.

### Upgrading and removing

Install a newer release the same way and it replaces the old one in place. Releases before 26.10.30 were named `psf-security-packages`. The new package replaces them, so with `apt` or `dnf` there is nothing to uninstall first. To remove the tools:

```bash
sudo apt remove psf-security-patches     # Debian family
sudo dnf remove psf-security-patches     # RPM family
```

Removing the package deletes only the files it installed. It does not undo what a tool did to your system when you ran it, such as an ini drop-in, an AppArmor profile or a distrusted certificate. Use each tool's own `cleanup`, `remove` or `restore` command, described in its README, before you remove the package.

Each tool still targets the systems named in its own README: for example the PHP2Shell AppArmor mitigation is for Debian-family systems, and the cPanel variant is for EasyApache 4. See [`packaging/`](packaging/README.md) for how releases are built and verified.

## 🗓️ Updates

See the [changelog](CHANGELOG.md) for new tools and changes, newest first.

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
