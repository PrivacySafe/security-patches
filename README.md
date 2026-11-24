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

This repository contains security mitigations, system-hardening scripts, and auditing tools developed for PrivacySafe and Ivy Cyber infrastructure. PrivacySafe publishes these tools so that others can study, adapt, and use them to protect their own systems, including when upstream security fixes are not yet available.

**84 scripts addressing 212 CVEs across 85 software projects and 11 programming languages, plus 9 other global security incidents.**

**Documentation:** open [`docs/index.html`](docs/index.html) in a browser for the offline site (every tool, a CVE index, a glossary and the manual pages in HTML), or read it online at [privacysafe.app/docs/security-patches](https://privacysafe.app/docs/security-patches/). The packages also install a manual page for every tool (`man psf-<tool>`) and an info manual.

> 💚 If this work is helpful, please consider [supporting PrivacySafe Foundation](https://privacysafe.foundation), a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, and public-interest privacy and security research.

---

## 📦 Available tools

The tools are grouped in six folders. Each tool has its own folder inside one of them, with a README that explains the flaw, the commands and how to undo any change.

### Servers, proxies and network services

In [`servers/`](servers/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [VMware vCenter directory service](servers/vmware/README.md#vcenter-dirsvc) | vCenter 7.0, 8.0 before U3m, 9.0 before 9.0.2.0200 and 9.1 before 9.1.1.0200, checked remotely from GNU/Linux or on the appliance: administrator session without a password, exploited, CISA KEV | CVE-2026-123890 | Remote version check, hunt, port 2012 allowlist on the appliance (`mitigate`) and rollback |
| [N-central Legacy API and Apache Axis](servers/n-central/README.md#ncentral-legacyapi) | On-premises N-able N-central before 2026.4 HF3 with the Legacy API on, and Apache Axis 1.x anywhere: unauthenticated chain to root, exploited, CISA KEV | CVE-2026-90436 | Remote Legacy API check, Axis inventory, hunt |
| [nginx2root](servers/nginx/README.md#nginx2root) | nginx on GNU/Linux (HTTP/2, HTTP/3, resolver, mail proxy) | CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425 | Check, config audit, hunt, four workarounds (`mitigate`) and rollback |
| [nginx October 2026](servers/nginx/README.md#nginx-october-2026-check) | nginx and njs on GNU/Linux | CVE-2026-15176, CVE-2026-93479, CVE-2026-97205, CVE-2026-95101, CVE-2026-97629; njs: CVE-2026-101019, CVE-2026-101025 | Check, config audit, hunt, three workarounds (`mitigate`) and rollback |
| [vsftpd FTPS data channel hijack](servers/vsftpd/README.md#vsftpd-ftps-data-channel-hijack) | vsftpd 3.0.5 and older with FTPS enabled on a standalone listener, GNU/Linux | CVE-2026-119568, CVE-2025-14242 (Red Hat family packages) | Check, mitigation, optional hardening and rollback |
| [Apache Tomcat October 2026](servers/tomcat/README.md#apache-tomcat-october-2026-check) | Apache Tomcat 9.0, 10.1 and 11.0 on GNU/Linux | CVE-2026-103119, CVE-2026-101356 | Check, mitigation (`mitigate --ajp\|--http2`) and rollback |
| [HAProxy HTTP/2 PING](servers/haproxy/README.md#haproxy-http2-ping-check) | HAProxy 3.1 to 3.4 on GNU/Linux | CVE-2026-110353 | Check, config audit, vendor workaround (`mitigate`) and rollback |
| [Apache CouchDB](servers/couchdb/README.md#couchdb-check) | Apache CouchDB 3.5.2 and earlier on GNU/Linux | CVE-2026-86471 | Read-only check |
| [ISC BIND 9](servers/bind/README.md#bind-check) | BIND 9 name servers on GNU/Linux (9.18 and older get no upstream fix) | CVE-2026-94300 | Read-only check |
| [rsyslog dynaFile](servers/rsyslog/README.md#rsyslog-dynafile-audit) | rsyslog configurations on GNU/Linux | CVE-2026-92709 | Configuration audit, secure-path fix (`mitigate`) and rollback |
| [Apache Traffic Server](servers/trafficserver/README.md#trafficserver-check) | Traffic Server 8.x to 10.2.0 that loads the experimental magick or tsmemcache plugin (CVSS 10) | CVE-2026-111813, CVE-2026-111811 | Read-only check |
| [Apache Pulsar and Pulsar Manager](servers/pulsar/README.md#pulsar-check) | Pulsar brokers with the MultiRoles authorization provider and an anonymous role, or a proxy role; and any Pulsar Manager (retired) | CVE-2026-105869, CVE-2026-105942, CVE-2026-105944 | Read-only check |
| [Incus](servers/incus/README.md#incus-check) | Incus 6.0 before 6.0.7, 7.0 before 7.0.2 and 7.1 to 7.4: a confined client can write to the host as root | CVE-2026-115375, CVE-2026-115377, CVE-2026-115372 | Read-only check |
| [nginx-ui restricted-directive bypass](servers/nginx-ui/README.md#nginx-ui-check) | nginx-ui below 2.4.1: a logged-in user can bypass the restricted-directive check, which leads to code execution where nginx loads njs, Perl or Lua | CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319 | Read-only check and hunt |
| [nginx-ui directive injection](servers/nginx-ui/README.md#nginx-ui-check) | nginx-ui below 2.4.1: authenticated directive injection leading to RCE when nginx loads njs/Perl/Lua | CVE-2026-84316, CVE-2026-84317, CVE-2026-84318 | Read-only check |
| [Apache mod_http2](servers/apache/README.md#mod-http2) | Apache HTTP Server 2.4.55 to 2.4.70 with mod_http2 loaded and HTTP/2 enabled; standalone mod_h2 2.0.8 to 2.0.42 (archived, no fix) | CVE-2026-119618 | Check, hunt, HTTP/2 disable (`mitigate`) and rollback |
| [MySQL client programs](servers/mysql/README.md#client-programs) | MySQL client packages (mysql, mysqldump, mysqlbinlog and others) through the November 2026 CSPU batch; no fix exists for the 8.0 line | CVE-2026-114952 | Check, and speculative cleartext-plugin hardening (`harden`) with rollback |

### Operating system and libraries

In [`system/`](system/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [Brotli checker](system/brotli/README.md#brotli-checker-quick-start) | libbrotli and the processes using it, plus Node/Bun/Python/Ruby/PHP/Envoy/Istio/cdxgen and containers on GNU/Linux | CVE-2026-111497 (Broccoli2Shell) | Read-only check and audit |
| [libheif HEIF/AVIF Decoder](system/heif/README.md#libheif-heifavif-decoder-check) | libheif, ImageMagick and Discourse on GNU/Linux | [writeup](https://www.hacktron.ai/blog/hacking-openai); DSA-6417-1 | Check, audit and ImageMagick coder mitigation |
| [eMudhra CA Compromise](system/pki/README.md#emudhra-intermediate-ca-compromise-mitigation) | System CA store on Debian/Ubuntu/Trisquel and derivatives | [disclosure](https://emudhra.we-have-a-problem.com/); Go: CVE-2026-111943 | Mitigation |
| [eMudhra CA Compromise on macOS](system/pki/README.md#emudhra-on-macos) | macOS system CA bundle `/etc/ssl/cert.pem` and Homebrew `ca-certificates` | [disclosure](https://emudhra.we-have-a-problem.com/#macos-curl); [Apple](https://support.apple.com/en-us/149555) | Check and mitigation |
| [curl HTTP/2 upload](system/curl/README.md#curl-http2-upload-use-after-free-check) | curl and libcurl on GNU/Linux | CVE-2026-92392 | Read-only check and audit |
| [pam-mysql](system/pam-mysql/README.md#pam-mysql) | pam-mysql in a login service's PAM stack (sshd by default): accounts with no stored password let in with any password | CVE-2026-124749 | Check (with an optional count of rows with no password) and hunt |
| [Pillow 13.0.0](system/pillow/README.md#pillow-13-security-release-check) | Pillow in Python environments and lock files on GNU/Linux | CVE-2026-96639, CVE-2026-112900 | Read-only check |
| [libexpat billion laughs](system/expat/README.md#libexpat-billion-laughs-check) | libexpat, Python's pyexpat and programs that embed expat on GNU/Linux | CVE-2026-115506 | Read-only check and embedded-copy scan |
| [Ghostscript Upload2Shell](system/ghostscript/README.md#upload2shell) | Ghostscript before 10.08.0: -dSAFER sandbox escape via a crafted font, reached through ImageMagick, Pillow, WordPress, Roundcube, CUPS and more, by content not file name | CVE-2026-125396 | Check (with a release-candidate trap caveat), hunt, ImageMagick `policy.xml` `mitigate` and rollback |
| [Linux kernel ebtables SNAT](system/linux-kernel/README.md#linux-kernel-check) | The Linux kernel on every distribution: out-of-bounds write in the ebtables SNAT ARP rewrite, exploited in the wild | CVE-2026-53266 | Read-only check |
| [Linux kernel local root quartet](system/linux-kernel/README.md#linux-kernel-lpe-check) | The Linux kernel on every distribution: four local privilege escalations with public exploits (IPsec AH6, TUN/TAP, PPPoE, SCTP), each fixed at a different release per branch | CVE-2026-80844, CVE-2026-81000, CVE-2026-68121, CVE-2026-74469 | Check, opt-in protective measures (`mitigate`) and rollback |
| [Linux kernel IPv4 TCP use-after-free](system/linux-kernel/README.md#linux-kernel-ireq-opt-check) | The Linux kernel from 4.4 on every distribution: a race in the IPv4 TCP handshake that an unauthenticated peer can trigger with IP options, remote code execution shown with an MPTCP listener | CVE-2026-98432 | Check, hunt and reversible reductions |
| [Linux kernel module blocker](system/linux-kernel/README.md#linux-kernel-module-block) | The Linux kernel on every distribution: stop any module from loading, with a list of 42 (recent exploits, older well known flaws, rarely needed attack surface), a status command and a rollback | CVE-2026-80844, CVE-2026-81000, CVE-2026-68121, CVE-2026-74469, CVE-2026-53266, CVE-2026-98432 | List, check and reversible blocks |
| [APT package downloads](system/apt/README.md#apt-nov2026-check) | Debian, Ubuntu and their derivatives: APT before the fixed release of its line (3.0.4, 2.6.2, 2.8.4 and others), when it follows redirects and retries downloads | CVE-2026-109518 | Check, hunt, stopgap (`mitigate`) and rollback |
| [OpenSSH musl password bypass](system/openssh-musl/README.md#openssh-musl-password-bypass) | sshd linked against musl (Alpine, OpenWrt, buildroot, Yocto) without PAM in effect: a password over 256 bytes matches any account with no password set | CVE-2026-123158 | Check, hunt, stopgap (`mitigate`) and rollback |
| [OpenSSL DTLS heap disclosure](system/openssl/README.md#openssl-check) | OpenSSL 4.0, 3.6, 3.5, 3.4, 3.0, 1.1.1 and 1.0.2 before their fixed releases: a High flaw reachable through DTLS | CVE-2026-84782 | Read-only check |

### Language runtimes

In [`runtimes/`](runtimes/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [PHP2Shell](runtimes/php/README.md#php2shell-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560, CVE-2026-126714 | Mitigation |
| [PHP2Shell live watch](runtimes/php/README.md#watching-live) | PHP-FPM, Apache and nginx logs on any GNU/Linux; optional systemd unit | CVE-2026-109618, CVE-2026-109619 | Read-only live monitor |
| [PHP2Shell on cPanel](runtimes/php/README.md#php2shell-on-cpanel-easyapache-4) | cPanel/WHM servers running EasyApache 4 PHP (ea-php74 to ea-php85), any handler | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560, CVE-2026-126714 | Mitigation, check and audit |
| [PHP session audit](runtimes/php/README.md#php-session-audit-cve-2026-115560) | Any PHP host | CVE-2026-115560, CVE-2026-126714 | Read-only audit |
| [PHP2Shell edge guards](runtimes/php/edge/README.md) | Apache httpd (server configuration or `.htaccess`) and nginx in front of PHP, with request body and header limits, and a curl tester | CVE-2026-109618, CVE-2026-109619 | Compensating controls (log-only first) |
| [PHP2Shell detection rules](runtimes/php/detect/README.md) | auditd, Tetragon and nftables on GNU/Linux | CVE-2026-109618, CVE-2026-109619 | Detection content |
| [Node.js October 2026](runtimes/node/README.md#nodejs-october-2026-mitigation) | Node.js on GNU/Linux; systemd for the guard | CVE-2026-111497 (Brotli) and 9 Node CVEs | Mitigation (Node only) |
| [Ruby and GitLab Regexp/case conversion](runtimes/ruby/README.md#ruby-and-gitlab-regexp-and-case-conversion-check) | Ruby runtimes, Ruby apps and GitLab on GNU/Linux | CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264; GHSA-34m4-m9fh-gqp5 and 6 more (CVE pending) | Read-only check and audit |
| [Java4Shell](runtimes/java/README.md#java4shell) | Java 17.0.6+, 21, 25 and 27 (including runtimes bundled with Jira, Confluence, Jenkins and others) on CPUs with AVX-512 VBMI | CVE-2026-114938 | Check of CPU, runtimes and running JVMs; `-XX:-UseBASE64Intrinsics` drop-ins for systemd services (`mitigate`) and rollback |

### Content management and web applications

In [`web-apps/`](web-apps/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [Idunno.AntiCsrf on IIS and Mono](web-apps/aspnet/README.md#idunno-anticsrf) | ASP.NET WebForms sites that register the defunct Idunno.AntiCsrf module, on Mono (mod_mono, XSP, fastcgi-mono-server) on GNU/Linux and on Windows and IIS: one anonymous POST runs code, exploited, no fix | CVE-2026-131914 | Check, log hunt, `web.config` mitigation (`mitigate`) and rollback, in bash for GNU/Linux and PowerShell for Windows |
| [Nextcloud Collabora Built-in CODE](web-apps/nextcloud/README.md#nextcloud-collabora-built-in-code-command-injection) | Nextcloud with the richdocumentscode app on GNU/Linux | CVE-2026-110447 | Mitigation, check and hunt |
| [Plex Media Server Plex2Shell](web-apps/plex/README.md#plex-media-server-plex2shell-rce-chain) | Plex Media Server on GNU/Linux | CVE-2026-96651, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656 | Read-only check and hunt |
| [WordPress XSS2Shell](web-apps/wordpress/README.md#wordpress-xss2shell-check) | WordPress Core sites and their web server logs on GNU/Linux | CVE-2026-64638 | Read-only check, audit and hunt |
| [BTCPay Server hot wallet thefts](web-apps/btcpayserver/README.md#btcpay-server-check) | BTCPay Server 2.4.1 and earlier, on a Docker host or any server you can reach by address; GNU/Linux | No CVE (1 November 2026) | Check, recovery plan, evidence archive, hunt, hardening review and a Tor option; `--strict` and `--json` |
| [WordPress plugins October 2026](web-apps/wordpress/README.md#wordpress-plugins-october-2026-check) | LiteSpeed Cache, Rank Math PRO, OttoKit, SureCart, LatePoint, Amelia, Profile Builder and Bricksforge (exploited upload to code execution) in WordPress installs on GNU/Linux | CVE-2026-113500, CVE-2026-111862, CVE-2026-110372, CVE-2026-112241, CVE-2026-110653, CVE-2026-112327, CVE-2026-112242, CVE-2026-85097 | Check, hunt, plugin deactivation (`mitigate`) and rollback |
| [Drupal Webform](web-apps/drupal/README.md#drupal-webform-check) | Drupal sites with the Webform module on GNU/Linux | CVE-2026-96355 | Read-only check |
| [Roundcube Webmail October and November 2026](web-apps/roundcube/README.md#roundcube-webmail-october-2026-check) | Roundcube on GNU/Linux, including copies bundled by hosting panels; a second, unnumbered round of 17 fixes followed the first within a month | CVE-2026-114716 | Read-only check and hunt |
| [Craft CMS](web-apps/craft/README.md#craft-cms-check) | Craft CMS 4.x and 5.x projects on GNU/Linux | CVE-2026-112777 | Read-only check |
| [Drupal core Field UI and Entity List](web-apps/drupal/README.md#drupal-core-check) | Drupal 8.9 to 12 sites on GNU/Linux (end-of-life branches move to a supported branch) and the contributed Entity List module | CVE-2026-108097, CVE-2026-108099 | Check, Drupal's Field UI workaround (`mitigate`) and rollback |
| [YOOtheme Pro](web-apps/yootheme/README.md#yootheme-check) | YOOtheme Pro 5 on WordPress and Joomla (CVSS 10.0) | CVE-2026-102785 | Check, hunt, web server rule (`mitigate`) and rollback |
| [Grav Login plugin](web-apps/grav/README.md#grav-login-check) | Grav CMS sites with Login 3.6.0 to 3.9.12 | CVE-2026-114658 | Read-only check and hunt |
| [Grav core allowlist bypass](web-apps/grav/README.md#grav-core-check) | Grav 2.0.15 to 2.2.12: a page editor can run arbitrary public static methods | CVE-2026-116019 | Read-only check and hunt |
| [WordPress page-template path traversal](web-apps/wordpress-pt/README.md#wordpress-pt-check) | WordPress core 4.7.0 to 7.1.1: unauthenticated path traversal, local PHP file inclusion, exploited in the wild | CVE-2026-87902 | Read-only check and hunt |
| [Etherpad static path traversal](web-apps/etherpad/README.md#static-traversal) | etherpad-lite 1.8.14 to 3.3.2: unauthenticated path traversal, reachable before auth middleware, chains to RCE via the admin plugin installer | CVE-2026-114516 | Check, hunt, nginx block (`mitigate`) and rollback |
| [Apache Roller XML-RPC deserialization](web-apps/apache-roller/README.md#xmlrpc) | Roller 4.0.0 to 6.1.5: unauthenticated deserialization RCE, exploited in the wild, CISA KEV; the admin-UI XML-RPC toggle does not gate it | CVE-2026-129448, CVE-2026-82384 | Check, hunt, `mitigate` (either named workaround) and rollback |
| [WordPress upgrade-window RCE](web-apps/wordpress-upgrade/README.md#wordpress-upgrade-check) | WordPress core 4.7.0 to 7.1.3: unauthenticated code execution while a core update runs, exploited in the wild | CVE-2026-119977 | Read-only check, hunt and the web server rule to add before updating |
| [Magento, Adobe Commerce and Mage-OS: PolyShell, StyleSmuggler, BlockStrap](web-apps/magento/README.md#magento-check) | Magento and Adobe Commerce 2.4.4 to 2.4.9 and Mage-OS: unauthenticated upload to code execution (PolyShell), customer account takeover, and two CVSS 10.0 template-engine RCEs, three of them exploited and in CISA KEV; the StyleSmuggler hotfix is in no release, the October one included | CVE-2026-48356, CVE-2026-71362, CVE-2026-75650, CVE-2026-103849 | Check per flaw with hotfix evidence and upload-folder rules, hunt (store files, host implants, logs), `mitigate` (upload-folder `.htaccess` written as the owner, nginx guard snippet) and rollback |
| [Zammad session hijack and privilege escalation](web-apps/zammad/README.md#zammad-check) | Zammad 6.3.0 to 6.5.4: session hijack to code execution as the zammad user, chained to root, exploited in the wild | CVE-2026-102489, CVE-2026-102490 | Read-only check and hunt |
| [Joomla core, September 2026 release](web-apps/joomla/README.md#joomla-check) | Joomla 4.0.0 to 5.4.8 and 6.0.0 to 6.1.3: 16 core fixes, two rated High (directory deletion, SSRF) | CVE-2026-90915, CVE-2026-92222, CVE-2026-92227 and others | Check, administrator path restriction (`mitigate --allow`) and rollback |
| [baserCMS 5](web-apps/basercms/README.md#basercms-check) | baserCMS 5.0.0 to 5.4.1 (before 5.3.2 and 5.4.2): admin SQL injection, path traversal, and deserialization leading to command execution | CVE-2026-114621, CVE-2026-114622, CVE-2026-114624 | Read-only check |
| [wp2shell, WordPress core RCE](web-apps/wordpress/README.md#wp2shell-check) | WordPress core 6.8.0 to 6.8.5, 6.9.0 to 6.9.4 and 7.0.0 to 7.0.1: unauthenticated remote code execution, exploited in the wild | CVE-2026-63030, CVE-2026-60137 | Check, hunt, batch-route block (`mitigate`) and rollback |

### Developer platforms, tools and supply chain

In [`developer/`](developer/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [openapi-typescript-codegen](developer/openapi/README.md#openapi-typescript-codegen-code-injection-check) | Projects, CI jobs and generated TypeScript clients on GNU/Linux | CVE-2026-108551 | Read-only check and generated-code scan |
| [binary-parser](developer/binary-parser/README.md#binary-parser-code-injection-check) | Node.js projects, installed and bundled copies, and Debian/Ubuntu `node-binary-parser` on GNU/Linux: code injection through a parser definition, every release before 2.3.1 | CVE-2026-134814, CVE-2026-1245 | Read-only check and source audit |
| [iTerm2 on macOS](developer/iterm2/README.md#iterm2-kitty) | iTerm2 3.6.1 to 3.7.8 on the Macs administrators use: a file shown with cat types commands into the shell | No CVE at time of writing | Check, and a scan for files that carry the escape sequence (macOS and GNU/Linux) |
| [LiteLLM supply-chain compromise](developer/litellm/README.md#litellm-11070-supply-chain-compromise) | litellm in Python environments and containers on GNU/Linux | [incident](https://github.com/BerriAI/litellm/issues/47826) (litellm 1.107.0, no CVE) | Detect, hunt and contain |
| [GhostAction developer-machine stealer](developer/ghostaction/README.md#ghostaction-developer-machine-stealer) | Git repositories and developer machines on GNU/Linux | [incident](https://opensourcemalware.com/blog/ghostaction-attack-escalates) (campaign, no CVE) | Scan, hunt and contain |
| [Claude Code extension SSH backdoor](developer/claude-code-vsx/README.md#claude-code-extension-ssh-backdoor) | Claude Code extension 2.1.312 and 2.1.313 served by the Cursor marketplace (29 October 2026); developer machines on GNU/Linux, macOS and Windows (Cursor's notice publishes scripts for macOS and Windows only; the Windows script here is a read-only check) | [incident](https://cursor.com/blog/claude-code-extension-security-notice) (no CVE) | Check, hunt, clean and block (Windows: check) |
| [Optimizely OPTIMJACK supply-chain compromise](developer/optimizely/README.md#optimizely-optimjack) | Optimizely Web Experimentation snippets (16 November 2026), on any site; sites that already use Optimizely, checked from GNU/Linux | [incident](https://blog.report-uri.com/) (no CVE) | Read-only check, hunt and CSP evaluation |
| [Laravel TokenGuard](developer/laravel/README.md#laravel-tokenguard-check) | Laravel apps on GNU/Linux | CVE-2026-114509 | Read-only check and protective middleware |
| [Next.js Server Actions, the August to November 2026 releases, and sharp](developer/nextjs/README.md#nextjs-server-actions-check) | Next.js projects on GNU/Linux, including 12.x to 14.x apps that get no fix, and the `sharp` each project pins | CVE-2026-94482, CVE-2026-119790, CVE-2026-119351, CVE-2026-119349, CVE-2026-119350, CVE-2026-119348, CVE-2026-119346, CVE-2026-119347, CVE-2026-96889, CVE-2026-75604, CVE-2026-114111, CVE-2026-114112, CVE-2026-114113 (and GHSA-673q-mjm6-r5xr, which has no CVE) | Read-only check |
| [Django REST framework](developer/django/README.md#drf-check) | DRF installs and pinned dependencies on GNU/Linux | CVE-2026-114138, CVE-2026-114137 | Check, nginx rule (`mitigate`) and rollback |
| [Gitea](developer/gitea/README.md#gitea-check) | Gitea up to 28.1.0 that trusts a user SSH certificate authority | CVE-2026-109553 | Read-only check |
| [Sentry for Next.js](developer/sentry/README.md#sentry-nextjs-check) | Next.js apps using `@sentry/nextjs` with `tunnelRoute` on a webpack build | CVE-2026-114139 | Read-only check |
| [Jupyter Server and nbconvert](developer/jupyter/README.md#jupyter-check) | Jupyter Server 2.0 to 2.5 with a gateway and a custom authorizer, and nbconvert 5.4 to 7.17.1 | CVE-2026-114135, CVE-2026-114140 | Read-only check |
| [Storybook](developer/storybook/README.md#storybook-check) | Storybook 8 to 11-alpha dev servers reachable from the network | CVE-2026-114126 | Read-only check |
| [Amazon SageMaker Python SDK](developer/sagemaker/README.md#sagemaker-check) | SageMaker SDK V2 before 2.257.3 and V3 before 3.10.0 (default bucket takeover) | CVE-2026-112408 | Read-only check |
| [LiteLLM proxy admin escalation](developer/litellm/README.md#litellm-proxy-admin-escalation) | LiteLLM proxy 1.87.0 up to the fixed release on each line | CVE-2026-114612 | Read-only check |
| [Jenkins plugins, advisory of 16 September 2026](developer/jenkins/README.md#jenkins-check) | 13 Jenkins plugins including Script Security (eight High sandbox bypasses) | CVE-2026-92122 to CVE-2026-92141 | Read-only check |
| [GitLab security releases, October 2026](developer/gitlab/README.md#gitlab-check) | Self-managed GitLab: seven High flaws from the 12 and 21 October releases (cross-site scripting, pipeline authorization, cache poisoning, an LDAP account takeover, a Duo prompt injection). 19.2.9 is not a full fix | CVE-2026-92883, CVE-2026-16301, CVE-2026-14814, CVE-2026-81839, CVE-2026-96893, CVE-2026-15723, CVE-2026-112212 | Read-only check |

### Active threats

In [`threats/`](threats/).

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [AI-driven attack frameworks](threats/agentic-attacks/README.md#agentic-attacks) | GNU/Linux hosts that run, were reached by, or are exposed to ARTEX, CAIRN, CyberStrikeAI, HexStrike AI, PentAGI and six other agentic attack frameworks (consoles, backdoored images, implants, web shells, log traces): exploited since August 2026, FBI FLASH on ARTEX | No CVE (attack tools) | Check (images, consoles, processes, files, hashes, AI clients, weaknesses), hunt (logs, folders, histories, connections), and indicator export for firewalls and SIEMs |

### Red Hat advisories

Where Red Hat has published an advisory for a CVE a tool covers, the tool's README has a **Red Hat advisories** section with the advisory, the fixed package release and the RHEL stream, and [REDHAT-ADVISORIES.md](REDHAT-ADVISORIES.md) lists them all by tool and by CVE. A Red Hat build is judged by its RPM release, not by the upstream version number. The packages install a checker for this, `rhsa.py` (`man psf-rhsa`): `find` lists the advisories for a CVE and `verify --rpm` compares every installed package with Red Hat's fix, within one stream and one version line, and says "check by hand" when it cannot judge. See [`packaging/rhsa/`](packaging/rhsa/README.md).

## 📥 Install from a package

Each release ships three files, all named `psf-security-patches` and versioned by release date, `YY.MM.DD-X.Y.Z` (for example `26.11.23-1.0.0`). Download them from the releases page on [Codeberg](https://codeberg.org/PrivacySafe/security-patches/releases) or [GitHub](https://github.com/PrivacySafe/security-patches/releases).

| File | For |
|---|---|
| `psf-security-patches_26.11.23-1.0.0_all.deb` | Debian, Ubuntu, Trisquel and derivatives |
| `psf-security-patches-26.11.23-1.0.0.noarch.rpm` | RHEL, Alma, Rocky, Fedora, CloudLinux and derivatives |
| `psf-security-patches-26.11.23-1.0.0.tar.gz` | Any GNU/Linux: the source tree, plus the scripts to rebuild the packages |

Check the files against the release's `SHA256SUMS-<version>.txt` before installing, then:

```bash
sha256sum -c SHA256SUMS-26.11.23-1.0.0.txt
sudo apt install ./psf-security-patches_26.11.23-1.0.0_all.deb       # Debian family
sudo dnf install ./psf-security-patches-26.11.23-1.0.0.noarch.rpm    # RPM family
/opt/psf-security-patches/runtimes/php/php2shell-mitigate.sh check             # read only
```

Each file also has a detached GPG signature, `FILE.asc`. Import the release key from the release page and confirm its fingerprint reads `4BAD A1D9 A399 352C D651 B1D7 4D36 5028 B8E5 6739` before you trust a signature.

### Where things go

- **`/opt/psf-security-patches/`** holds the whole tree: each tool in its own folder (`runtimes/php/`, `servers/nginx/`, `system/curl/` and so on) with its README, plus the governance documents and a `VERSION` file. Run the scripts from there.
- **`/opt/psf-security-patches/rhsa/rhsa.py`** is the Red Hat advisory checker, with its data and its README. On a Red Hat family host, `/opt/psf-security-patches/rhsa/rhsa.py verify --rpm` checks every installed package against Red Hat's published fixes, and `man psf-rhsa` documents it. It is a Python 3 program; the index of what it knows is [REDHAT-ADVISORIES.md](REDHAT-ADVISORIES.md).
- **`/usr/lib/systemd/system/php2shell-watch.service`** is the live watcher's unit, pointed at the `/opt` path. It is installed but not enabled; see [Watching live](runtimes/php/README.md#watching-live).
- **Manual pages and an info manual:** `man psf-security-patches` is the overview, and every tool has its own page named after its script, such as `man psf-haproxy-check`. `info psf-security-patches` has the same material as one manual. The pages are built from each script's own `--help` text when a release is built, so they always match the tool.
- **Documentation website:** it is online at [privacysafe.app/docs/security-patches](https://privacysafe.app/docs/security-patches/), and the packages install an offline copy: open `/usr/share/doc/psf-security-patches/html/index.html` in a browser (on RPM systems the folder is `psf-security-patches-<version>`). It starts with the newest vulnerabilities, groups the tools by kind of software, has a CVE index, a page on how the tools work, a glossary, one page per tool and per manual page, and a search that works offline. The offline copy loads nothing from other sites. It is built from the READMEs in this repository, so the READMEs are the documentation.
- **License files:** `LICENSE` and `NOTICE` come with the package (`/usr/share/doc/psf-security-patches/` on Debian, `/usr/share/licenses/` on RPM systems), and the `.deb` carries a `copyright` file. Everything is CC0 1.0 Universal.

Installing runs nothing: there are no install or removal scripts. The only dependencies are bash 4.0 or newer and coreutils. The Red Hat advisory checker also needs Python 3.8 or newer, which the packages recommend and do not require, so every other tool installs and runs without it.

### Upgrading and removing

Install a newer release the same way and it replaces the old one in place. To remove the tools:

```bash
sudo apt remove psf-security-patches     # Debian family
sudo dnf remove psf-security-patches     # RPM family
```

Removing the package deletes only the files it installed. It does not undo what a tool did to your system when you ran it, such as an ini drop-in, an AppArmor profile or a distrusted certificate. Use each tool's own `cleanup`, `remove` or `restore` command, described in its README, before you remove the package.

Each tool still targets the systems named in its own README: for example the PHP2Shell AppArmor mitigation is for Debian-family systems, and the cPanel variant is for EasyApache 4. See [`packaging/`](packaging/README.md) for how releases are built and verified.

**Root and sudo.** Commands that change a machine (`mitigate`, `rollback` and the tool-specific ones) need root. Run them from a named admin account with `sudo`, for example `sudo ./haproxy-check.sh mitigate`, not from a root login: sudo records who made the change. A tool that is started without root says so and prints the exact `sudo` command to run, and a tool started from the root account while sudo is available prints a one-line note and carries on (`PSF_NO_ROOT_NOTE=1` hides it). A hunt run without root sees only what that account can read, and says so instead of calling the result clean. The Claude Code extension tool's `update`, `clean` and `keys` work per user: run them as the account that uses the editor, not with sudo.

## 🗓️ Updates

See the [changelog](CHANGELOG.md) for new tools and changes, newest first.

## 🔒 One change at a time

A tool that changes the host (`mitigate`, `rollback`, `harden`, `block`, `apply` and the like) takes a lock first, so two runs started together, from a script or from two terminals, cannot overwrite each other's backups and manifests. The second run waits `PSF_LOCK_WAIT` seconds (default 30) and then stops with exit 2 and says why. The lock file is `STATE_DIR/.lock`, or `/var/lib/psf-security-patches/<tool>/.lock`. A dry run, `--help` and `version` never wait. The lock is held by a waiting `flock` process, not by the tool, so a service the tool starts does not keep it. Where `flock` is missing (macOS) nothing is locked. A tool whose default command changes the host (`php2shell-mitigate.sh`, `emudhra-mitigate.sh`) locks when it is run with no command, too. The two PHP2Shell tools and `emudhra-mitigate.sh` exit 1 instead of 2, as they do for every fatal error.

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
