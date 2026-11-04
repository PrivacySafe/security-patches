<!--
  The two sections the documentation site shows on its home page and in its menu and feed.
  They are not in the README, so the README stays the way GitHub and Codeberg readers see it.
  Update "Newest" with each release: one row per advisory, newest first, with the link to the tool's README.
  gen-site.py reads this file; packaging/check-site.py checks every link in it.
-->

## Start here

1. Run the tool's `check`. It changes nothing.
2. If you are exposed, install the vendor's update. That is the permanent fix.
3. If you cannot update yet, run `mitigate --dry-run` to see what the protection would do, then `mitigate`. `rollback` undoes it.
4. If the flaw was being exploited, run `hunt`, then change any password, key or token an attacker could have reached.

Each tool has its own page with the exact commands.

## Newest: 22 October to 2 November 2026

The vulnerabilities from the last days of October, newest first.

| Date | What happened | Who is affected | What you get |
|---|---|---|---|
| 3 November | [Linux kernel module blocker](../../linux-kernel/README.md#linux-kernel-module-block): a generic tool that stops any module from loading, with a list of 42 modules from recent exploits to rarely needed attack surface | Any Linux system | List, check, reversible blocks, status |
| 3 November | [Linux kernel IPv4 TCP use-after-free](../../linux-kernel/README.md#linux-kernel-ireq-opt-check) (CVE-2026-98432): an unauthenticated peer can trigger it with a SYN that carries IP options, and remote code execution has been shown against an MPTCP listener | Every Linux kernel from 4.4 until its branch's fixed release | Check, hunt, and reductions you can undo |
| 2 November | [eMudhra on macOS](../../pki/README.md#emudhra-on-macos): the command line tools that ship with macOS (`curl`, `git`, `python3`, `pip`) still trust the compromised eMudhra intermediates through `/etc/ssl/cert.pem`, and hosted macOS CI images keep an old Homebrew `ca-certificates` (no new CVE) | macOS machines and runners | Check, a reversible fix and a CI step |
| 2 November | [BTCPay Server](../../btcpayserver/README.md#btcpay-server-check): hot wallets drained on instances running 2.4.1 or earlier from 1 November. The fix is a fresh server and a new wallet, not an update (no CVE) | BTCPay Server 2.4.1 and earlier, and any host that ran it | Check, recovery plan, evidence archive, hunt, hardening review and a Tor option |
| 30 October | [vsftpd](../../vsftpd/README.md#vsftpd-ftps-data-channel-hijack): a resumed FTPS session ticket is accepted as proof that a data connection belongs to the logged-in user, so someone who shares your source IP can take over a transfer (CVE-2026-119568). A separate denial of service affects Red Hat family packages (CVE-2025-14242) | vsftpd 3.0.5 and older with FTPS turned on | A check, protection you can undo, optional hardening |
| 29 October | [Claude Code extension backdoor](../../claude-code-vsx/README.md#claude-code-extension-ssh-backdoor): tampered builds 2.1.312 and 2.1.313 were served from Cursor's marketplace and planted an SSH key and a persistent tunnel (no CVE) | Developers on GNU/Linux, macOS and Windows | Check, hunt, update, key inventory, clean-up, firewall block (Windows: check) |
| 25 October | [Brotli](../../brotli/README.md#brotli-checker-quick-start): an out-of-bounds write in the decoder, reachable from Node.js and many other programs (CVE-2026-111497) | libbrotli and everything that bundles it | Check and audit |
| 24 October | [Grav core](../../grav/README.md#grav-core-check): a page editor can run arbitrary public static methods, fixed in 2.2.13 (CVE-2026-116019) | Grav 2.0.15 to 2.2.12 | Check and hunt |
| 24 October | [PHP2Shell](../../php/detect/README.md): a honeypot report confirmed the exploit chain in the wild | PHP hosts | Detection rules and [web server guards](../../php/edge/README.md) |
| 23 October | [baserCMS 5](../../basercms/README.md#basercms-check): admin SQL injection, path traversal and deserialization that leads to command execution (CVE-2026-114621, CVE-2026-114622, CVE-2026-114624) | baserCMS 5.0.0 to 5.4.1 | Check |
| 23 October | [openapi-typescript-codegen](../../openapi/README.md#openapi-typescript-codegen-code-injection-check): code injection through the API document (CVE-2026-108551) | Projects and CI jobs that generate clients with it | Check and a scan of the generated code |
| 23 October | [Ruby and GitLab](../../ruby/README.md#ruby-and-gitlab-regexp-check): memory corruption in Onigmo, Ruby's regular expression engine (CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264) | Ruby runtimes, Ruby apps and GitLab | Check and audit |
| 22 October | [Django REST framework](../../django/README.md#drf-check): an oversized `Accept` header burns CPU (CVE-2026-114138), and `TokenProxy.delete()` revokes nothing (CVE-2026-114137) | DRF installs | Check, an nginx rule, rollback |
| 22 October | [libexpat](../../expat/README.md#libexpat-billion-laughs-check): entity amplification is detected too late (CVE-2026-115506) | libexpat, pyexpat and programs that embed expat | Check and a scan for embedded copies |
| 22 October | [HAProxy](../../haproxy/README.md#haproxy-http2-ping-check): a truncated HTTP/2 PING frame pins a worker thread (CVE-2026-110353) | HAProxy 3.1 to 3.4 | Check, configuration audit, the vendor's workaround, rollback |
| 22 October | [rsyslog](../../rsyslog/README.md#rsyslog-dynafile-audit): path traversal through `dynaFile` (CVE-2026-92709) | rsyslog configurations | Configuration audit, protection, rollback |
| 22 October | [YOOtheme Pro](../../yootheme/README.md#yootheme-check): unauthenticated remote code execution, CVSS 10.0 (CVE-2026-102785) | YOOtheme Pro 5 on WordPress and Joomla | Check, hunt, web server rule, rollback |
