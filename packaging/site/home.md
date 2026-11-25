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

## Newest: 2 to 25 November 2026

The vulnerabilities from November, newest first.

| Date | What happened | Who is affected | What you get |
|---|---|---|---|
| 25 November | [Drupal core installer](../../web-apps/drupal/README.md#drupal-installer-check): anyone can reinstall a Drupal site through `core/install.php`, a takeover; exploited, and still open after the 18 November fix for sites in an incomplete install state (CVE-2026-132165, CVE-2026-136716) | Drupal 10 and 11 sites, and end-of-life branches | Check, hunt, mitigation that moves the installer into a verified backup, rollback |
| 23 November | [VMware vCenter](../../servers/vmware/README.md#vcenter-dirsvc): anyone who can reach port 2012 gets an administrator session, exploited since September (CVE-2026-123890) | vCenter before 9.1.1.0200, 9.0.2.0200 and 8.0 U3m, and 7.0 | Remote check, hunt, port allowlist and rollback |
| 23 November | [N-central and Apache Axis](../../servers/n-central/README.md#ncentral-legacyapi): the Legacy API gives root with no login, exploited (CVE-2026-90436) | N-central before 2026.4 HF3; Apache Axis 1.x | Remote check, Axis inventory, hunt |
| 23 November | [Idunno.AntiCsrf](../../web-apps/aspnet/README.md#idunno-anticsrf): one anonymous POST to an ASP.NET WebForms page runs code, exploited, and the 2008 module will never be fixed (CVE-2026-131914) | Sites that register the module, on Mono or IIS | Check, hunt, `web.config` mitigation and rollback, in bash and PowerShell |
| 23 November | [Java4Shell](../../runtimes/java/README.md#java4shell): attacker-chosen Base64 overflows a buffer on AVX-512 VBMI CPUs (CVE-2026-114938) | Java 17.0.6+, 21, 25 and 27, bundled copies too | Check and a workaround flag for services |
| 23 November | [pam-mysql](../../system/pam-mysql/README.md#pam-mysql): an account with no stored password logs in with any password (CVE-2026-124749) | Logins checked against MySQL | Check and hunt |
| 23 November | [AI attack frameworks](../../threats/agentic-attacks/README.md#agentic-attacks): AI agents run whole intrusions with ARTEX, CAIRN, PentAGI, HexStrike, CyberStrikeAI and more; backdoored ARTEX images hand the host to a third party (no CVE) | Hosts that run them, were reached by them, or are exposed | Check, hunt and indicator export |
| 23 November | [iTerm2](../../developer/iterm2/README.md#iterm2-kitty): showing a file with cat runs commands (no CVE) | iTerm2 3.6.1 to 3.7.8 on macOS | Check and file scan |
| 23 November | [binary-parser](../../developer/binary-parser/README.md#binary-parser-code-injection-check): a parser definition someone else controls runs as JavaScript when the parser compiles (CVE-2026-134814, CVE-2026-1245) | Node.js applications that build definitions from data, every release before 2.3.1 | Check and source audit |
| 22 November | [Apache Roller](../../web-apps/apache-roller/README.md#xmlrpc): unauthenticated deserialization through XML-RPC, exploited and in CISA's catalog (CVE-2026-129448, CVE-2026-82384) | Roller 4.0.0 to 6.1.5 | Check, hunt, mitigation and rollback |
| 22 November | [Ghostscript Upload2Shell](../../system/ghostscript/README.md#upload2shell): a crafted font escapes `-dSAFER`, reached through ImageMagick, Pillow, WordPress and others (CVE-2026-125396) | Ghostscript before 10.08.0 | Check, hunt, ImageMagick policy mitigation and rollback |
| 20 November | [Etherpad](../../web-apps/etherpad/README.md#static-traversal): unauthenticated path traversal that chains to code execution (CVE-2026-114516) | etherpad-lite 1.8.14 to 3.3.2 | Check, hunt, nginx block and rollback |
| 20 November | [KVM on AMD](../../system/linux-kernel/README.md#kvm-guest-to-host-escape-on-amd-nested-virtualization-cve-2026-99312): a guest can reach host memory through nested virtualization (CVE-2026-99312) | AMD hosts running KVM guests | Check and mitigation |
| 19 November | [Apache mod_http2](../../servers/apache/README.md#mod-http2): unauthenticated remote code execution (CVE-2026-119618) | Apache HTTP Server 2.4.55 to 2.4.70 with HTTP/2 | Check, hunt, HTTP/2 disable and rollback |
| 19 November | [MySQL client programs](../../servers/mysql/README.md#client-programs): a hostile server can attack the client (CVE-2026-114952) | MySQL client packages; no fix for 8.0 | Check and hardening |
| 19 November | [phpAfterShell](../../runtimes/php/README.md#php2shell-mitigation): a session file torn mid-update is read back as trusted state (CVE-2026-126714) | Every current PHP branch | Mitigation keeps upload progress off |
| 18 November | [nginx2root](../../servers/nginx/README.md#nginx2root): HTTP/2 code execution with a public proof of concept, plus HTTP/3, resolver and mail proxy flaws (CVE-2026-123007 and others) | nginx before 1.30.7 and 1.31.9 | Check, audit, hunt, workarounds and rollback |
| 17 November | [Optimizely OPTIMJACK](../../developer/optimizely/README.md#optimizely-optimjack): hijacked snippets served a card skimmer to visitors (no CVE) | Sites that load Optimizely Web Experimentation | Check, hunt and CSP review |
| 15 November | [NoisyTCP](../../system/linux-kernel/README.md#linux-kernel-noisytcp-check): anyone who can reach a TCP port can crash a Linux server whose packets are spread across CPUs, no login needed; a sibling flaw keeps it open on Arm and POWER kernels fixed for the first (CVE-2026-99288, CVE-2026-99676) | The Linux kernel from 4.4 on every distribution | Check, hunt, stopgaps and rollback |
| 5 November | [OpenSSH on musl](../../system/openssh-musl/README.md#openssh-musl-password-bypass): a long password matches an account with no password set (CVE-2026-123158) | sshd on Alpine, OpenWrt and other musl systems without PAM | Check, hunt, stopgap and rollback |
| 4 November | [WordPress upgrade window](../../web-apps/wordpress-upgrade/README.md#wordpress-upgrade-check): unauthenticated code execution while a core update runs, exploited (CVE-2026-119977) | WordPress core 4.7.0 to 7.1.3 | Check, hunt and a web server rule |
| 4 November | [APT](../../system/apt/README.md#apt-nov2026-check): a package download can be swapped after it was verified (CVE-2026-109518) | Debian, Ubuntu and derivatives | Check, hunt, stopgap and rollback |
| 3 November | [Linux kernel module blocker](../../system/linux-kernel/README.md#linux-kernel-module-block): a generic tool that stops any module from loading, with a list of 42 modules from recent exploits to rarely needed attack surface | Any Linux system | List, check, reversible blocks, status |
| 3 November | [Linux kernel IPv4 TCP use-after-free](../../system/linux-kernel/README.md#linux-kernel-ireq-opt-check) (CVE-2026-98432): an unauthenticated peer can trigger it with a SYN that carries IP options, and remote code execution has been shown against an MPTCP listener | Every Linux kernel from 4.4 until its branch's fixed release | Check, hunt, and reductions you can undo |
| 2 November | [eMudhra on macOS](../../system/pki/README.md#emudhra-on-macos): the command line tools that ship with macOS (`curl`, `git`, `python3`, `pip`) still trust the compromised eMudhra intermediates through `/etc/ssl/cert.pem`, and hosted macOS CI images keep an old Homebrew `ca-certificates` (no new CVE) | macOS machines and runners | Check, a reversible fix and a CI step |
| 2 November | [BTCPay Server](../../web-apps/btcpayserver/README.md#btcpay-server-check): hot wallets drained on instances running 2.4.1 or earlier from 1 November. The fix is a fresh server and a new wallet, not an update (no CVE) | BTCPay Server 2.4.1 and earlier, and any host that ran it | Check, recovery plan, evidence archive, hunt, hardening review and a Tor option |
