# Changelog

Notable changes to PrivacySafe Security Patches, newest first.

## 2026-10-24

### Added

- [PHP2Shell on cPanel](php/README.md#php2shell-on-cpanel-easyapache-4): check, interim drop-in, status, restore and cleanup for EasyApache 4 PHP (`ea-php74` to `ea-php85`) under any handler, with patch detection and a check that the web server and FPM workers have restarted.
- [PHP2Shell edge guards](php/edge/README.md): Apache and nginx configuration that refuses multipart POSTs to paths you have not allowlisted (log-only first), cuts an oversized `Set-Cookie` on Apache, and documents request body and response header limits for both servers.
- [PHP2Shell detection rules](php/detect/README.md): an auditd rule, a Tetragon filter and a log-only outbound-connection rule that record every program the web-server account starts, with a guide to how strong each signal is.
- [curl HTTP/2 upload](curl/README.md#curl-http2-upload-use-after-free-check): check for CVE-2026-92392 (fixed in 8.23.0; branch backports 8.14.3 / 8.16.2 / 8.20.2).
- [nginx October 2026](nginx/README.md#nginx-october-2026-check): check and `nginx -T` config audit for the five flaws fixed in 1.30.6 / 1.31.7, plus the two njs fixes in 1.0.2.
- [Nextcloud Collabora Built-in CODE](nextcloud/README.md#nextcloud-collabora-built-in-code-command-injection): interim mitigation, check and hunt for CVE-2026-110447 (exploited in the wild). Update to 26.4.303 or remove; disabling is not enough.
- [LiteLLM 1.107.0 supply-chain compromise](litellm/README.md#litellm-11070-supply-chain-compromise): detect, hunt and contain the malicious release (no CVE). Pin 1.106.2 and treat an affected host as compromised.
- [Plex Media Server Plex2Shell](plex/README.md#plex-media-server-plex2shell-rce-chain): check and hunt for the RCE chain (CVE-2026-96651/96652/96654/96655/96656) fixed in 1.43.3.10861, exploited in the wild to drop miners and a proxy backdoor.
- [GhostAction developer-machine stealer](ghostaction/README.md#ghostaction-developer-machine-stealer): scan, hunt and contain the stage-2 stealer hidden in a fake `fa-solid-400.woff2` and a VS Code `folderOpen` task (no CVE, exploited in the wild).

### Changed

- [PHP2Shell edge guards](php/edge/README.md#verification): verified with real PHP handlers under `mod_proxy_fcgi`, with nginx reverse-proxying to an Apache backend, over negotiated HTTP/2, with chunked-encoding multipart bodies, and against the official WordPress codebase using the documented allowlist example. `mod_proxy_fcgi` rejects a leak-sized response on its own before the guard runs, `proxy_buffer_size` behaves the same as `fastcgi_buffer_size`, and HTTP/2 cannot run under `mod_php` because `mod_http2` declines to operate under the `prefork` MPM.
- [PHP2Shell detection rules](php/detect/README.md): the nftables egress rule was loaded on a live system and logged a real DNS lookup and outbound connection made by the web account, and did not log the same traffic from another account.
- [PHP2Shell hunt](php/README.md#php2shell-hunting-for-exploitation): the hunt baseline moved from the 21 October patch date to 17 October, when exploitation attempts were first reported. Set `HUNT_SINCE` to override (`php2shell-mitigate.sh` 5.2.5).
- [PHP2Shell hunt and watch](php/README.md#php2shell-hunting-for-exploitation): indicators from a 24 October honeypot report, including both forms of the numbered-request fingerprint, leak-sized response leads, nginx's `upstream sent too big header` error, TCP peers of flagged processes, an attempt-only address list, proof files, and auditd events (`php2shell-mitigate.sh` 5.2.4, `php2shell-watch.sh` 1.4.3).
- [PHP2Shell exploitability summary](php/README.md#how-exploitable-is-it-and-since-when): a sourced summary of what PHP validated (remote code execution over `mod_php` for CVE-2026-109618 and over PHP-FPM for CVE-2026-109619, attempts reported from 17 October) and PHP's interim measures with their costs. The AppArmor layer does not reach `mod_php`.
- [Help and version handling](php/README.md#php2shell-interim-mitigation): every script accepts `--help`, `--version` and `version`, and rejects an unknown command.
- [Brotli checker](brotli/README.md#brotli-checker-quick-start): 1.2.0 also detects Python `brotlicffi` (fixed 1.2.1.0) and cdxgen (fixed 13.5.0 / 12.8.9), and recognizes Debian 13's fixed `brotli` build.

## 2026-10-23

### Added

- [Brotli checker](brotli/README.md#brotli-checker-quick-start): CVE-2026-111497 is not only a Node.js bug. The checker covers `libbrotli` on the host, the runtimes that bundle it, and containers.
- [libheif checker](heif/README.md#libheif-heifavif-decoder-check): the HEIF/AVIF decoder heap overflow used to breach a Discourse forum. Read-only check plus ImageMagick and MediaWiki hardening.
- [Ruby and GitLab checker](ruby/README.md#ruby-and-gitlab-regexp-check): the Regexp fixes in Ruby 4.0.9 / 3.4.12 / 3.3.13 and the four GitLab CVEs. If you run GitLab, upgrade it first.

### Changed

- [PHP2Shell](php/README.md#php2shell-interim-mitigation): CVE-2026-115560 (session upload progress) is not fixed by the 21 October releases. v5 keeps upload progress off after `cleanup`. If you ran `cleanup` with v4, re-run it with v5.
- [php2shell-watch](php/README.md#watching-live): adds two ReliaQuest detection signals for CVE-2026-109618 (`in Unknown on line 0`, and a POST-500 / same-PID crash correlation).

## 2026-10-22

### Changed

- [PHP2Shell](php/README.md#php2shell-hunting-for-exploitation): an allocator double-free reproduced on 8.5.12 (the release listed as fixed) via `php -S`. `hunt` and the watcher now detect it. The AppArmor layer confines PHP-FPM, not the `php` CLI.
