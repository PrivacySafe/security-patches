# PHP2Shell detection content

Part of the [PHP docs](../README.md) in the [PrivacySafe Security Patches](../../README.md) collection. Compensating controls that narrow what a request can do live in [`php/edge/`](../edge/README.md); this folder is about **seeing** an attack. Neither is a fix: the only complete fix is a patched PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or your distribution's backport).

## Why this exists

A honeypot report from 24 October 2026 (phpot, 35 confirmed shell executions on single-worker Apache `mod_php`) is unusually specific about what worked as evidence. Its decisive observation was process-level: an Apache worker starting `/bin/sh` as uid 33, matched to a complete HTTP request. Three details matter for anyone watching a real server:

- The stages of the chain answered HTTP 200, and the final request, the one that starts the shell, could fail to reach the access log because the worker died (about 0.7 seconds after the shell started in the first confirmed case). A missing access-log line is not a sign the request failed.
- A crash, an out-of-memory error or an oversized cookie alone is not proof of execution. Only an unexpected child process shows that something ran.
- Logs show residue. A tool that samples running processes can miss a shell that starts and exits between samples. Auditing `execve` cannot.

## What is here

| What | For |
|---|---|
| [`php2shell-auditd.rules`](php2shell-auditd.rules) | Record every program the web-server account starts (auditd) |
| [Tetragon filter](#tetragon) | The same signal from Tetragon `process_exec` events |
| [Outbound connections](#outbound-connections) | Log what the web account connects to, log-only |
| [Reading the signals together](#reading-the-signals-together) | What each signal does and does not tell you |

`php2shell-mitigate.sh hunt` (5.2.0 and later) and `php2shell-watch.sh` (1.4.0 and later) cover the log and live-process side; see [PHP2Shell hunting for exploitation](../README.md#php2shell-hunting-for-exploitation) and [Watching live](../README.md#watching-live).

## auditd

```bash
sudo cp php2shell-auditd.rules /etc/audit/rules.d/60-php2shell.rules
sudo augenrules --load
sudo auditctl -l | grep php2shell_web_exec
sudo ausearch -k php2shell_web_exec -ts today -i
```

The rule matches every `execve` by an account whose effective uid is 33 (`www-data` on Debian, Ubuntu and Trisquel) and that is not in a login session. Edit the uid for your web account, and add a line for any PHP-FPM pool that runs as another user (each pool's `user =` setting). In the output, the useful fields are `ppid` (the parent), `comm` and `exe` (what ran), and the arguments: a `sh`, `curl`, `wget` or PHP CLI whose parent is a web worker is the signature in the phpot report (a [24 October 2026 honeypot report](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)). `hunt` reads this key when `ausearch` is present, and prints the parent, command and executable of the most recent starts.

Expect noise where the application legitimately runs programs (ImageMagick, sendmail, git). Review a week of events before trusting it, and silence a known harmless program with a `never` rule placed before the main one (an example is in the file). The 32-bit rule is commented out because some kernels reject `b32` rules.

Both rule lines (64-bit and the optional 32-bit one) load cleanly on a live audit subsystem on x86-64, and the rule recorded real program starts by `www-data`, which `hunt` then read from real `ausearch -i` output. Run `auditctl -l` after loading to confirm the rule is active on your system. One thing to know if you query the log yourself: `ausearch` blocks forever when its standard input is an open pipe, as it is under `ssh host command`, so give it `--input-logs` and a closed stdin. `hunt` does.

## Tetragon

Tetragon reports process starts by default, with no policy needed: a `process_exec` event carries the new process (`process.binary`, `process.arguments`, `process.uid`) and its parent (`parent.binary`). This filter keeps only a shell, fetch tool or interpreter started directly by a web server or PHP worker:

```bash
sudo tetra getevents -o json | jq -c '
  select(.process_exec != null)
  | select((.process_exec.parent.binary // "") | test("/(apache2|httpd|php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9]*|nginx)$"))
  | select((.process_exec.process.binary // "") | test("/(sh|dash|bash|ash|zsh|ksh|busybox|curl|wget|nc|ncat|netcat|socat|php[0-9.]*|python[0-9.]*|perl|ruby|openssl|base64|mkfifo)$"))
  | {time, node: .node_name, uid: .process_exec.process.uid,
     parent: .process_exec.parent.binary, binary: .process_exec.process.binary,
     args: .process_exec.process.arguments}'
```

Run the same filter over your Tetragon JSON export file if you keep one. Verified with jq 1.7 against sample events in this shape: it returns an Apache-to-`sh` and an nginx-to-`curl` event, and ignores an `sshd` shell, an Apache-to-`convert` start, a `process_exec` event with no parent, and non-exec events without erroring. Field names can differ between Tetragon versions, so check them against one real event first.

Two limits. The filter sees direct children only, so a `curl` started by that `sh` shows up as a child of `sh`, not of the web server; the first shell is the signal. And the arguments can carry secrets on hosts whose applications legitimately shell out, so drop the `args` field if you ship these events elsewhere. Network events (`tcp_connect`) come from a Tetragon `TracingPolicy` rather than this process filter; the [outbound-connection rule](#outbound-connections) below covers that side. The phpot report used a `TracingPolicy` to see a shell's `curl` reach `TCP_SYN_SENT` towards an attacker address.

## Outbound connections

In the phpot report the shells tried to call out: PHP CLI, `curl` and `wget` towards attacker hosts on ports 8080 and 8081, with one connection seen in `TCP_SYN_SENT`. Whether a call-out succeeded was not established by the telemetry, which is itself a reason to watch for the attempt.

Two things help without changing any traffic. First, `php2shell-watch.sh` and `hunt` now print the TCP peers of any shell or tool they flag under a web worker, for example `[tcp: SYN-SENT->203.0.113.9:8080]`, so the destination is in the alert. Second, a log-only rule records new outbound connections from the web account, so you can see what normal looks like before deciding anything:

```text
table inet php2shell_egress {
    chain output {
        type filter hook output priority 0; policy accept;
        meta skuid "www-data" ct state new ip daddr != { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } log prefix "php2shell-egress "
    }
}
```

Save it as a file, check it with `nft -c -f <file>`, load it with `nft -f <file>`, and read it with `journalctl -k | grep php2shell-egress`. It logs only, accepts everything and handles IPv4 only. Loaded on a live nftables (x86-64): the account name resolves to its uid, and both a DNS lookup and a TCP connection made by that account were logged, while the same traffic from a different account was not. It applies to PHP running on the host; a container's traffic crosses the `forward` hook, not `output`.

Restricting egress for real, so the web account can reach only the hosts it needs (a database, an API, a mail relay, a package mirror), is the strongest compensating control against the call-out step. Build the allow-list from a week of the log-only output first. A drop rule written without that review will break the site.

## Reading the signals together

| Signal | Strength | What it does and does not tell you |
|---|---|---|
| A web worker starts a shell or fetch tool (auditd, Tetragon, the live poll) | Strong | A program ran. Not what else the attacker did, and not whether anything left the host |
| Repeated pre-script out-of-memory errors (`in Unknown on line 0`) from one client, then a crash of the same worker | Strong lead | The shape of the confirmed chain. Not proof of execution |
| A POST response of hundreds of kilobytes, or a `PHPSESSID` value thousands of characters long | Lead | The disclosure stage returned a `PHPSESSID` of 819,200 bytes decoded (about 2 MB on the wire). Legitimate large POST responses exist, and the size shows only in logs that count header bytes (Apache `%O`, which is the Debian and Ubuntu default; nginx `$bytes_sent`, not its default `$body_bytes_sent`) |
| nginx error log: `upstream sent too big header` | Lead | At default buffer sizes nginx refuses a leak-sized `Set-Cookie` with a `502` and this line, which is nginx's counterpart of the oversized response size its default access log cannot show. Large legitimate headers raise it too |
| No `User-Agent`, a multipart boundary of ten `C` characters, and a fixed header order (Host, Content-Type, Transfer-Encoding or Content-Length, Connection) | Weak | Seen from both source addresses against all three targets in the phpot report: one public client family, trivial to change. The nginx edge log records the boundary in its `ct=` field |
| The `q<N>=v&q<N>=v&q<N>=v` request fingerprint | Weak | One public client family; both a long form (seven-digit numbers) and a short form (`q0`, `q1`) have been observed. Trivial for an attacker to change |
| Source addresses from the phpot report | Weak and ageing | A hit means the address touched you, not what it did. They are hosting-provider addresses, and the attempt-only list may include shared ones |
| One out-of-memory error, or one worker crash | Not evidence | Extensions crash workers too |

Do not log the cookie value to get the disclosure signal: it is leaked process memory, and your log would keep it. Do not block whole hosting networks because two of their addresses appeared once. An HTTP 200 on one stage does not mean the attempt failed.

## If a web worker started a shell

Treat it as a compromise of everything the web account could read, not as a crash. Preserve the logs and audit events first, rotate the secrets the account could reach (database passwords, API keys, session secrets), rebuild the host or container from a clean image rather than cleaning it in place, and patch PHP before it goes back into service. Command execution inside a container is not a host escape, and the phpot report did not establish one, but its container restrictions (a read-only web root, no `wget`) are what stopped some of the attackers' follow-up steps.

---

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
