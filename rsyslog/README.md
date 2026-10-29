# rsyslog: CVE-2026-92709 dynaFile path traversal

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="rsyslog-dynafile-audit"></a>

## rsyslog dynaFile audit

**Script:** [`rsyslog/rsyslog-dynafile-audit.sh`](rsyslog-dynafile-audit.sh)

rsyslog's `omfile` `dynaFile` feature builds an output file name from a template. When a template puts a value that an outside party can influence (the HOSTNAME or program name of an incoming message, the message text, structured data) into a path component **without** explicit secure-path handling, the rendered path can escape the intended log directory. rsyslog usually runs as root or with broad write access to `/var/log`, so the result is an arbitrary file write, which the advisory title and several trackers escalate to code execution.

| | |
|---|---|
| CVE | CVE-2026-92709 (GHSA-xmp9-244p-5ggv, published 22 October 2026) |
| Severity | High, CVSS 8.1 (attack complexity high) |
| Affected | rsyslog 1.15.0 through 8.2610.0, **when** a dynaFile template uses an untrusted value in a path component without secure-path handling |
| Fixed | **No release is listed as fully patched** as of 27 October 2026. Debian, Cyberus and nixpkgs trackers show it as open |
| Defence | The documented, recommended one, which works on every version: explicit secure-path handling for each untrusted value in a dynaFile path |
| Not limited to | The RFC 5424 HOSTNAME field. Any untrusted value that reaches a path component creates the condition |
| Exploit | A PoC reference is listed by one aggregator. The page we saw contained only the advisory text |

**The configuration decides your exposure, not the version**, which is why this is a configuration audit. On the rsyslog 8.2312.0 default configuration it correctly reports that nothing builds a path from message data. The daily stable documentation describes new dynaFile controls and a rule that the path must stay under a fixed leading prefix, which hints that a fix is on the way. No release carries it yet, so do not wait for it.

## The fix, validated

```text
# string templates
template(name="DynFile" type="string"
         string="/var/log/hosts/%HOSTNAME:::secpath-replace%/%programname:::secpath-replace%.log")

# legacy syntax
$template DynFile,"/var/log/%HOSTNAME:::secpath-replace%/%programname:::secpath-replace%.log"

# list templates
template(name="DynFileList" type="list") {
  constant(value="/var/log/hosts/")
  property(name="hostname" securePath="replace")
  constant(value="/")
  property(name="programname" securePath="replace")
  constant(value=".log")
}
```

`secpath-drop` (remove the slashes) is the alternative to `secpath-replace` (replace them with underscores). All of these forms were validated with `rsyslogd -N1` on a real rsyslog 8.2312.0.

> **Caution: do not copy `global(compatibility.defaults.secure="strict")` onto an older rsyslog.** It defaults unprotected dynaFile fields to `secpath-replace`, but it is only known to newer versions. On 8.2312.0 `rsyslogd -N1` rejects it with "parameter 'compatibility.defaults.secure' not known". Test every change with `rsyslogd -N1` before you restart.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/rsyslog/rsyslog-dynafile-audit.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/rsyslog/rsyslog-dynafile-audit.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less rsyslog-dynafile-audit.sh
   chmod +x rsyslog-dynafile-audit.sh
   ```

3. Audit this host. It reads `/etc/rsyslog.conf` and everything it includes. No root is needed unless your configuration is unreadable to your user.

   ```bash
   ./rsyslog-dynafile-audit.sh audit
   ```

## Commands

| Command | What it does |
|---|---|
| `audit` (default) | Reads the rsyslog version, the main configuration and everything included through `$IncludeConfig` and `include(file=...)` (files, globs and directories, with a loop guard), finds templates used by `dynaFile` and by the legacy `?Template` action, and lists every path component that comes from an untrusted property without secure-path handling. Reports whether network input modules are configured and which user `rsyslogd` runs as |
| `version` | Prints the script version |

Environment: `RSYSLOG_CONF` (space separated files) replaces configuration discovery.

Exit codes: `0` no unprotected untrusted value in a dynaFile path, `1` at least one was found or could not be judged, `2` bad arguments.

## How it classifies properties

- **Treated as untrusted:** `hostname`, `source`, `fromhost`, `programname`, `app-name`, `syslogtag`, `msg`, `rawmsg`, `procid`, `msgid`, `structured-data`, `protocol-version`, and any message variable starting `$!`.
- **Treated as not controllable by a sender:** `fromhost-ip`, `inputname`, `timegenerated`, `timereported`, `timestamp`, `now`, the date parts, the priority and facility properties, and `$now`, `$year`, `$month`, `$day`, `$hour`, `$minute`, `$myhostname`.
- **Unrecognised:** anything else, including local variables (`$.name`). The script warns, because it cannot tell whether a sender can influence the value, and exits `1`.
- **Protected:** a property whose options contain `secpath-replace`, `secpath-drop` or `securepath`, in string templates (`%name:::options%`) and list templates (`securePath=`).

## How to read the result

- **Unprotected untrusted property:** add secure-path handling to each one, test with `rsyslogd -N1`, then restart.
- **Strict mode set:** shown as protected only by the global setting, with a warning to confirm your rsyslog accepts it.
- **A dynaFile template that is not defined in the files read,** or a subtree or plugin template: reported for manual review, with exit `1`.
- **No dynaFile at all:** nothing here builds a path from message data. A template that is defined but never used by dynaFile is ignored.
- **Network input configured:** senders you do not control can reach the templates. Local sources such as `imuxsock` and `imjournal` can still carry attacker-chosen program names.
- **rsyslogd running as root:** a path escape writes as root. Run it as an unprivileged user and keep its writable area to the log directories. Debian and Ubuntu drop to `syslog` by default.

This is a text search over the configuration, not a full parser. Unusual layouts, generated configuration, and templates built through other mechanisms may be missed.

## Sources

- [rsyslog advisory GHSA-xmp9-244p-5ggv](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-xmp9-244p-5ggv)
- [rsyslog omfile dynaFile documentation](https://docs.rsyslog.com/doc/reference/parameters/omfile-dynafile.html)

## rsyslog know before you run it

- **There is no fixed release to move to yet.** As of 27 October 2026 no rsyslog release is listed as fully patched for CVE-2026-92709, so this is an audit of your configuration, not a version check.
- **It only matters with an untrusted value in a path component.** The flaw applies when a `dynaFile` template puts a value an outside party can influence (the hostname or program name of an incoming message, the message text, structured data) into a path component without secure-path handling.
- **The documented defence works on every version.** Use explicit secure-path handling in the template; rsyslog usually runs as root or with broad write access to `/var/log`, which is why an escape is an arbitrary file write.
- **There is no hunt.** No indicators of exploitation have been published.

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
