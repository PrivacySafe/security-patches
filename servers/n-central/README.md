# N-able N-central and Apache Axis: CVE-2026-90436 ("4EverAble2Shell")

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="ncentral-legacyapi"></a>

## Apache Axis unsafe reflection through the N-central Legacy API (exploited)

**Script:** [`servers/n-central/ncentral-legacyapi-check.sh`](ncentral-legacyapi-check.sh)

Apache Axis 1.x processes attacker-chosen objects while it parses a SOAP request, before any service checks a login. On-premises N-able N-central exposes Axis through its Legacy API (`/dms/services/ServerUI`), and a public chain turns that into root on the server with no login. Huntress found crypto miners on 21 servers within hours of the proof of concept; N-able reported attacks on 13 November, and the same Axis flaw was used against Confluence Data Center the same day.

| | |
|---|---|
| CVE | CVE-2026-90436 (Apache Axis 1.x through 1.4); the N-central root step has no CVE yet |
| Exploited | Yes. CISA KEV 18 November 2026, due 21 November |
| Affected | On-premises N-central before 2026.4 HF3 with LEGACY APIS on (off by default) and reachable; any product that exposes Apache Axis 1.x SOAP services |
| Fixed | N-central 2026.4 HF3 (2026.4.1.39, 16 November), which removes the Legacy API. HF2 (2026.4.1.26) does not stop the chain. Hosted N-central got HF3 automatically. Apache Axis has no fixed release |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/servers/n-central/ncentral-legacyapi-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less ncentral-legacyapi-check.sh
   chmod +x ncentral-legacyapi-check.sh
   ```

3. Ask each N-central server whether its Legacy API answers, from where an attacker might stand (the internet, or your internal network). This fetches only the service description.

   ```bash
   ./ncentral-legacyapi-check.sh check ncentral.example.com
   ```

4. On the N-central server, and on any server running Apache Axis, look for what the attacks left.

   ```bash
   sudo ./ncentral-legacyapi-check.sh check
   sudo ./ncentral-legacyapi-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check [HOST...]` | With hosts: `GET https://HOST/dms/services/ServerUI?wsdl`. An HTTP 200 with the service description means the Legacy API is on and reachable from here. On this machine: Apache Axis 1.x jars (`axis.jar`, `axis-1.*.jar`) under `ROOTS`, in running Java processes' class paths and in running docker and podman containers, with the version from the jar's manifest; Axis 2 is a different project and is not reported. Read-only. Exits `0` if nothing is exposed, `1` for a Legacy API that answers or an Axis 1.x copy, `2` if a host did not answer |
| `hunt` | An `xvd.service` unit, `/tmp/.xvd` and `/var/tmp/.xvd`, cron entries and processes that run a miner, connections to `157.20.241.16`, and log lines from the last `HUNT_DAYS` days that name that address or the `jline.internal.TerminalLineSettings` gadget used against `/dms/services/ServerUI`. Read-only. Exits `0` if nothing is found, `1` for leads |
| `version` | Prints the script version |

Environment: `ROOTS`, `MAX_DEPTH`, `HTTP_PORT`, `CURL_TIMEOUT`, `HUNT_DAYS`, `HUNT_LOG_DIRS`, `IOC_IP`, `SCAN_CONTAINERS`.

## What to do

1. Install N-central 2026.4 HF3 (2026.4.1.39) now, outside normal patch cycles. Update every Agent and Probe to 2026.4.1 HF3 and Patch Management Engine to 2.14.4.5829 or later.
2. Until then, turn LEGACY APIS off: **Administration > Mail and Network Settings > Network Security**. If you truly need it, never expose it to the internet. A reverse proxy in front of N-central can refuse the path:

   ```nginx
   location ^~ /dms/services/ { return 403; }
   ```

   ```apache
   <Location "/dms/services/">
       Require all denied
   </Location>
   ```

3. Any other product that bundles Apache Axis 1.x (Confluence Data Center among them) needs its vendor's fix; keep its SOAP endpoints away from untrusted networks until then.
4. If `hunt` finds anything, treat the server as fully owned (root). An RMM server reaches every managed client: rotate the secrets stored in Automation Manager policies, enforce MFA on N-central accounts, and review activity from 11 November on for new accounts, scripts, scheduled tasks and remote sessions.

## Before you run it

- `check` uses `curl -k`, because on-premises servers often have self-signed certificates. It sends a plain `GET` for the service description; nothing Axis would deserialize.
- Without root, `check` and `hunt` see only what this account can read, and say so.

Sources: [Rapid7](https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited/), [N-able's remediation update](https://www.n-able.com/blog/n-able-vulnerability-remediation-update), [Huntress](https://www.huntress.com/blog/n-able-disables-cloud-services-following-disclosure-of-able2shell-exploit-chains), the [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-90436), [CISA](https://www.cisa.gov/news-events/alerts/2026/11/18/cisa-adds-four-known-exploited-vulnerabilities-catalog) and [N-able's Legacy API documentation](https://developer.n-able.com/n-central/docs/soap-api-legacy). Status current on 23 November 2026.

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
