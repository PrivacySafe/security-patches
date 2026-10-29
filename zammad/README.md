# Zammad session hijack and local privilege escalation (CVE-2026-102489, CVE-2026-102490)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="zammad-check"></a>

## Zammad check

**Script:** [`zammad/zammad-check.sh`](zammad-check.sh)

Zammad is an open-source helpdesk and ticket system. The Dutch Institute for Vulnerability Disclosure (DIVD) reported that two previously unknown flaws in Zammad were used to breach its own instance, with first access on 21 September 2026. CISA added both to its Known Exploited Vulnerabilities catalog on 2 October 2026. Chained, the first gives code execution as the `zammad` service user and the second gives root.

| | CVE-2026-102489 | CVE-2026-102490 |
|---|---|---|
| What | A session hijack leading to remote code execution as the `zammad` user | A local privilege escalation from the `zammad` user to root |
| CVSS | 9.4 (CVSS 4.0, CISA) | 8.5 to 9.4, depending on who scores it |
| Affected | 6.3.0 through 6.5.4 are exploitable. The same code is in 7.0.0 through 7.1.3 but is reported as not exploitable there | DIVD lists 1.5.0 through 7.1.0-alpha |
| Vendor position | Zammad says exploitation is possible only on 6.5 and older and that 7.0 and later are not affected. 7.2.0 adds hardening | Zammad disputes the report (it says it received no technical details) and, at the time of the sources used here, had published no patch. It needs code already running as the `zammad` user |
| Exploited | Yes, in the DIVD breach (CISA KEV) | Yes, as the second step of the chain (CISA KEV) |

Zammad's advice is to update to version 7 or take the instance offline.

## What this script can and cannot say

It reports the remote chain, CVE-2026-102489, from the version. It does **not** say that any version is fixed for CVE-2026-102490, because no source used here confirms a patch. The host's own hardening is the control for that one.

| Zammad version | Result |
|---|---|
| 6.3.0 to before 7.0.0 | Exposed: the remote chain is open. Exit `1` |
| 1.5.0 to before 6.3.0 | The session flaw does not apply, but the release is long unsupported and the local flaw is reported against it. Exit `1` |
| 7.0.0 to before 7.2.0 | The remote chain is not open. Update to 7.2.0 for the hardening. Exit `0` |
| 7.2.0 or later | Hardening for the session flaw. Exit `0`, with a note about the local flaw |
| A pre-release of 7.2.0 or later (the `VERSION` file ends in `-pre`) | Not judged as the release: it may not have the hardening. Warns, exit `1`. A pre-release below 7.2.0 is judged by the version it leads to |

The version is read from the `VERSION` file at the Zammad root (it holds just the version, for example `6.5.4`), with the package version as a fallback.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/zammad/zammad-check.sh
less zammad-check.sh
chmod +x zammad-check.sh
./zammad-check.sh check
./zammad-check.sh hunt
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds Zammad under `ZAMMAD_ROOT`, `/opt/zammad` or `/usr/share/zammad`, reads the version, and reports. Exit `0` the remote chain is not open, `1` exposed or unclear |
| `hunt` | Looks for persistence a root compromise would leave: changed `authorized_keys`, changed `root` and `zammad` crontabs, and, for review, root-owned files under the Zammad root and new SUID files. Exit `0` nothing found, `1` a lead |
| `version` | Prints the script version |

Env: `ZAMMAD_ROOT`, `ZAMMAD_HUNT_SINCE` (default `2026-09-21`), `ZAMMAD_HUNT_HOMES` (directories searched for `authorized_keys`; default `/root /home/zammad /opt/zammad`) and `ZAMMAD_CRON_DIRS` (default `/var/spool/cron/crontabs /var/spool/cron`).

## About the hunt

These are leads, not indicators of this particular campaign: there is no published list of indicators in the sources used. A changed `authorized_keys` or crontab may be an administrator's work, so confirm each. DIVD published its own log check for the campaign, which is the better source for indicators.

## Update

Update to 7.2.0 or later, or take the instance offline, as Zammad advises. If you cannot update, restrict network access to Zammad to trusted addresses.

## If an instance on 6.x was reachable after 21 September 2026

Treat the host as possibly compromised. Restore from a backup taken before that date, rotate every credential Zammad could read, and review accounts and keys on the host.

## Sources

- [Zammad advisory](https://zammad.com/en/advisories/cve-2026-102489-cve-2026-102490)
- [DIVD case DIVD-2026-00015](https://csirt.divd.nl/DIVD-2026-00015)
- [DIVD: CVE-2026-102489](https://csirt.divd.nl/CVE-2026-102489)
- [runZero: Zammad vulnerabilities](https://www.runzero.com/blog/zammad/)

## Zammad know before you run it

- **This is a check, not a fix.** Update to Zammad 7.2.0 or later, or take the instance offline, as Zammad advises.
- **It never claims a fix for CVE-2026-102490.** That local privilege escalation is disputed by the vendor and no patch is confirmed in the sources, so a fixed version is reported only for the remote chain (CVE-2026-102489).
- **A pre-release is not the release.** `7.2.0-pre` is reported with a warning, because it may not have the hardening.
- **It also reads running containers.** With `SCAN_CONTAINERS=1` (the default) `check` reads `VERSION` under `/opt/zammad` and `/usr/share/zammad` inside running docker and podman containers. A container whose `VERSION` cannot be read is reported as unreadable and is never judged by the host's package version. `hunt` is host only.
- **`hunt` lists leads, not proof of this campaign.** It looks for changed `authorized_keys`, changed root and zammad crontabs, files owned by root under the Zammad root and new SUID files since 21 September 2026. If a 6.x instance was reachable after that date, treat it as possibly compromised.

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
