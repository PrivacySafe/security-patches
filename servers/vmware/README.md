# VMware vCenter: CVE-2026-123890 directory service authentication bypass

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="vcenter-dirsvc"></a>

## vCenter directory service authentication bypass (exploited)

**Script:** [`servers/vmware/vcenter-dirsvc-check.sh`](vcenter-dirsvc-check.sh)

Anyone who can reach vCenter's directory service, the single sign-on port 2012, can get an administrator session without a password. A suspected China-nexus group, ARMORY CASTLE (formerly UNC5221), used it from early September with a tool Mandiant calls BONESAW: it created an SSO administrator account and copied vCenter's directory database, which holds the key that signs login tokens, so the attackers could forge a login for any user. CISA added it to its Known Exploited Vulnerabilities catalog on 20 November 2026.

vCenter is an appliance on Photon OS. This tool asks each vCenter for its version over its web API, the way the vSphere client does before logging in, from any GNU/Linux machine; or runs on the appliance itself.

| | |
|---|---|
| CVE | CVE-2026-123890 (VMSA-2026-0009, 19 November 2026) |
| Severity | 9.8 Critical (CVSS 3.1) |
| Affected | vCenter 8.0, 9.0 and 9.1 before the fixed builds, the vCenter inside VMware Cloud Foundation 5.x, vSphere Foundation and Telco Cloud, and 7.0; Broadcom says to presume 6.5 and 6.7 affected. ESX is not affected |
| Fixed | 9.1.1.0200 (build 25901347), 9.0.2.0200 (build 25901331), 8.0 Update 3m (8.0.3.01200, build 25934264); VCF 5.x through 5.2.5; Telco Cloud per Broadcom KB 463116. No public fix for 7.0 (extended-support customers ask Broadcom) |
| Workaround | None from Broadcom. Mandiant recommends a default-deny firewall that lets only trusted hosts reach ports 2012 and 443 |
| Exploited | Yes, since early September 2026 (Mandiant); CISA due date for US agencies 23 November 2026 |

The same advisory fixes four lesser bugs that need an account or local access, in SDDC Manager (CVE-2026-123891, CVE-2026-123892, CVE-2026-123893; fixed in 9.1.1.0200, 9.0.2.0100 and 5.2.5) and VMware Tools for Windows (CVE-2026-123894; fixed in 13.1.5 and 12.5.5).

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/servers/vmware/vcenter-dirsvc-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less vcenter-dirsvc-check.sh
   chmod +x vcenter-dirsvc-check.sh
   ```

3. Check every vCenter you run, from a GNU/Linux machine that can reach them. This sends only the version request every vSphere client sends, without logging in.

   ```bash
   ./vcenter-dirsvc-check.sh check vcenter1.example.com vcenter2.example.com
   ```

4. Look for the attackers' files on the GNU/Linux machines that can reach vCenter, and on the appliance for SSO user changes.

   ```bash
   sudo ./vcenter-dirsvc-check.sh hunt
   ```

5. If you cannot patch yet, on the appliance's root shell, let only your admin hosts (and every other vCenter in the same SSO domain) reach port 2012.

   ```bash
   ALLOW_FROM="10.0.0.5 10.0.1.0/24" ./vcenter-dirsvc-check.sh mitigate --dry-run
   ALLOW_FROM="10.0.0.5 10.0.1.0/24" ./vcenter-dirsvc-check.sh mitigate
   ```

## Commands

| Command | What it does |
|---|---|
| `check [HOST...]` | With hosts: asks each one for its product, version and build with an unauthenticated `RetrieveServiceContent` call to `https://HOST/sdk` and judges the build against the fixed build of its line; reports ESXi hosts as not affected; says whether this machine can reach the host's port 2012. Without hosts, on the appliance: judges `vpxd -v`. Read-only. Exits `0` if every vCenter is fixed, `1` if one is affected, `2` if a version could not be read |
| `hunt` | On any GNU/Linux machine: the files Mandiant found on the GNU/Linux machines the attackers used to reach vCenter (`/tmp/123`, `/tmp/sss`, `/tmp/dbr`, `/usr/bin/vmtoolscs`). On the appliance also: single sign-on log entries of the last `HUNT_DAYS` days that create users or add them to groups. Read-only. Exits `0` if nothing is found, `1` for leads |
| `mitigate [--dry-run]` | On the appliance, as root: an iptables chain of its own that lets only `ALLOW_FROM` (plus loopback and connections already open) reach `PORTS` (default `2012`; add `443` as Mandiant suggests). `--dry-run` prints the rules. Not persistent across a reboot, and not supported by Broadcom: it narrows the attack until you patch |
| `rollback [--dry-run]` | Removes that chain |
| `version` | Prints the script version |

Environment: `ALLOW_FROM`, `PORTS`, `SDK_PORT` (default 443), `CURL_TIMEOUT`, `HUNT_DAYS`, `SSO_LOG_DIR`, `IOC_PATHS`, `STATE_DIR`, `PSF_LOCK_WAIT`.

## If you were exposed

A patch does not remove an attacker who is already in. Look for single sign-on administrator accounts you did not create (**Administration > Single Sign On > Users and Groups**, and the members of `Administrators`). Because the attackers copied the token-signing key, replace the STS signing certificate after patching, so forged logins stop working, and review vCenter tasks and events for changes nobody made. Check the other GNU/Linux machines that can reach vCenter with `hunt`: in Mandiant's case the attackers worked from appliances that had no endpoint protection.

## Before you run it

- `check` uses `curl -k`, because vCenter ships a self-signed certificate. Nothing secret is sent and only the reply's version is read.
- Broadcom's patches are cumulative, so a later build also fixes it. Heads-up from Broadcom: 8.0 U3m and 9.0.2.0200 block upgrades to VCF 9.1.1, so patch now and wait for 9.1.2 before that upgrade.
- `mitigate` changes only the appliance's own firewall. A network firewall in front of vCenter is the lasting form of the same protection.

Sources: Broadcom [VMSA-2026-0009](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495) and its [FAQ](https://github.com/vmware/vcf-security-and-compliance-guidelines/blob/main/security-advisories/vmsa-2026-0009/README.md), Broadcom [KB 326316](https://knowledge.broadcom.com/external/article/326316/build-numbers-and-versions-of-vmware-vce.html) (build numbers), [KB 463116](https://knowledge.broadcom.com/external/article/463116) (Telco Cloud), Mandiant's [ARMORY CASTLE report](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere), and the [CISA KEV entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-123890). Status current on 23 November 2026.

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
