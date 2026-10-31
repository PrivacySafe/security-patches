# Jenkins plugin security advisory of 16 September 2026 (CVE-2026-92122 to CVE-2026-92141)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="jenkins-check"></a>

## Jenkins plugin check

**Script:** [`jenkins/jenkins-check.sh`](jenkins-check.sh)

Jenkins published a security advisory on 16 September 2026 covering 20 vulnerabilities in 13 widely deployed plugins. Eight are High-severity flaws in Script Security, the plugin that sandboxes Groovy for Pipelines and is installed on nearly every Jenkins server. They are ways around the sandbox that let a user who may define Pipeline scripts run code in the controller's JVM. The techniques include interface coercion, calls on a null receiver, collection casts, AST transformations, `@Builder` at compile time, dynamic methods, a classpath approval bypass, and a time-of-check to time-of-use race on approved remote JARs.

| Plugin (short name) | Fixed in | CVE | Severity | What |
|---|---|---|---|---|
| `script-security` | 1422.v06869826dd9b_ | CVE-2026-92122 to CVE-2026-92129 | High (8 issues) | Sandbox bypass: code execution in the controller JVM |
| `workflow-multibranch` | 842.v3a_b_59b_57b_e6e | CVE-2026-92130 | Low | System-scoped credential exposure through `resolveScm` |
| `pipeline-groovy-lib` | 806.v408277b_33d1d | CVE-2026-92131 | Medium | Path traversal: file read and deletion |
| `gradle` | 2.20.1253.vc116f0763a_eb_ | CVE-2026-92132 | Medium | SSRF: theft of the Develocity access key |
| `gitlab-plugin` | 1.2152.veec0897048b_0 | CVE-2026-92133 | Medium | GitLab API token exposure |
| `warnings-ng` | 13.10259.v80f407cb_03a_e | CVE-2026-92134 | High | Stored XSS |
| `coverage` | 3.3361.v0626103a_67e6 | CVE-2026-92135 | High | Stored XSS |
| `dependency-check-jenkins-plugin` | 5.6.5 | CVE-2026-92136 | High | Stored XSS through CWE values |
| `robot` | 6.3.0 | CVE-2026-92137 | High | Arbitrary file write on the controller, potentially code execution |
| `atlassian-bitbucket-server-integration` | 6.0.2 | CVE-2026-92138 | Medium | OAuth access token hijacking |
| `bitbucket-push-and-pull-request` | 4.1.0 | CVE-2026-92139 | Medium | SSRF: Bitbucket credential theft |
| `gitee` | 1304.v2702f1d71cde | CVE-2026-92140 | High | Stored XSS through webhook sender data |
| `keycloak` | 2.4.2 | CVE-2026-92141 | Medium | Open redirect |

The eight Script Security identifiers are CVE-2026-92122, CVE-2026-92123, CVE-2026-92124, CVE-2026-92125, CVE-2026-92126, CVE-2026-92127, CVE-2026-92128 and CVE-2026-92129. No exploitation was reported in the sources used.

## How the script reads an install

A plugin's version is the `Plugin-Version` line of its `META-INF/MANIFEST.MF`, either in the expanded plugin directory or inside the `.jpi` or `.hpi` file under `$JENKINS_HOME/plugins`. A manifest wraps long lines, and a line that starts with one space continues the line before. The script joins them and handles Windows line endings. The 13 short names were checked against each plugin's own project file.

Versions are compared by their leading dotted number, as numbers (so `5.6.10` is newer than `5.6.5`). Two builds with the same number but different build hashes cannot be ordered, and are reported as such. A plugin that is disabled does not run and is reported as such: update or remove it anyway. A listed plugin that is installed but whose version cannot be read (a manifest with no `Plugin-Version`, or no manifest) is never skipped: it is reported as a warning, exit `1`, with the fixed version to confirm in the Plugin Manager.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/jenkins/jenkins-check.sh
less jenkins-check.sh
chmod +x jenkins-check.sh
./jenkins-check.sh check
```

It looks in `$JENKINS_HOME`, `/var/lib/jenkins` and `/var/jenkins_home`. Pass one or more Jenkins home directories to name them. Everything is read-only.

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Reads each listed plugin's version and compares it with the fixed version. Exit `0` no plugin below its fix, `1` a plugin below its fix or unorderable |
| `version` | Prints the script version |

## Update

Update the plugins in Manage Jenkins, Plugins, then restart Jenkins. Until you can, the project suggests limiting who holds Pipeline authoring and Item/Configure permissions; that is not Jenkins guidance.

## After an update

If an affected Script Security, GitLab, Gradle or Bitbucket plugin was installed while users you do not fully trust could define Pipelines or edit jobs, treat the credentials those plugins could reach as possibly exposed and rotate them. That means GitLab, Bitbucket, Develocity and OAuth credentials, and Jenkins credentials.

## Sources

- [Jenkins security advisory, 2026-09-16](https://www.jenkins.io/security/advisory/2026-09-16/)
- [Cyber Security News: Jenkins fixes 20 plugin vulnerabilities](https://cyberpress.org/jenkins-fixes-20-plugin-vulnerabilities/)

## Before you run it

- The fix. Update the listed plugins in Manage Jenkins, Plugins, then restart Jenkins.
- It reads manifests, not the update center. Each plugin's `Plugin-Version` is read from its expanded directory first, then its `.jpi` or `.hpi` archive. A plugin that is installed but whose version cannot be read is reported, not skipped, and a plugin that is disabled is noted as not running (update or remove it anyway). Two builds with the same leading number but different hashes cannot be ordered, and are reported that way.
- It also reads running containers. With `SCAN_CONTAINERS=1` (the default) it reads the advisory plugins' manifests inside running docker and podman containers (`JENKINS_HOME` there, default `/var/jenkins_home`), judged by the same rules. It is skipped when you name the home directories yourself.
- The protective measure is the project's, not Jenkins's. Limiting who holds Pipeline authoring and Item/Configure permissions reduces the exposure to the High flaws. There is no hunt.

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
