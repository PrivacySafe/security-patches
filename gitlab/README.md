# GitLab security releases, October 2026 (seven High flaws)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="gitlab-check"></a>

## GitLab check

**Script:** [`gitlab/gitlab-check.sh`](gitlab-check.sh)

Two GitLab releases are covered. The critical patch release of 12 October 2026 (19.4.2, 19.3.5, 19.2.8) fixed 24 vulnerabilities, and the one of 21 October 2026 (19.5.1, 19.4.3, 19.3.6) fixed 12 more. Seven rated High are checked here, with the affected ranges GitLab published for each.

| CVE | CVSS | Edition | What | Affected |
|---|---|---|---|---|
| CVE-2026-92883 | 8.7 | CE and EE | Stored cross-site scripting in syntax highlighting, through a crafted repository | 19.1 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2 |
| CVE-2026-16301 | 8.5 | CE and EE | A user with the Developer role can run CI/CD pipelines on protected branches without authorization | 18.7 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2 |
| CVE-2026-14814 | 8.2 | CE and EE | A permissive regular expression in repository file access lets a user poison the cache of raw repository files, so other users' pipelines run crafted content and protected variables can be exposed | Every version before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2 |
| CVE-2026-15723 | 8.2 | CE and EE | When OmniAuth SAML and LDAP auto-linking are both enabled, an authenticated user can take over an existing LDAP-backed account, because the LDAP email lookup used during identity linking does not sanitize its input | 10.1 before 19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1 |
| CVE-2026-81839 | 7.7 | EE only | After a project is transferred, scheduled pipeline execution policy records are not cleaned up, so pipelines run with the new group's privileges | 18.1 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2 |
| CVE-2026-96893 | 7.3 | EE only | Prompt injection in the GitLab Duo Agent Platform: crafted content in the AI conversation context can cause unintended commands attributed to other users | 19.1 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2 |
| CVE-2026-112212 | 7.5 | CE and EE | Cache poisoning of the OAuth and OpenID Connect discovery document: an attacker without an account can point some sign-in flows at a server they control (it needs a shared cache) | 18.3 before 19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1 |

The start of the affected range for CVE-2026-112212 comes from write-ups of GitLab's advisory, not from the CVE record, which was not available when this checker was written. Every other range is from GitLab's release pages or the CVE record.

| | |
|---|---|
| Fixed | See the table: each flaw has its own fixed releases, and 19.5 and later are not listed as affected by any |
| **Which release is a full fix** | **19.5.1, 19.4.3 and 19.3.6.** The 21 October release backported only the regular-expression fix (CVE-2026-110264) to 19.2.9, 19.1.9, 19.0.10 and 18.11.13, so those leave the High flaws above open. 19.2.9 is the case to watch for: it is current for the regex flaw and still exposed to CVE-2026-15723 and CVE-2026-112212 |
| No fix on the line | A line below those named in the table is affected and has no fixed release: move to a fixed release of a supported line |
| Scope | Self-managed instances (Omnibus, source and Helm). GitLab.com already ran the fixes, and GitLab Dedicated needed no action |
| Not checked | The Medium and Low flaws of the two releases |

The two regular-expression flaws of October (CVE-2026-97229 and CVE-2026-110264) are covered by the [`ruby/`](../ruby/README.md) checker. Run both: each flaw has its own fixed versions, so being current for one says nothing about the other. An 18.11.13 instance, for example, has the regular-expression fix and still has no fix for five of the seven flaws in this table.

## How the script reads an install

The version comes from GitLab's own `VERSION` file (Omnibus: `/opt/gitlab/embedded/service/gitlab-rails/VERSION`, or `version-manifest.txt`; source installs: `/home/git/gitlab/VERSION`) and from the tags of `gitlab/gitlab-ce` and `gitlab/gitlab-ee` images known to docker or podman. An image on disk is not necessarily a running container, and the script says so.

A build whose `VERSION` file ends in `-pre` or `-rc` is a build before a release, not the release: it is reported as a warning (exit `1`), not judged as the version it leads to.

Each flaw is judged on its own ranges. The edition matters for CVE-2026-81839 and CVE-2026-96893, which affect Enterprise Edition only. It is read from the package or image marker (`-ee`, `-ce`), the product name in the manifest, or the presence of GitLab's `ee` directory. When it cannot be read, the script raises those flaws as warnings that say they apply only to Enterprise Edition, instead of skipping them.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/gitlab/gitlab-check.sh
less gitlab-check.sh
chmod +x gitlab-check.sh
./gitlab-check.sh check
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds GitLab and judges the seven flaws separately, naming the fixed version for the install's line. Exit `0` nothing exposed, `1` an install without a fix |
| `version` | Prints the script version |

Env: `GITLAB_ROOT` (Omnibus root, default `/opt/gitlab`) and `GITLAB_SOURCE_DIRS` (source installs, default `/home/git/gitlab`).

## There is no hunt

GitLab published no indicators of exploitation for these flaws, so the script has none.

## Update

Move to 19.5.1, 19.4.3 or 19.3.6. Until you can, the project suggests taking the instance off the public internet or restricting it at the reverse proxy or firewall to trusted networks. That is not GitLab guidance.

## If an affected instance was reachable

If CVE-2026-14814 applied, protected CI/CD variables that pipelines could read may have been exposed: rotate them. If CVE-2026-15723 applied (SAML and LDAP auto-linking both on), review LDAP-backed accounts for sign-ins you do not recognise.

## Sources

- [GitLab critical patch release 19.4.2, 19.3.5, 19.2.8 (12 October 2026)](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/)
- [GitLab critical patch release 19.5.1, 19.4.3, 19.3.6 (21 October 2026)](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/)
- [GitLab package information: package version format](https://docs.gitlab.com/ee/administration/package_information)

## GitLab know before you run it

- **This is a check, not a fix.** Only 19.5.1, 19.4.3 and 19.3.6 are a full fix for the seven flaws. The backports of the 21 October release to 19.2.9, 19.1.9, 19.0.10 and 18.11.13 carry only the regular-expression fix, so 19.2.9 is current for that flaw and still exposed to CVE-2026-15723 and CVE-2026-112212.
- **Each flaw is judged on its own ranges.** Being current for one says nothing about another, and the two regular-expression flaws (CVE-2026-97229, CVE-2026-110264) are in the Ruby checker, so run both.
- **The edition matters.** CVE-2026-81839 and CVE-2026-96893 affect Enterprise Edition only. The script reads the edition from the package or image marker, the manifest or the presence of GitLab's `ee` directory; when it cannot, it raises those flaws as warnings instead of skipping them.
- **Some inputs are second-hand.** The start of the affected range for CVE-2026-112212 (18.3) comes from write-ups of GitLab's advisory, not the CVE record. The Medium and Low flaws of the two releases are not checked, and there is no hunt, because GitLab published no indicators.

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
