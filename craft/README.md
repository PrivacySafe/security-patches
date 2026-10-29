# Craft CMS: CVE-2026-112777 Twig create() blocklist bypass

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="craft-cms-check"></a>

## Craft CMS check

**Script:** [`craft/craftcms-check.sh`](craftcms-check.sh)

Craft CMS limits which classes the Twig `create()` function may instantiate with a blocklist of class names. The checks are case-sensitive while PHP class resolution is not, so a differently capitalised class name gets past the blocklist. The result is remote code execution, or reading secrets such as the `.env` file, for someone who can make Twig render attacker-controlled template content.

| | |
|---|---|
| CVE | CVE-2026-112777 (CWE-184, GitHub advisory GHSA-w643-x88w-6wcm, published 19 October 2026) |
| Severity | High: 8.7 (CVSS 4.0), 7.2 (CVSS 3.1) |
| Affected | Craft CMS 4.0.0 up to 4.18.8, and 5.0.0 up to 5.11.0 |
| Fixed | 4.18.8 and 5.11.0 |
| Needs | Template-execution rights. This is an authenticated flaw: a compromised or malicious control panel account, or any setup where untrusted users can supply template code |
| Exploit | One CVE aggregator reports a GitHub proof of concept, which is not linked here. This tool contains no exploit logic |
| Same release | The same two versions fix several related Twig sandbox and behavior-injection flaws, so updating covers more than this one issue |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/craft/craftcms-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/craft/craftcms-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less craftcms-check.sh
   chmod +x craftcms-check.sh
   ```

3. Check this host. By default it searches `/var/www /srv /home /opt`; pass directories to narrow it.

   ```bash
   ./craftcms-check.sh check
   ./craftcms-check.sh check /var/www/mysite
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds `composer.lock` files, reads the Craft version from `vendor/craftcms/cms/src/config/app.php` when it is installed (it wins over the lock file) and otherwise from `composer.lock`, compares it with 4.18.8 and 5.11.0, and reads `config/general.php` for `allowAdminChanges` and `enableTwigSandbox` |
| `version` | Prints the script version |

Exit codes: `0` nothing affected, `1` an affected version was found, `2` bad arguments.

## How to read the result

- **Affected version:** update. The configuration lines tell you how reachable the flaw is, they do not make an affected version safe.
- **`allowAdminChanges`:** Craft recommends turning it off in production. If it is on, any admin account can change configuration that feeds Twig. The script reads both the array style (`'allowAdminChanges' => false`) and the fluent style (`->allowAdminChanges(false)`).
- **`enableTwigSandbox`:** reported as information. The advisory does not say whether the sandbox stops this specific bypass, so do not treat it as a mitigation.
- **Craft 3 and older** are end of life and the advisory covers 4.x and 5.x, so the script warns and does not call them affected by this CVE.
- **6.x pre-releases and dev checkouts** cannot be compared mechanically; the script warns and points you at the advisory.

## Fixing it

```bash
composer update craftcms/cms        # 4.18.8 or later on 4.x, 5.11.0 or later on 5.x
php craft up
```

While you prepare the update, review who holds admin or template-related permissions in the control panel, remove accounts you do not recognise, and set `allowAdminChanges` to `false` in production. Those steps narrow who can reach the flaw. They are our reasoning, not vendor documented for this bypass, and they do not replace the update.

## Sources

- [GitHub advisory GHSA-w643-x88w-6wcm](https://github.com/craftcms/cms/security/advisories/GHSA-w643-x88w-6wcm)
- [Canadian Centre for Cyber Security AV26-1067: Craft CMS](https://cyber.gc.ca/en/alerts-advisories/craft-cms-security-advisory-av26-1067)

## Craft CMS know before you run it

- **This is a check, not a fix.** Update to 4.18.8 or 5.11.0. The same two releases fix several related Twig sandbox flaws, so updating covers more than this one issue.
- **The flaw is authenticated.** It needs template-execution rights, so the realistic attackers are a compromised or malicious control panel account, or any setup that lets untrusted users supply template code.
- **It reads the install, not the site.** The version comes from `vendor/craftcms/cms` and `composer.lock`; from `config/general.php` it reports whether `allowAdminChanges` is off and whether the Twig sandbox is on.
- **There is no hunt.** No indicators of exploitation have been published for this flaw.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), the check finds installs inside running docker and podman containers by their marker file, copies only the files it reads into a private temporary directory, and judges them like a host install. A path shown as `.../docker_NAME_PATH` is the PATH inside the container NAME. It never runs anything in a container beyond `find` and a file copy, never copies `.env` or `wp-config.php`, never keeps a staged symlink, and is skipped when you name directories yourself.

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
