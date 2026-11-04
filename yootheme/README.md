# YOOtheme Pro 5: CVE-2026-102785 unauthenticated remote code execution

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="yootheme-check"></a>

## YOOtheme check

**Script:** [`yootheme/yootheme-check.sh`](yootheme-check.sh)

YOOtheme Pro is a widely used commercial theme and page builder for WordPress and Joomla. Its public image handler, the route that creates and caches resized images, does not fully tie the image operations and the output location to the request signature (CVE-2026-102785, CVSS 10.0). Without logging in, an attacker can reuse a signature from an ordinary public image URL, add image operations, step out of the cache directory and write a PNG/PHP polyglot into a public media directory that runs PHP. Requesting that file runs the attacker's code.

| | |
|---|---|
| CVE | CVE-2026-102785 (CWE-434, published 22 October 2026) |
| Severity | **Critical, CVSS 10.0** |
| Affected | YOOtheme Pro 5.0.0 through 5.0.52 |
| Fixed | **5.0.53** (released 21 October 2026) |
| Not affected | YOOtheme Pro 4 and earlier (vendor statement) |
| Needs | Nothing: no account is required |
| Exploited | Not listed as known exploited. A CVSS 10 pre-authentication flaw with a published mechanism should be treated as likely to be exploited quickly |
| Workaround | None documented by the vendor. See the web server rules below |

**Sources disagree slightly, and this tool follows the vendor.** The CVE record is filed against the Joomla extension, and one aggregator's title says "5.0.0-5.0.55". The vendor's own notice, the changelog entry and the CVE description text say 5.0.52 and earlier, fixed in 5.0.53, for "YOOtheme Pro 5" in general. So the tool applies the same rule to the **WordPress theme** as well as the Joomla template.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/yootheme/yootheme-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/yootheme/yootheme-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less yootheme-check.sh
   chmod +x yootheme-check.sh
   ```

3. Check the version, then hunt for what the attack leaves behind. Run the hunt as root so it can read your web logs.

   ```bash
   ./yootheme-check.sh check
   sudo ./yootheme-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds WordPress themes (`wp-content/themes/yootheme`) and Joomla templates (`templates/yootheme`) under `/var/www /srv /opt /home` or the directories you pass, reads each version, and applies the rule. A look-alike such as `yootheme-child` is not matched |
| `hunt [DIR ...]` | Runs `check`, then searches each site's upload, media and cache directories and the web logs (below) |
| `mitigate [--web auto\|apache\|nginx] [--dir DIR] [--dry-run] [--reload] [--force]` | **Changes the host (root).** Applies the rule below for you, and only when an affected or unreadable YOOtheme is found. Apache: writes `psf-yootheme-deny-php.conf` (`conf-available` plus `a2enconf` on Debian, `conf.d` on RHEL) and checks it with a configtest. nginx: writes a snippet and adds an `include` as the first line of every server block that serves PHP, then checks with `nginx -t`. If the web server rejects the result, everything is undone at once. Reloads nothing unless you add `--reload` |
| `rollback [--dry-run] [--reload]` | Removes what `mitigate` added and restores the files it edited |
| `version` | Prints the script version |

Environment: `HUNT_WEB_LOGS` adds web access log paths for the hunt. `STATE_DIR` (default `/var/lib/psf-security-patches/yootheme`) holds the backups and manifest. `NGINX_MAIN_CONF=FILE` checks a non-default nginx main file.

Exit codes: `0` nothing affected or nothing found, `1` an affected or unreadable version, or an indicator, `2` bad arguments.

It reads the standard WordPress theme header (`style.css`, `Version:`) and the Joomla template manifest (`templateDetails.xml`, `<version>`). If it cannot read a version it says so and exits `1`. The YOOtheme dashboard also shows the version.

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget:

```bash
sudo ./yootheme-check.sh mitigate --dry-run
sudo ./yootheme-check.sh mitigate
sudo ./yootheme-check.sh rollback
```

## What the hunt looks for

| Where | Indicator |
|---|---|
| Upload, media and cache directories (WordPress: `uploads`, `wp-content/cache`, the theme's `cache`; Joomla: `images`, `cache`, `media`, the template's `cache`) | PHP files (`.php`, `.phtml`, `.phar`, `.pht`, `.php5` and similar). The harmless WordPress placeholder `index.php` containing "Silence is golden" is ignored |
| The same directories | Image files (PNG, JPEG, GIF, WebP) that contain a `<?php` open tag, which is what a polyglot looks like. Only the five-byte `<?php` is searched: a three-byte `<?=` would match random image data |
| Web access logs | Successful (2xx) requests to a PHP file under a `cache`, `images`, `media` or `uploads` path, counted by client and path. The match is case-insensitive and ignores the query string |

A clean hunt does not prove a site is clean: the attacker may have used a path or name the hunt does not cover, and logs rotate.

## If the hunt finds something

1. Keep a copy of the file for analysis before you delete it.
2. Update YOOtheme Pro to 5.0.53 or later, and remove any file you did not put there.
3. Look for other changes: new administrator users, modified theme and plugin files, new scheduled tasks.
4. Rotate the CMS, database and hosting credentials, and consider restoring from a backup taken before 21 October 2026.

An update does not remove a file an attacker already wrote.

## Protective measure: deny PHP in media and cache paths

`./yootheme-check.sh mitigate --dry-run` and then `mitigate --reload` apply the rules below. `rollback` removes them. Verified on nginx 1.24: PHP under `uploads` and `cache` (including `.PHP` and `.phtml`) gets 403 after the change and reached the PHP handler before. `index.php` and static files are unaffected. On Apache 2.4.58 with mod_php and two virtual hosts, the same rule stopped an uploaded PHP file from running on both, and in the Debian layout `a2enconf` and Apache's own `configtest` accepted it and `rollback` removed it. The rule applies to every PHP virtual host on the machine.

PrivacySafe recommendation. It stops a written file from running. It does not stop the write, so it does not replace the update. On nginx and Apache, both rules answer 403 for PHP under uploads, media, images and cache paths. That includes upper-case extensions, a query string, and the `/images/a.jpg/x.php` path-info trick. Ordinary PHP entry points such as `/index.php` and `admin-ajax.php`, a file merely *named* `cache.php`, and static images are served as before.

nginx (this location must come **before** your generic PHP location, because the first matching regex wins):

```nginx
location ~* ^/(.+/)?(cache|images|media|uploads)/.+\.(php|phtml|phar|pht|php[0-9])$ { return 403; }
```

Apache (in the server or virtual host configuration):

```apache
<LocationMatch "(?i)^/(.+/)?(cache|images|media|uploads)/.+\.(php|phtml|phar|pht|php[0-9])$">
    Require all denied
</LocationMatch>
```

These rules also block any legitimate PHP file that lives under a directory named `cache`, `images`, `media` or `uploads` and is requested directly. That is unusual, but check your site before you rely on them.

## Sources

- [YOOtheme on X: critical security update for YOOtheme Pro 5](https://x.com/yootheme)
- [mySites.guru: YOOtheme Pro 5.0.53 fixes an unauthenticated RCE](https://mysites.guru/blog/yootheme-pro-5-critical-security-update/)

## Before you run it

- The fix. Update YOOtheme Pro 5 to 5.0.53. YOOtheme Pro 4 and earlier are not affected (vendor statement).
- Sources disagree slightly. The CVE record is filed against the Joomla extension and one aggregator title says 5.0.0 to 5.0.55. The vendor's notice, the changelog and the CVE description say 5.0.52 and earlier, fixed in 5.0.53, for YOOtheme Pro 5 in general, and the script follows the vendor.
- A CVSS 10 flaw with a published mechanism should be treated as likely to be exploited quickly, although it was not listed as exploited at the time of the sources.
- `hunt` is read-only. Run it on a site that was exposed before the update.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe inside each running docker and podman container copies only the first few KB of each YOOtheme `style.css` or `templateDetails.xml`, where the version is, and the script runs once per container in isolation against that copy. `hunt` does not look inside containers. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME.

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
