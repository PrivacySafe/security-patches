# Magento, Adobe Commerce and Mage-OS: PolyShell, CVE-2026-71362, StyleSmuggler and BlockStrap

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="magento-check"></a>

## Magento exploited-flaws check, hunt and upload-folder guard

**Script:** [`web-apps/magento/magento-check.sh`](magento-check.sh)

Four flaws hit Magento Open Source, Adobe Commerce and Mage-OS in 2026, and three of them were attacked before most stores had patched. Each has its own fix, and one of them changes no version string, so a store can look current and still be open. The script judges each flaw separately, looks for what the attacks leave behind, and closes the folder PolyShell writes into.

| Flaw | What it does | Exploited | Fixed in |
|---|---|---|---|
| **CVE-2026-48356**, PolyShell | Unauthenticated file upload through the guest-cart REST API (`/V1/guest-carts/:cartId/items`). A polyglot, a valid GIF or PNG with PHP inside, lands in `pub/media/custom_options/quote/`; where the web server runs PHP from there, it is remote code execution. CVSS 9.3 | Since March 2026; CISA KEV 27 October 2026 | July 2026 releases (APSB26-73, `-2026-jul`); Mage-OS 2.2.1 and every 3.x |
| **CVE-2026-71362** | Customer account takeover without authentication (incorrect authorization). CVSS 9.1 | Shortly after disclosure; CISA KEV 24 September 2026 | August 2026 releases (APSB26-92, `-2026-aug`); Mage-OS 3.4.0 |
| **CVE-2026-75650**, StyleSmuggler | Unauthenticated remote code execution through template `styles` parameters, in two stages: PHP stored in a report or log file, then included through a GraphQL gadget chain. CVSS 10.0 | From 4 September 2026, three days before the fix; CISA KEV 8 September 2026 | **Only** Adobe's hotfix VULN-39341 (APSB26-146, 7 September 2026); Mage-OS 3.5.0 |
| **CVE-2026-103849**, BlockStrap | A bypass of the StyleSmuggler fix through a second-pass directive in email templates. CVSS 10.0 | Not confirmed in the sources used here | October 2026 releases (APSB26-153, `-2026-oct`); Mage-OS 3.6.0 |

**The October release does not include the StyleSmuggler hotfix.** Sansec states that the October patch does not carry VULN-39341 and that Adobe's patch registry does not list it as a prerequisite; Adobe recommends applying both. A store on `2.4.8-2026-oct` without the hotfix is still open to StyleSmuggler.

Adobe published no fix for any of the four below Adobe Commerce and Magento Open Source 2.4.4. Scandiweb backported the StyleSmuggler fix to 41 older releases (2.2.0 to 2.4.3-p3); those patches are not reviewed here.

## What a version number can and cannot show

Adobe ships these fixes as full releases with a dated name (`2.4.9-2026-oct`), as isolated patches and as a hotfix, and the last two do not change the version string. The script gives a firm answer where one exists and names what to confirm where it does not:

| Install | PolyShell | CVE-2026-71362 | StyleSmuggler | BlockStrap |
|---|---|---|---|---|
| Dated release `-2026-jul` or later | Fixed | August or later: fixed | Needs evidence of the hotfix | October or later: fixed |
| Dated release before that | Exposed | Exposed | Needs evidence of the hotfix | Exposed |
| Any other Magento or Adobe Commerce 2.4.4 to 2.4.9 version (`2.4.8-p5`, `2.4.9`) | Confirm | Confirm | Needs evidence of the hotfix | Confirm |
| Below 2.4.4 | Out of Adobe support: exposed | | | |
| Mage-OS | 2.2.1 or later | 3.4.0 or later | 3.5.0 or later | 3.6.0 or later |

Sources disagree on plain `2.4.9`: Sansec reports that the May release of 2.4.9 carried the PolyShell fix, while Adobe's bulletin and the CVE record list 2.4.9 as affected and `2.4.9-2026-jul` as fixed. The script follows Adobe and asks you to confirm.

For StyleSmuggler, the script looks for evidence that the hotfix was applied: `VULN-39341` in `composer.json` (a `cweagans/composer-patches` entry), `composer.lock` or `.magento.env.yaml`, a patch file in `m2-hotfixes/` or `patches/` that names it, or the `disrex/stylesmuggler-adobe-patches` package, which applies Adobe's patch through Composer. A reference is evidence, not proof; confirm with Adobe's tool:

```bash
vendor/bin/magento-patches -n status | grep "39341\|Status"
```

The `ceymox/module-style-smuggler-shield` module and a CLI-only guard in the DI `ArrayScanner` are reported as community mitigations, not as the fix.

## The upload folder

PolyShell writes into `pub/media/custom_options/` whether or not the server ever runs the file. Whether the upload becomes code execution depends on the web server: on nginx a `location ~ \.php$` that comes first, or a plain prefix rule it overrides, sends `/media/custom_options/.../index.php` to PHP-FPM. The check reads:

- **nginx** (when nginx runs, or `WEB_SERVERS=nginx`): every configuration file under the usual folders and every absolute file they include (the store's `nginx.conf.sample` included), for a `location` naming `custom_options` that denies (`deny all`, `return 403`, `404` or `444`). A `^~` prefix wins wherever it is; a regex location must come before the first PHP regex location in its file; a plain prefix is overridden by a PHP regex location and is reported as not closing the folder. An `include` of the guard snippet counts; the snippet file on its own does not. Files that are links are not read.
- **Apache and LiteSpeed** (when they run, or with no server seen): `pub/media/custom_options/.htaccess` must deny all access (`Require all denied`, or `Deny from all`), comments aside. An `.htaccess` that only turns the PHP engine off still serves the file. A link is reported, not read.
- **The folder itself:** files already in it are counted, and any PHP file or file carrying PHP code is reported as a compromise.

On a release that carries the fix, an open folder is a warning (defense in depth); on any other, it is critical.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/web-apps/magento/magento-check.sh
less magento-check.sh
chmod +x magento-check.sh
./magento-check.sh check
sudo ./magento-check.sh hunt
sudo ./magento-check.sh mitigate --dry-run
```

By default it looks for `bin/magento` under `/var/www /srv /home /opt`. Pass directories to narrow it.

| Command | What it does |
|---|---|
| `check` (default) | Read-only. Finds installs, reads the distribution and version from `composer.lock` (or `composer.json` for a git checkout), judges the four flaws, looks for hotfix evidence, and reads the upload-folder rules. Also reads installs in running docker and podman containers (`SCAN_CONTAINERS=1`, the default); for those, the container's web server rules are not read. Exit `0` nothing exposed, `1` exposed or unconfirmed |
| `hunt` | Read-only. Looks for what the attacks leave behind (next section). Exit `0` nothing found, `1` findings or leads |
| `mitigate [--dry-run] [--no-nginx] [DIR ...]` | Root. Writes `pub/media/custom_options/.htaccess` where it is missing or does not deny, and the nginx guard `/etc/nginx/snippets/psf-magento-guard.conf`. Includes nothing and reloads nothing |
| `rollback [--dry-run]` | Root. Puts back every file `mitigate` changed and removes the files it created |
| `version` | Prints the script version |

Settings: `HUNT_DAYS` (30), `SCAN_CONTAINERS` (1), `WEB_SERVERS` (the servers to judge, `nginx`, `apache` or both; default: the running ones), `NGINX_DIRS`, `NGINX_SNIPPET_DIR` (`/etc/nginx/snippets`), `LOG_DIRS`, `STATE_DIR` (`/var/lib/psf-security-patches/magento-check`), `PSF_LOCK_WAIT` (30).

## Hunt

Indicators come from Sansec's PolyShell and StyleSmuggler research and the disrex StyleSmuggler incident notes. Addresses rotate within days: a match is a lead, and a miss proves nothing. A finding (`CRIT`) is something a stock store does not have; a lead (`WARN`) is an attempt or a pattern worth reading.

**In each store:**

- Files in the upload folder that are PHP or carry PHP code, with polyglot images named as such (Sansec's commonest drop is a `GIF89a` file called `780index.php`, the option ID before `index.php`).
- Any PHP file under `pub/media`, which holds none in a stock store, including the second StyleSmuggler crew's `pub/media/catalog/product/cache/ss_<hex>/sync_<hex>.php`.
- The `accesson.php` backdoor, which the PolyShell crew sprays into `assets/images/` folders inside every top-level folder it can write to, and any PHP in such a folder.
- Webshell and beacon strings in PHP outside the packages: the `8194460` beacon (`409723*20`), the two webshell password hashes, the second crew's `X-Cache-Token` value, the `gl_google_advisor_` cookie, and the stage-one labels `MGPROOF::` and `MGKWSIM::`.
- `vendor/magento/framework/App/View.php` reading a cookie or decoding base64, which is the cookie-triggered remote include Sansec found.
- PHP code or StyleSmuggler markers stored in `var/report/` (stage one of the chain), PHP open tags in `var/log/*.log`, and the `exception.log` signatures: Laminas `ClassMapAutoloader` errors (one per stage-two attempt; `Map file provided does not exist` marks a failed include), `Requested store is not found (<?` (the recon probe), and a GraphQL error about a `$guard` variable no Magento schema declares.
- `mgproof717.txt`, and the gs-netcat `defunct` and `defunct.dat` files.

**On the host:**

- A process whose name is a bracketed kernel-thread name but which runs a real program: kernel threads have no command line and belong to root, so `[kworker/u:8:0]` on a site account is the StyleSmuggler implant.
- A process with a system name (`fc-cache`, `chronyd`, `gvfsd-user`, `kworker`, `sshd`, `bash`) running a binary from `/tmp`, `/var/tmp`, `/dev/shm`, `~/.local/share/.gvfsd/` or `~/.cache/fontconfig/`; a `chronyd` that does not run from a system folder; an `sshd: <user>@notty` whose parent is PID 1 (the WraithC2 disguise).
- The published drop paths (`/tmp/.kw_*`, `/tmp/.fc-<hex>/fc-cache`, `/tmp/.fc_<hex>.lock`, `/tmp/.chrony-<hex>/chronyd`, `~/.local/share/.gvfsd/gvfsd-user`, `~/.cache/fontconfig/fc-cache`) and the php-fpm private `/tmp` drops (`.dbus-session-*`, `.pipewire-session-*`, `.dbus/.c2`, `.gsusr-*/defunct`, `adminer.version`).
- Cron entries for those binaries, read from the spool files themselves, because the implant writes the spool directly and leaves no syslog line.
- SHA-256 of every file and running binary it flags, against the published hashes.
- Open connections to the published command servers.

**In the access logs** (nginx, Apache, LiteSpeed, `/var/www` and `/home`, last `HUNT_DAYS` days, compressed files included): PHP requested from the upload folder and answered 200 (a finding), `accesson.php` or a cache shell answered 200, probes for PHP in the upload folder, addresses that posted to a guest cart and then requested the upload folder, StyleSmuggler requests (`styles[`, `template_styles`, `generatorClass`, `with_resolved`, PHP in the PayPal response query), and the published source addresses.

**In the database**, which the script does not open: the crews store skimmer loaders in CMS blocks and pages and in the HTML head setting, and Sansec found a fully patched store compromised through a rogue administrator. `hunt` prints read-only queries for `cms_block`, `cms_page`, `core_config_data` (`design/head/*`) and `admin_user`, with the published loader domains. Add your table prefix if the store uses one.

If `hunt` finds anything: keep the evidence (do not reboot; `/proc/<pid>/exe` can be the only copy of a deleted binary), remove the cron entries before stopping the processes, and rotate the encryption key and every credential it protected, at the source: admin passwords, integration and OAuth tokens, payment gateway credentials, database credentials, SSH and deploy keys. Rotating the key alone does not undo what was already read.

## Mitigate

`mitigate` closes the upload folder. It is a guard, not a fix: uploads still reach the disk until the July 2026 fix is in, and StyleSmuggler needs the hotfix.

- **`.htaccess`:** written in every install where it is missing or does not deny, with the PHP engine off and all access denied (`Require all denied`, and `Deny from all` for servers without `mod_authz_core`). Magento serves customer uploads through its own controller, which this does not affect. The file is written **as the account that owns the folder** (with `setpriv`, or `runuser`), so a link the web account plants cannot turn it into a root write elsewhere. Inside the folder nothing follows a link: the folder is opened with `O_NOFOLLOW`, a new file is created with `O_EXCL` beside the target and renamed over it, and an `.htaccess` or a `custom_options` that is a link is reported and left alone. An existing file is copied to `STATE_DIR` first, and its mode is kept. A missing `custom_options` folder is created by the owner of `pub/media`.
- **nginx snippet:** `/etc/nginx/snippets/psf-magento-guard.conf` closes the upload folder and any PHP under `media` (under both `/media/` and `/pub/media/`), and closes the connection (`444`) on the StyleSmuggler query strings, raw and percent-encoded, PHP in the query string, and PHP in the `User-Agent` or `Store` header. Nothing includes it and nothing is reloaded. Add it at the top of each Magento `server` block, above every PHP location, then test and reload:

```nginx
server {
    include snippets/psf-magento-guard.conf;
    # ... the store's own locations follow
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

The query-string rules stop the requests seen in the wild. The same parameters sent in a POST body pass them, which is why they do not replace the hotfix.

On Apache, the StyleSmuggler requests can be closed with mod_rewrite in the store's virtual host (the same caveat applies):

```apache
RewriteEngine On
RewriteCond %{QUERY_STRING} (styles(\[|%5B)|template_styles|generatorClass|with_resolved|<\?|%3C%3F) [NC]
RewriteRule ^ - [F]
RewriteCond %{HTTP:Store} <\? [OR]
RewriteCond %{HTTP_USER_AGENT} <\?(php|=) [NC]
RewriteRule ^ - [F]
```

`rollback` restores each copied file (newest run first, so the true original comes back last) and removes the files `mitigate` created, unless a created file was changed since, which it reports and leaves for you. Then remove any `include` line you added.

## Update

- **Adobe Commerce and Magento Open Source 2.4.4 to 2.4.9:** move to the October 2026 release for your line (`-2026-oct`), which carries the PolyShell, August and BlockStrap fixes, and apply hotfix VULN-39341 from APSB26-146 as well.
- **Mage-OS:** 3.6.0 or later.
- **Below 2.4.4:** no Adobe fix exists; upgrade.
- **Every environment that faces the internet**, staging included.

## Sources

- [Sansec: PolyShell](https://sansec.io/research/magento-polyshell): the upload path, affected web server setups, payloads, filenames, `accesson.php`, loader domains and scanner addresses
- [Sansec: StyleSmuggler](https://sansec.io/research/stylesmuggler-0day): the two stages, the implants, persistence, the second crew and the indicators
- [Sansec: BlockStrap](https://sansec.io/research/blockstrap-magento-rce): including that the October patch does not carry VULN-39341
- [disrex: StyleSmuggler mitigation notes](https://github.com/disrex-group/stylesmuggler-mitigation): the process check, the query-string patterns and further indicators
- [Adobe APSB26-153](https://www.adobe.com/trust/security/products/commerce/apsb26-153.html); Adobe APSB26-146, APSB26-92 and APSB26-73
- [Experience League: APSB26-146 hotfix](https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146)
- [Mage-OS 3.4.0](https://github.com/mage-os/mageos-magento2/releases/tag/3.4.0), [3.5.0](https://github.com/mage-os/mageos-magento2/releases/tag/3.5.0) and [2.2.1](https://mage-os.org/releases/2026-03-18-mage-os-2-2-1-release/) release notes
- [Scandiweb: Magento security news](https://scandiweb.com/blog/magento-security-news/): the CISA listing dates

## Before you run it

- **The hotfix needs evidence.** No release carries VULN-39341, so a dated or current version never settles StyleSmuggler. A reference in the project files is evidence; Adobe's `magento-patches status` is the confirmation.
- **A clean hunt is not a clean store.** The script does not read the database, does not see stores in other containers' file systems beyond the files it copies for `check`, and reads only the logs it can reach; run it as root, and run the printed queries.
- **The nginx reading is a static reading.** It follows absolute `include` paths but not relative ones, does not evaluate `if` or `map`, and judges the order of locations within one file. `nginx -T` shows the configuration as nginx sees it.
- **The `.htaccess` needs `AllowOverride`.** Apache ignores it where overrides are off; then put the same rules in the virtual host.
- **mitigate needs python3 and `setpriv` or `runuser`.** It refuses to write a store folder without switching to its owner.
- A Mage-OS pre-release is not the release: `3.6.0-rc1` is reported with a warning.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. It copies only the files it reads into a private temporary directory, never runs anything in a container beyond `find` and a file copy, and never keeps a staged link.

## Output for automation

`--output jsonl` (or `PSF_OUTPUT=jsonl`) makes `check`, `hunt`, `mitigate` and `rollback` write JSON Lines for monitoring and language models. Each finding of `check` carries a `kind` (`vulnerability`, `exposure` or `compromise`), a stable `code` such as `MAGENTO_UPLOAD_PHP` and the install's `path`; a host with no install says so (`applicable: false`). `psf-report` turns the records into a summary, Markdown, HTML or PDF. `PSF_READ_ONLY=1` refuses `mitigate` and `rollback` before they start, so a scheduled run can only read. The format and the reports: [Output for automation](../../automation/README.md).

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
