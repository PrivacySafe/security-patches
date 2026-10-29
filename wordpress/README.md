# WordPress: XSS2Shell core check and October 2026 plugin checks

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="wordpress-xss2shell-check"></a>

## WordPress XSS2Shell check

**Script:** [`wordpress/wordpress-xss2shell-check.sh`](wordpress-xss2shell-check.sh)

WordPress Core 4.7 through 7.0.2 reflects the submitted username in the `wp-login.php` error message through `sprintf()` without adequate sanitization. A whitespace parser-differential payload (`< area`, with a space between `<` and the tag name) survives PHP `strip_tags()` but is re-tokenized by WordPress's KSES sanitizer into a live DOM element. An attacker who can get a logged-in administrator to send that crafted login form runs attacker JavaScript in the WordPress origin, and can then chain the injected session privileges into full remote code execution through OAuth app-password abuse and plugin upload. No account is required for the XSS stage. Disclosure by PWN.AI on 2026-08-07; WordPress shipped the fix in 7.0.3 the same day.

| | |
|---|---|
| CVE | CVE-2026-64638 (CWE-79, reflected XSS) |
| Severity | 8.9 (CVSS 4.0, `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N`) |
| Affected | WordPress Core 4.7 through 7.0.2 |
| Fixed | 7.0.3 (same day as disclosure, 2026-08-07) |
| Attack vector | Pre-authentication: a single crafted POST to `wp-login.php` delivers the XSS payload; the RCE stage requires a logged-in administrator to visit attacker-controlled content |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/wordpress/wordpress-xss2shell-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/wordpress/wordpress-xss2shell-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less wordpress-xss2shell-check.sh
   chmod +x wordpress-xss2shell-check.sh
   ```

3. Check a site. The probe is a non-destructive POST to `wp-login.php` that generates one failed-authentication entry.

   ```bash
   ./wordpress-xss2shell-check.sh check https://your.site
   ```

4. Full defensive-posture audit.

   ```bash
   ./wordpress-xss2shell-check.sh audit https://your.site
   ```

5. Look for signs of exploitation in web server logs and plugin directories.

   ```bash
   sudo WP_ROOTS="/var/www/html /srv/www" ./wordpress-xss2shell-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check URL` (default) | Detects the WordPress version from the homepage meta generator (and from `/wp-links-opml.php` as a fallback), then POSTs the parser-differential probe to `wp-login.php` and checks whether it is reflected unescaped into the response. One failed-authentication entry is written to the auth log; nothing else changes. Exits `0` if not vulnerable, `1` if vulnerable, `2` if the target was unreachable or not WordPress |
| `audit URL` | All of `check`, plus: sensitive file exposure (`wp-config` backups, `.git/config`, `debug.log`, `.env`, `xmlrpc.php`), security response headers (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`), and REST API user enumeration. Exits `0` if no critical findings, `1` if critical |
| `hunt [WEBROOT]` | Scans web server access logs for POST bursts to `wp-login.php`, requests to `authorize-application.php` (OAuth app-password abuse), plugin upload requests, and direct PHP calls in plugin directories returning 200; WordPress `debug.log` for suspicious patterns; and plugin directories for PHP files created after `HUNT_SINCE`. Root optional but improves coverage. Exits `0` if nothing found, `1` if findings |
| `version` | Prints the script version. Every command prints it on its first line too |

Environment: `WP_ROOTS` (space-separated directories to look for `wp-content/` under; default `/var/www /srv/www /srv/www/html /opt/wordpress`), `HUNT_SINCE` (how far back hunt looks; default `2026-08-07`, the disclosure date), `HUNT_LOGS` (extra log file globs), `CURL_OPTS` (extra curl options, e.g. `--insecure` for a self-signed certificate).

## What the probe checks and why it is non-destructive

The probe posts `< area id=ajaxurl href=/?rest_route=/>` as the username to `wp-login.php`. On a vulnerable WordPress install, KSES re-tokenizes the whitespace-prefixed tag into a real `<area id="ajaxurl">` element in the error message; on a patched install the output is escaped or the tag is stripped. The checker looks for `id="ajaxurl"` and `<area` together with `Error:` (the login-failure marker, which also prevents false positives against non-WordPress pages). This is the same matcher the verified Nuclei template uses.

Posting to `wp-login.php` with an incorrect password generates one failed-authentication record in the auth log and no other side effects: no account is created or modified, no data is written, and no session is opened.

## What `hunt` looks for

In web server access logs (Apache and nginx, from standard paths and from `HUNT_LOGS`):

- **POST bursts to `wp-login.php`:** the XSS stage sends a crafted login form. Legitimate traffic is usually much lower volume.
- **Requests to `authorize-application.php`:** this page handles OAuth application-password authorization and is not normally accessed directly. A request here after a burst of login POSTs is a strong indicator of stage 4 of the chain.
- **Plugin upload requests (`update.php?action=upload-plugin`):** the RCE stage uploads a plugin zip containing a webshell. Each upload that the admin did not make is worth investigating.
- **Direct PHP access in plugin directories returning 200:** a webshell dropped via plugin upload lives at `wp-content/plugins/<slug>/<slug>.php` and is web-accessible without activation. Successful GET requests to a path matching that pattern are a strong signal.

In plugin directories under `WP_ROOTS` (with `WEBROOT` supplied as an argument or from the environment):

- **PHP files created after `HUNT_SINCE`:** any `*.php` file that appeared after the disclosure date is worth reviewing. The webshell dropped by the public PoC is not named uniquely, so a new PHP file in any plugin directory is a lead.

In WordPress `debug.log` (under `WP_ROOTS`):

- Fatal errors, `call_user_func` warnings, and `system()` or `shell_exec()` calls that suggest code execution.

A hit is a lead, not proof. Confirm by reviewing the specific request IDs, the plugin directory contents, and your outbound traffic logs.

## Know before you run it

- **`check` and `audit` make HTTP requests to the target.** The probe causes one failed-authentication entry. The sensitive-file checks each make one GET request. `audit` fetches the homepage, the OPML endpoint, several sensitive paths, the homepage headers, and the REST API user list: nine or ten requests in total.
- **`hunt` is read-only.** It reads log files and file system metadata; it does not modify anything.
- **Version detection can miss.** WordPress plugins and themes often hide the meta generator tag. A clean version result does not mean the site is patched; the XSS reflection probe covers this case independently.
- **GNU/Linux only.** The find `-printf` and date formats assume GNU tools.
- **Root helps but is not required.** Without root, hunt reads only the logs you own and may miss files in other users' directories.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container copies only the `Plugin Name` and `Version` header lines of each covered plugin's main file, plus its modification time, and the script runs once per container in isolation against that copy. For Rank Math PRO 3.0.123 the arrival-time test uses the modification time alone, because a container's inode change time cannot be recovered; the output says so. `hunt` does not look inside containers. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME.

## Sources

- PWN.AI disclosure: [https://pwn.ai/blog/xss2shell](https://pwn.ai/blog/xss2shell)
- NVD record: [https://nvd.nist.gov/vuln/detail/CVE-2026-64638](https://nvd.nist.gov/vuln/detail/CVE-2026-64638)
- THN coverage: [https://thehackernews.com/2026/08/new-wordpress-pre-auth-xss-could-lead.html](https://thehackernews.com/2026/08/new-wordpress-pre-auth-xss-could-lead.html)
- NHS cyber alert: [https://digital.nhs.uk/cyber-alerts/2026/cc-4827](https://digital.nhs.uk/cyber-alerts/2026/cc-4827)
- Nuclei template (upstream): projectdiscovery/nuclei-templates PR #16785

<a name="wordpress-plugins-october-2026-check"></a>

## WordPress plugin checks, October 2026

**Script:** [`wordpress/wordpress-plugins-oct2026-check.sh`](wordpress-plugins-oct2026-check.sh)

Eight plugin problems: seven vulnerabilities and one supply-chain compromise. The script reports all eight and hunts for signs of abuse.

| | CVE-2026-113500 | CVE-2026-111862 | CVE-2026-110372 | CVE-2026-112241 |
|---|---|---|---|---|
| Plugin | LiteSpeed Cache (millions of active installs) | Rank Math SEO PRO, the paid add-on (the free Rank Math SEO plugin is not part of the incident) | OttoKit, formerly SureTriggers (folder `suretriggers`) | SureCart, the e-commerce plugin from the same vendor (folder `surecart`) |
| What | An HTML optimization routine is not limited to stylesheet content and can delete the markup that closes an attribute in the rendered page. With unescaped comment author output, an unauthenticated visitor whose comment is published can inject event-handler attributes that run JavaScript for any visitor, including a logged-in administrator | Some copies of version 3.0.123 contained malware. Rank Math removed the files and shipped 3.0.124 | Incorrect privilege assignment (CWE-266) lets an unauthenticated visitor escalate privileges, in practice to administrator | Authentication bypass by spoofing (CWE-290): an attacker can present identity markers the plugin trusts and be treated as another user, with no valid credentials |
| Affected | Below 7.9.2 | Copies of 3.0.123 downloaded or updated between 15 October 2026 20:02 UTC and 16 October 2026 07:12 UTC. The genuine 3.0.123 is dated 7 October, so the version number alone does not prove compromise | 1.1.40 and earlier | 4.9.5 and earlier |
| Fixed | 7.9.2 | 3.0.124 (the clean replacement). **An update alone does not remove what the malware left behind** | 1.1.41. **An update does not remove administrator accounts already created** | 4.9.6. **An update does not undo account takeovers** |
| Severity | High 7.5 | 9.8 Critical | 9.8 Critical | 9.8 Critical |
| Needs | The HTML optimization feature on, and comments from unauthenticated visitors being published | The tainted copy to have been activated. Reports say it does nothing until then | Nothing: the flaw is reachable without an account | No credentials (a CVSS 9.8 score implies none are required) |
| Exploitation | None known to us | The malware shipped through the vendor's own update channel | A Nuclei template exists and is tagged as known-exploited by VulnCheck's list. Another tracker says no public proof of concept exists. Treat exploitation as plausible | None known to us. Patchstack rates it high priority and expects mass exploitation |

Two booking plugins and a registration plugin, covered by the same script:

| | CVE-2026-110653 | CVE-2026-112327 | CVE-2026-112242 |
|---|---|---|---|
| Plugin | LatePoint, appointment booking (folder `latepoint`) | Amelia, booking (folder `ameliabooking`) | Profile Builder, registration forms and profiles (folder `profile-builder`; the paid add-on ships separately and is not checked) |
| What | The one-time-password check increments its attempts counter with a stale value and no conditional guard or row lock, so concurrent requests slip past the 10-attempt lockout and an unauthenticated visitor can brute-force the code and log in as a customer | SQL injection | Incorrect privilege assignment (CWE-266): a low-privilege account may gain a higher role |
| Affected | 5.7.4 and earlier | 2.4.11 and earlier | 4.0.4 and earlier |
| Fixed | 5.7.5. The advisory references the 5.7.5 code for the fixed helper; the advisory does not say "fixed in" in so many words | 2.4.12 or later (Patchstack's solution) | 4.0.5 |
| Severity | 9.1 Critical (CVSS 3.1) | 9.3 Critical | 8.8 High (CVSS 3.1) |
| Needs | Nothing: no account is required | The advisory does not state a required role; a 9.3 score implies none | A low-privilege account (privileges required: low), such as a registered user |
| Exploitation | None known to us | None known to us | None known to us |

One more plugin, exploited since 7 October 2026:

| | CVE-2026-85097 |
|---|---|
| Plugin | Bricksforge, an add-on for the Bricks site builder (about 6,000 sites). It is found by the `Plugin Name` in its main file, whatever its folder is called |
| What | The plugin trusts file metadata that arrives with a form submission. An unauthenticated visitor gets a form nonce, uploads a file that passes the image type check but also holds PHP code, then submits the form naming a `.php` file, and the code runs. Attackers used the route `/wp-json/bricksforge/v1/form_submit` and filenames matching `login_admin_*.php`, sometimes placed straight in the uploads directories |
| Affected | 3.1.8.9 and earlier. Sites with Pro Forms active are affected even when no form has an upload field |
| Fixed | 3.1.8.10 for the 3.x line. The vendor changelog says 4.0.0 also has the fix; Patchstack names 4.0.1. The script treats 4.0.0 as unconfirmed and 4.0.1 or later as fixed |
| Severity | 10.0 Critical (9.8 in one report) |
| Needs | Nothing: no account is required |
| Exploitation | **Yes.** Patchstack saw the first attempts on 7 October 2026 at 21:47 UTC, before the advisory of 8 October, from 63 addresses within days |
| If you cannot update | Deactivate Pro Forms or the whole plugin (the mitigation reported by Patchstack). **An update does not remove a file already uploaded**: run `hunt` and treat a site that was reachable as possibly compromised |

**What the Rank Math malware reportedly does once activated.** It contacts a command server (`rank1cdn[.]com`), plants hidden PHP backdoors that it rebuilds whenever a visitor loads a page, creates administrator accounts, drops a fake WordPress core file and PHP code hidden inside `.cache` files, adds scheduled tasks, can add SSH keys, and reads every secret the web server can reach: WordPress passwords, the database login, API keys and payment gateway keys. Treat an activated tainted copy as a full compromise. The vendor notice is [rankmath.com/kb/pro-3-0-123-security-incident](https://rankmath.com/kb/pro-3-0-123-security-incident/).

### Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/wordpress/wordpress-plugins-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/wordpress/wordpress-plugins-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less wordpress-plugins-oct2026-check.sh
   chmod +x wordpress-plugins-oct2026-check.sh
   ```

3. Check the versions, then hunt. Run the hunt as root so it can read crontabs and logs.

   ```bash
   ./wordpress-plugins-oct2026-check.sh check
   sudo ./wordpress-plugins-oct2026-check.sh hunt
   ```

### Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds WordPress installs (a `wp-content/plugins` directory under `/var/www /srv /home /opt /usr/share/wordpress`, or the directories you pass), reads the `Version:` header of LiteSpeed Cache, OttoKit, SureCart, LatePoint, Amelia, Profile Builder and Rank Math PRO (folders `seo-by-rank-math-pro` and `rank-math-pro`), and compares them. For Rank Math PRO 3.0.123 it compares the plugin file's modification and inode-change times with the incident window |
| `hunt [DIR ...]` | Looks for the published Rank Math indicators, for signs of OttoKit abuse and for Bricksforge upload attacks, in each install and on the server (below) |
| `version` | Prints the script version |

Exit codes: `0` nothing affected or nothing found, `1` affected or to review (check) or an indicator found (hunt), `2` bad arguments.

A pre-release of a fixed release (`7.9.2-rc1` against a fix in 7.9.2) counts as below it, as in semantic versioning, so it is never reported as the release.

### Reading the Rank Math result

- **3.0.123 whose files changed inside the window:** likely the tainted package.
- **3.0.123 that arrived before the window opened:** not the tainted package.
- **3.0.123 that arrived after the window:** probably clean, because Rank Math pulled the bad files, but the script asks you to update and run the hunt. File times are circumstantial: a backup restore or `rsync` resets them. Also check the plugin update history, your backup log and the email Rank Math sent to affected accounts.
- **3.0.124 or newer:** clean replacement. If the site ever ran 3.0.123, run the hunt anyway.

### Reading the Profile Builder result

- **4.0.4 or earlier:** affected. Update to 4.0.5. A registered user may be able to gain a higher role, so afterwards review administrator and editor accounts (the hunt lists administrators created since 1 October). If you cannot update today, deactivate the plugin and close public registration. Only the free `profile-builder` folder is checked; a folder named `profile-builder-pro` is a different product and is not matched.

### Reading the LatePoint and Amelia results

- **LatePoint 5.7.4 or earlier:** affected. Update to 5.7.5. An attacker who brute-forces the one-time code logs in as a customer, so afterwards review recent customer logins and bookings. The hunt counts web log requests that name LatePoint's OTP route (`auth__verify_otp`) by source address; many from one address is a lead. POST bodies are not normally logged, so a POST-only attack may not show.
- **Amelia 2.4.11 or earlier:** affected. Update to 2.4.12. An SQL injection can expose the whole database, including user password hashes, so afterwards rotate administrator passwords and the keys and salts in `wp-config.php`, and run the hunt for new administrators.
- If you cannot update today, deactivate the plugin: an inactive plugin registers no routes (our reasoning, not vendor documented).

### Reading the SureCart result

- **4.9.5 or earlier:** affected. Update to 4.9.6, or deactivate the plugin if you cannot update today (an inactive plugin registers no routes; this is our reasoning, not vendor documented). After updating, reset administrator passwords and end all sessions by changing the `AUTH_KEY` and `SECURE_AUTH_KEY` salts in `wp-config.php`, because an authentication bypass leaves no account trace.
- **4.9.6 or newer:** fixed. If the site ran 4.9.5 or earlier in October, run the hunt. It lists new administrator accounts, but it cannot see a login as an existing user, so also review recent administrator activity.
- SureCart has had a run of authentication and account-takeover fixes this autumn, so keep it current rather than pinning a version.

### Reading the OttoKit result

- **1.1.40 or earlier:** affected. Update to 1.1.41, or deactivate the plugin if you cannot update today (an inactive plugin registers no routes; this is our reasoning, not vendor documented).
- **1.1.41 or newer:** fixed, but a site that ran an affected version in October may already have a rogue administrator. Run the hunt.

### What the hunt looks for

| Where | Indicator |
|---|---|
| Files, per install (Rank Math) | `wp-includes/class-wp-cache-util.php` (not a real WordPress file); `.cache` files that contain PHP; `.htaccess` rules that mention `.cache` together with PHP or a handler; the key `xmmqhn` or the name `rank1cdn` in PHP or `.cache` files; PHP in `wp-content/mu-plugins` and in `wp-content/uploads` (reported for review, not as proof) |
| Database, per install (Rank Math) | `wp_options` rows named `_uf6qdn2hmm`, `t8krdk990phb` or `_np5pvf754c`; users whose login starts with `wpsupport_` or whose email ends in `@wp-mail.net` |
| Database, per install (OttoKit) | Administrator accounts created since 1 October 2026 (change it with `HUNT_ADMIN_SINCE`). Reported for review: you know which administrators are yours |
| Server (Rank Math) | Crontab entries tagged `#ms6v46`; logs that mention `rank1cdn`; `authorized_keys` files changed since 15 October 2026 (reported for review) |
| Files, per install (Bricksforge) | Files named `login_admin_*.php` anywhere under `wp-content`; PHP, `.phtml` or `.phar` files in `wp-content/uploads` (the empty `index.php` stubs some plugins write are not counted). Both are strong leads: WordPress uploads should hold no PHP |
| Server (Bricksforge) | Requests to `/wp-json/bricksforge/v1/form_submit` (or its `rest_route` form) in the readable web logs, counted by source address. Real visitors use this route too, so it is reported for review, not as proof |
| Server (LatePoint) | Requests naming `auth__verify_otp` in the readable web logs, counted by source address. Reported for review, not as proof |
| Server (OttoKit) | Requests to OttoKit's REST routes (`sure-triggers`) in the readable web logs, counted by source address. OttoKit's own cloud service also calls these routes, so a count is not an alarm: unfamiliar addresses are the lead. Set `HUNT_WEB_LOGS` to add log paths |

The Rank Math indicators come from public reports of the incident (Rank Math, Wordfence and Patchstack, as relayed by several write-ups). The named rows, domain, usernames, fake core file and cron tag are specific to that attack. A clean hunt does not prove a site is clean, and the published list may be incomplete. The administrator list is a generic check that also catches other privilege escalations.

### How the database check works, and why it avoids wp-cli

The script reads `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` and `$table_prefix` from `wp-config.php` with a text search, and runs three `SELECT` queries with the `mysql` client. The password goes through the `MYSQL_PWD` environment variable, not the command line. It deliberately does not use `wp-cli`: `wp-cli` loads the site's PHP, including `mu-plugins`, and a backdoor could run when it does. `localhost:/path/to.sock` and `host:port` forms of `DB_HOST` are understood. If there is no readable `wp-config.php`, no `mysql` client or the login fails, the script prints the three queries so you can run them yourself.

### If the hunt finds something

For the Rank Math malware:

1. Delete the whole `rank-math-pro` plugin folder first. Deactivating it does not stop the malware, and it recreates deleted files whenever someone visits the site, so remove the folder and the database rows before the other files.
2. Block outgoing traffic to `rank1cdn[.]com`.
3. Restore files and database from a backup taken before 15 October 2026 20:02 UTC.
4. Rotate WordPress user passwords, the database login, the keys and salts in `wp-config.php`, payment, SMTP and API keys, and hosting, FTP and SSH logins.
5. Only then install Rank Math PRO 3.0.124, downloaded by typing the vendor's address yourself. Rank Math says it never sends download links by email.

For OttoKit: update to 1.1.41, remove administrator accounts you did not create, reset the password of every administrator and rotate the keys and salts in `wp-config.php`, and review plugins and themes for files you did not add.

### LiteSpeed Cache: fixing and an interim measure

Update LiteSpeed Cache to 7.9.2 or later. Until then, hold every comment for moderation (Settings, Discussion). That is our reading of the description, which needs a published comment from an unauthenticated visitor; it is not vendor documented.

### Sources

- [Rank Math: PRO 3.0.123 security incident](https://rankmath.com/kb/pro-3-0-123-security-incident/)
- [CVE record for CVE-2026-113500 (WPScan)](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/113xxx/CVE-2026-113500.json)
- [Patchstack: Bricksforge arbitrary file upload exploited (CVE-2026-85097)](https://patchstack.com/articles/critical-unauthenticated-arbitrary-file-upload-vulnerability-exploited-in-bricksforge-plugin/)
- [Patchstack entry for the OttoKit flaw](https://patchstack.com/database/wordpress/plugin/suretriggers/vulnerability/wordpress-ottokit-plugin-1-1-40-privilege-escalation-vulnerability)

<a name="wp2shell-check"></a>

## wp2shell: WordPress core pre-authentication RCE (CVE-2026-63030 and CVE-2026-60137)

**Script:** [`wordpress/wordpress-wp2shell-check.sh`](wordpress-wp2shell-check.sh)

wp2shell chains two flaws in WordPress core into remote code execution for an **unauthenticated** attacker on a default install, with no plugins and no login. It was disclosed and fixed on 17 July 2026, exploitation began on 20 July, and CISA added both CVEs to its Known Exploited Vulnerabilities catalog on 21 July. Observed attacks create rogue administrator accounts and install webshells. Discovered by Adam Kues of Searchlight Cyber.

| | CVE-2026-63030 | CVE-2026-60137 |
|---|---|---|
| What | REST API batch endpoint route confusion (`/wp-json/batch/v1` or `/?rest_route=/batch/v1`): a malformed sub-request path desynchronizes the matched handlers from the requests, so later sub-requests run under the wrong permission check | SQL injection in `WP_Query`: when `author__not_in` reaches the query as a string rather than an array, it skips integer sanitization and is interpolated into the SQL `WHERE` clause |
| Affected | 6.9.0 through 6.9.4, 7.0.0 through 7.0.1, and 7.1 beta 1 | 6.8.0 through 6.8.5, 6.9.0 through 6.9.4, 7.0.0 through 7.0.1, and 7.1 beta 1 |
| Fixed | 6.9.5, 7.0.2, 7.1 beta 2 | 6.8.6, 6.9.5, 7.0.2, 7.1 beta 2 |
| Not affected | Before 6.9.0 (the flaw is absent on 6.8.x) | Before 6.8.0 |
| Chain | Together on 6.9.x and 7.0.x: unauthenticated RCE. On **6.8.x only the SQL injection exists**, and the full chain does not apply | |
| Object cache | The SQL injection sink is **not reached when a persistent object cache (Redis, Memcached) is active**. A cached site may appear safe from this check but should still be updated, because disabling the cache later re-exposes it | |

Update with `wp core update`, to 6.8.6, 6.9.5, 7.0.2 or newer on your branch.

**Object cache caveat:** when a persistent object cache (Redis, Memcached) is active, the SQL injection sink is not reached and the chain does not fire. The site still needs the update; if the cache is ever disabled or flushed the full chain becomes reachable again.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/wordpress/wordpress-wp2shell-check.sh
less wordpress-wp2shell-check.sh
chmod +x wordpress-wp2shell-check.sh
./wordpress-wp2shell-check.sh check
./wordpress-wp2shell-check.sh hunt
```

By default it searches `/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress`; pass directories to narrow it. Everything it does is read-only.

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds each WordPress install by `wp-includes/version.php`, reads the version, reads the two source files for the fixes, and looks for a web server rule that refuses the batch route. Exit `0` nothing exposed, `1` an install without the fixes or whose state is unclear |
| `hunt` | Looks for signs of exploitation: requests to the batch route and SQL injection strings in web server logs (plain and rotated `.gz`), PHP files inside `wp-content/uploads`, and changes to `wp-content/mu-plugins` since the disclosure. Exit `0` nothing found, `1` a strong lead. A lead is not proof, and a clean hunt is not proof of safety |
| `version` | Prints the script version |

Env: `HUNT_SINCE` (`YYYY-MM-DD`, default `2026-07-17`) sets the date for file changes; `WP2S_LOGS` names web server logs (space separated paths or globs) when they are not in the usual places.

## How the check decides

- **Version, per branch.** 6.8.0 to 6.8.5 is reported as the SQL injection only; 6.9.0 to 6.9.4, 7.0.0 to 7.0.1 and 7.1 beta 1 as the full chain; 6.8.6, 6.9.5, 7.0.2, 7.1 beta 2 and later as fixed; anything before 6.8.0 as not affected.
- **The source, because a package can backport.** A distribution can carry both fixes under an older version number. The SQL injection fix replaces the `is_array` test and `implode()` in `wp-includes/class-wp-query.php` with `wp_parse_id_list()`; the batch fix adds a guard against starting a new top-level REST cycle while one is already dispatching, in `wp-includes/rest-api/class-wp-rest-server.php`. The script judges **each flaw from its own signature**: both present is reported as a backport and not exposed; only one present is reported as partially patched and exposed, naming the flaw that remains.
- **A fixed version whose files still hold the vulnerable code** is reported as a mismatch (a partial or failed update).
- **The block on the batch route.** If an install is exposed, the script looks in the usual nginx, Apache and `.htaccess` locations for a refusing rule for **each of the two URL forms** and says which it found. Both forms must be covered. The block closes the chain's entry point; it does not fix the SQL injection, so update anyway.

## If you cannot update at once

Refuse both URL forms of the batch route at the web server.

nginx:

```nginx
location ~* "^/wp-json/batch" { return 403; }
if ($args ~* "rest_route=(%2F|/)batch") { return 403; }
```

Apache:

```apache
RewriteEngine On
RewriteRule ^wp-json/batch - [F,L]
RewriteCond %{QUERY_STRING} rest_route=(%2F|/)batch [NC]
RewriteRule ^ - [F,L]
```

If you cannot install a web server rule, a WordPress plugin can block the route from within WordPress. Drop this file on the server at `wp-content/plugins/disable-batch-api-for-unauth.php` and activate it from the Plugins screen:

```php
<?php
/**
 * Plugin Name: Disable Unauthenticated REST Batch API
 * Description: Requires an authenticated WordPress user for REST batch requests.
 * Version: 1.0.0
 * Requires at least: 5.6
 * License: GPL-2.0-or-later
 */

defined( 'ABSPATH' ) || exit;

function wporg_require_authentication_for_rest_batch( $result, $server, $request ) {
    if ( '/batch/v1' !== strtolower( untrailingslashit( $request->get_route() ) ) || is_user_logged_in() ) {
        return $result;
    }
    return new WP_Error(
        'rest_batch_authentication_required',
        'Authentication is required to use the batch API.',
        array( 'status' => 401 )
    );
}
add_filter( 'rest_pre_dispatch', 'wporg_require_authentication_for_rest_batch', -1000, 3 );
```

This approach causes fewer compatibility issues than a network-level block, because authenticated editors keep full access to the batch endpoint. Source: Searchlight Cyber.

The block editor uses the batch route for some saves, so a network-level block may affect editing until you update. These are interim measures; they do not fix the underlying flaws.

## If an affected site was reachable after 17 July 2026

Run `hunt`. Then treat any strong lead as a possible compromise: update core; in the database look for administrator accounts you did not create (`wp user list --role=administrator`) and for unexpected `customize_changeset` posts; review `wp-content/plugins` and `mu-plugins`; and rotate the database password, the salts in `wp-config.php` and every administrator password. The hunt cannot see request bodies, which is where the exploit's payload travels, so a quiet log does not rule out an attack.

## Sources

- [WordPress 7.0.2 release announcement](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [CVE-2026-63030 at CVE.org](https://www.cve.org/CVERecord?id=CVE-2026-63030) and [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q)
- [CVE-2026-60137 at CVE.org](https://www.cve.org/CVERecord?id=CVE-2026-60137) and [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf)
- [Searchlight Cyber: wp2shell pre-authentication RCE in WordPress core](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core)
- [Rapid7 ETR: CVE-2026-63030 wp2shell](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/)

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
