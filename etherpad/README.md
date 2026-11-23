# Etherpad security releases

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="static-traversal"></a>

## Static path traversal: CVE-2026-114516, unauthenticated arbitrary file read

**Script:** [`etherpad/etherpad-static-traversal-check.sh`](etherpad-static-traversal-check.sh)

GHSA-mc8w-wjhw-45x5 / CVE-2026-114516, published 27 October 2026: critical (CVSS 3.1 9.8), unauthenticated path traversal in Etherpad's `/static/*` handler, reachable before the session and auth-check middleware even load. Affects etherpad-lite 1.8.14 through 3.3.2; fixed in 3.3.3.

Etherpad's path sanitizer rejects a literal `..` path component, and folds a backslash to a forward slash only on Windows, by design, since a backslash is an ordinary filename byte on GNU/Linux and folding it early would make a real backslash in a filename unreachable. The code that serves a plugin's static assets runs that sanitizer first and then, for the plugin-static branch only, folds every backslash to a forward slash again unconditionally on every platform, on the strength of a comment asserting the opposite of that invariant. On GNU/Linux this turns a `..\` sequence the sanitizer passed through as ordinary bytes into a live `../` sequence after the one check meant to catch it, and because the resulting path is joined as absolute first, the final resolve step discards the intended root entirely. A URL-encoded backslash (`%5C`) is the only separator that reaches this: an encoded forward slash is decoded and re-split by Etherpad's own router before the sanitizer runs and is rejected there, and the always-registered core plugin name (`ep_etherpad-lite`) gives every installation a working prefix regardless of which third-party plugins are actually present.

The route is registered on Etherpad's `expressPreSession` hook, which the app runs before it installs session and auth-check middleware, so no account, session or `requireAuthentication`/`requireAuthorization`/`users` setting gates it. A plain reverse proxy does not stop this on its own: `%5C` is ordinary request-path text and proxies forward unchanged.

What a successful read reaches: `settings.json`/`credentials.json` (admin password, session secret, database credentials, SSO client secrets), `/proc/self/environ` (any secret passed as an environment variable), TLS private keys, the pad database, and ordinary OS files. From there, the disclosed admin password mints an admin session against `POST /admin-auth/`, and an admin session can install an attacker-controlled plugin through the `/pluginfw/installer` Socket.IO namespace, which Etherpad `require()`s in-process: full remote code execution as the Etherpad process user.

`check` and `hunt` change nothing and need no privilege. `mitigate` and `rollback` change the host and require root, stopping with a clear message (and a `sudo` suggestion) otherwise. `check` finds installed etherpad-lite copies (by `package.json` under the usual install roots, or a running `node ... etherpad` process's working directory) and reports each one's version against the fixed release. `hunt` greps readable web server and Etherpad logs for the one signature this exploit needs: the plugin-static route together with an encoded backslash; finding none is not proof nothing happened, since a request reading only one harmless file still matches and a successful read need not be logged anywhere this script can reach.

`mitigate` covers nginx only. It adds two drop-ins: an `http`-level one that computes a `map` flag from `$request_uri` (an `if` is not valid at `http` level in nginx, only `map` is), and a `server`-level one that checks that flag and returns 400. It walks every config file `nginx -T` reports and injects the `server`-level rule into every `http`-context `server {}` block it finds, explicitly skipping a `server {}` nested inside a top-level `mail {}` or `stream {}` block, since nginx reuses that same keyword there for something that does not support `if`/`return` the way an HTTP server block does. It backs up every file it touches and verifies the result with `nginx -t`, rolling back automatically if the test fails. Neither `mitigate` nor `rollback` reloads nginx unless you pass `--reload` (graceful, via `systemctl reload` where that unit exists, otherwise `nginx -s reload`); without it, reload nginx yourself once you're satisfied with the result. For Apache, add the equivalent rule by hand (see `rules`). This blocks the one separator the exploit depends on; it is not a substitute for upgrading to 3.3.3.

Verified on nginx 1.24.0 with both an HTTP `server {}` block and a `mail {}` block: `mitigate` adds the rule to the HTTP block only, `nginx -t` passes, and `rollback` restores both files. With the rule live, the advisory's `%5C` path and a lowercase `%5c` return 400, while an ordinary request, an encoded `%2F` and a query string are unaffected.

### Static path traversal quick start

```sh
curl -O https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/etherpad/etherpad-static-traversal-check.sh
chmod +x etherpad-static-traversal-check.sh
./etherpad-static-traversal-check.sh check
```

If you can upgrade to 3.3.3, do that and skip the rest. If not, and you run nginx in front of Etherpad:

```sh
sudo ./etherpad-static-traversal-check.sh mitigate --dry-run
sudo ./etherpad-static-traversal-check.sh mitigate --reload
```

Once you've upgraded:

```sh
sudo ./etherpad-static-traversal-check.sh rollback --reload
```

### Static path traversal commands

| Command | Changes the system? | What it does |
|---|---|---|
| `check` | no | Finds installed etherpad-lite copies and reports each against the fixed version; exit 0 clear, 1 exposed, 2 not found/undetermined |
| `hunt` | no | Greps web server and Etherpad logs for the plugin-static + encoded-backslash request signature |
| `mitigate [--dry-run] [--reload]` | yes (unless `--dry-run`) | nginx only: blocks requests whose URI contains an encoded backslash. Backs up first, tests the config, rolls back on failure. `--reload` gracefully reloads nginx afterward |
| `rollback [--dry-run] [--reload]` | yes (unless `--dry-run`) | Restores every file `mitigate` backed up and removes the added snippets; `--dry-run` lists what it would restore; `--reload` gracefully reloads nginx afterward |
| `rules` | no | Prints the explanation above, including the Apache rule to add by hand |
| `version` | no | Prints the script's version |

Environment overrides: `ETHERPAD_FIXED` (default `3.3.3`) if you need to compare against a different fixed version; `ETHERPAD_ROOTS` (default `/opt/etherpad-lite /usr/share/etherpad-lite /usr/local/etherpad-lite /srv/etherpad-lite /var/www/etherpad-lite /home`) to change where `check` looks for an install; `NGINX_SNIPPET_DIR` (default `/etc/nginx/snippets`) and `PSF_BACKUP_DIR` (default `/var/backups/psf-security-patches/etherpad-static-traversal`) for `mitigate`.

What this script can't see: a backslash-handling bug reachable through a path other than the plugin-static branch described above (none is known as of this script's writing), Apache or any other reverse proxy in front of Etherpad (the rule for those has to be added by hand, see `rules`), and an install under a path `ETHERPAD_ROOTS` doesn't cover with no readable `package.json`.

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
