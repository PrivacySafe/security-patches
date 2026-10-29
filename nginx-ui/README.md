# nginx-ui restricted-directive bypass (CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="nginx-ui-check"></a>

## nginx-ui restricted-directive bypass check

**Script:** [`nginx-ui/nginx-ui-check.sh`](nginx-ui-check.sh)

nginx-ui is a web interface for managing nginx. Its security control, `ValidateConfigFile`, refuses configuration that contains directives able to run code or raise privileges: `load_module` of the njs or Perl modules, `js_import`, `js_content`, `perl_*`, and `user root`. Four advisories published on 12 October 2026 describe ways around that control for a logged-in user. Where nginx loads the njs, Perl or Lua module, which the official Docker image does, the injected configuration runs code in the nginx worker.

| CVE | CVSS | What |
|---|---|---|
| CVE-2026-84316 | 8.8 | The validator split the configuration on newlines and checked only the first token of each line. nginx separates directives with `;`, so a harmless directive first and a restricted one after a semicolon on the same line passed |
| CVE-2026-84317 and CVE-2026-84318 | 8.8 each | The MCP tool `nginx_config_add` wrote the caller's configuration to disk and reloaded nginx without calling `ValidateConfigFile` at all. The REST paths do call it. Two identifiers describe this one gap, with different affected ranges (84318 from 2.0.0-rc.6) |
| CVE-2026-84319 | 8.3 | The MCP configuration interface let a secondary authenticated user write and apply the restricted directives the regular API refuses, such as loading the njs module and importing JavaScript, which runs njs in the nginx worker |

| | |
|---|---|
| Authentication | A logged-in user (a secondary user for 84319) |
| Affected | nginx-ui below 2.4.1 |
| Fixed | 2.4.1 |
| Exploited | No exploitation reported in the sources used |

## How the script reads an install

The nginx-ui binary has no version flag, and its version endpoint needs a login, so a read-only check cannot ask it. The script uses what it can read:

1. `NGINX_UI_VERSION`, if you set it from the web interface, or the package version if there is one.
2. A string inside the binary. The 2.4.1 validator adds the names `lua_package_cpath` and `lua_package_path` to its restricted list; 2.4.0 does not contain them. A binary without them has the older validator, which is a strong finding. A binary with them is consistent with 2.4.1 or later, but it is a string match, so confirm the version in the web interface.
3. When the two disagree (a version of 2.4.1 or later on a binary without the names, or the reverse) the script says so rather than choosing.

The binary is found through `NGINX_UI_BIN`, the usual install paths, the `ExecStart` of the `nginx-ui` systemd unit, and running processes.

The official container image, `uozi/nginx-ui`, is checked too, by its tag in docker or podman. A tag that names a version (`2.4.0`, `v2.4.1`) is judged; a tag such as `latest` does not name a version and the version inside an image cannot be read from outside, so it is a warning that says so. An image on disk is not necessarily a running container. If no binary or image is found on the host but you have set `NGINX_UI_VERSION` (for an instance elsewhere), that version is judged on its own.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/nginx-ui/nginx-ui-check.sh
less nginx-ui-check.sh
chmod +x nginx-ui-check.sh
./nginx-ui-check.sh check
./nginx-ui-check.sh hunt
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds nginx-ui (binary, container image, or a version you supply), reads the version and the binary signature, and reports. Exit `0` nothing exposed, `1` exposed or unclear |
| `hunt` | Reads nginx configuration for the semicolon-bypass shape and lists restricted directives present, for review. Exit `0` nothing found, `1` a strong lead |
| `version` | Prints the script version |

Env: `NGINX_UI_BIN`, `NGINX_UI_VERSION`, and `NGINX_UI_CONF_DIRS` (space separated nginx configuration directories for `hunt`; default `/etc/nginx /etc/angie /usr/local/etc/nginx /usr/local/nginx/conf`).

## What `hunt` looks for

A restricted directive appearing after a semicolon on a line that already holds another directive, which is the shape of CVE-2026-84316, is a strong lead. Restricted directives in plain form are listed for review only, because legitimate njs and Perl use looks the same. The MCP paths (84317, 84318, 84319) write ordinary-looking directives, so a clean result does not rule them out: compare your configuration against your own records.

## Update

Update nginx-ui to 2.4.1 or later and restart it. Until then the project suggests limiting who has an nginx-ui account, keeping it off untrusted networks, and not giving secondary users write access. That is not vendor guidance.

## If it was exposed

Review nginx configuration written since the exposure for restricted directives you did not add, remove them, reload nginx, rotate nginx-ui credentials and review who has accounts. If nginx loads the njs, Perl or Lua module, treat the worker as possibly compromised.

## Sources

- [nginx-ui 2.4.1 release](https://github.com/0xJacky/nginx-ui/releases/tag/v2.4.1)
- [GHSA-cf23-7qxj-xmhr (CVE-2026-84316)](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-cf23-7qxj-xmhr)
- [GHSA-76pm-mq2q-9gcr (CVE-2026-84317)](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-76pm-mq2q-9gcr)
- [GHSA-9jww-cxg5-rj9m (CVE-2026-84318)](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-9jww-cxg5-rj9m)

## nginx-ui know before you run it

- **This is a check, not a fix.** Update to nginx-ui 2.4.1. All four flaws need a logged-in user, and they matter most where nginx loads the njs, Perl or Lua module, as the official Docker image does.
- **A read-only check cannot ask the program its version.** The binary has no version flag and its version endpoint needs a login. The script judges the container image `uozi/nginx-ui` by its tag when the tag names a version (a tag such as `latest` does not, and is a warning), a version you supply in `NGINX_UI_VERSION`, the package version, and a string inside the binary that the 2.4.1 validator adds.
- **The binary check is a string match.** It looks for names the fixed validator adds; it does not run the program.
- **CVE-2026-84317 and CVE-2026-84318 describe one gap with different affected ranges,** and 84318 starts at 2.0.0-rc.6.
- **It also reads running containers.** With no argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container runs the same two signature tests this check applies to the binary (`lua_package_cpath` and `lua_package_path`) and copies only a small file recording the answer; the binary itself is never copied and nginx-ui is never run. A container is therefore judged by the signature alone (no version is read): a binary without the 2.4.1 validator names is reported as affected. The script runs once per container in isolation and does not repeat the host's discovery.

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
