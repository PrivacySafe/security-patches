# Django REST framework: CVE-2026-114138 and CVE-2026-114137

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="drf-check"></a>

## Django REST framework check

**Script:** [`django/drf-check.sh`](drf-check.sh)

Django REST framework (DRF) is the standard toolkit for building web APIs on Django. Two flaws were published on 21 and 22 October 2026, and both are fixed in DRF 3.18.2. The first lets any client burn CPU with an oversized `Accept` header, on any endpoint. The second only matters if you use `rest_framework.authtoken`: deleting a token through `TokenProxy.delete()` matches no row and raises no error, so a token you believe you revoked may still exist.

| | CVE-2026-114138 | CVE-2026-114137 |
|---|---|---|
| What | `DefaultContentNegotiation` accepts an unbounded number and size of `Accept` header tokens and parses each one repeatedly for every renderer. A remote client can send many distinct media types with large quoted parameters and burn about 19 seconds of CPU per request | From 3.12.0, `TokenProxy.delete()` in `rest_framework.authtoken` uses the wrong primary key, so the delete matches no row, raises nothing and reports success. **The token keeps working.** DRF tokens do not expire, so access you believed revoked stays open indefinitely |
| Severity | High 7.5 (CVSS 3.1) | High 7.4 (CVSS 3.1) |
| Affected | Every release before 3.18.2. Sites on the 0.x and 2.x lines move to 3.18.2 or later | 3.12.0 up to 3.18.2, and only sites with `rest_framework.authtoken` installed |
| Needs | Nothing: every API view does content negotiation, so any reachable endpoint is a target | Code, an integration or a script that revokes tokens by calling `.delete()` on a `TokenProxy` instance. DRF's own `TokenAdmin.delete_model` is not affected, and neither is deleting through `Token.objects` |
| Fixed | 3.18.2 | 3.18.2 |

**The Accept header cost also involves Django.** The Debian description says the cost comes from Django's header parameter parser together with DRF's repeated parsing. Django fixed its own quadratic-time parser separately in **5.2.18, 6.0.9 and 6.1.2**. Updating DRF alone may not remove all of the cost, so the script also reports the neighbouring Django version.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/django/drf-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/django/drf-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less drf-check.sh
   chmod +x drf-check.sh
   ```

3. Check this host. By default it searches `/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root`. Pass directories to narrow it, such as one virtual environment.

   ```bash
   ./drf-check.sh check
   ./drf-check.sh check /srv/myapi/.venv
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds installed copies (`djangorestframework-*.dist-info` and `.egg-info`) and declared pins (`requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`). For pins it looks at the project's Python files for `rest_framework.authtoken` and `TokenProxy`; for installed copies it reads the neighbouring `Django` version |
| `mitigate [--server-name NAME] [--dir DIR] [--dry-run] [--reload] [--force]` | **Changes the host (root).** The protective measure below, applied to nginx: answers 406 to an `Accept` header of 1024 characters or more. Acts only when an affected copy is found. Adds a `map` block right after `http {` and an include at the top of every server block that proxies (`proxy_pass`, `uwsgi_pass` or `scgi_pass`; use `--server-name` to limit it to your API), checked with `nginx -t`; if nginx rejects the result, everything is undone at once. Reloads nothing unless you add `--reload`. nginx only |
| `rollback [--dry-run] [--reload]` | Removes what `mitigate` added and restores the files it edited |
| `version` | Prints the script version |

Exit codes: `0` nothing affected, `1` an affected copy or pin was found, `2` bad arguments.

## How to read the result

- Affected version: upgrade (`pip install --upgrade 'djangorestframework>=3.18.2'`) and check that your Django version is supported by 3.18.x.
- The second warning (CVE-2026-114137) appears for 3.12.0 and later. It only matters if `rest_framework.authtoken` is installed. For a project the script checks its source. For an installed copy it cannot map the environment to a project, so check the `INSTALLED_APPS` of the apps that use it.
- `TokenProxy` found in the project: revocations made through it did nothing on an affected version. Treat those tokens as still live.
- Neighbouring Django below 5.2.18, 6.0.9 or 6.1.2: update it as well. An unsupported series (3.2, 4.2, 5.0, 5.1) was not evaluated by Django, so assume it is affected.
- Look-alike packages such as `djangorestframework-simplejwt` and `djangorestframework-stubs` are not DRF and are ignored, including when they are listed before DRF in a lock file.
- Distribution packages: the script reads the package changelog for a mention of either CVE.

## After upgrading: clear tokens that should have been revoked

On an affected version, anything revoked through `TokenProxy` is still valid after the upgrade. The upgrade fixes the bug, it does not delete tokens. Tokens of deactivated users can be cleared with `Token`, not `TokenProxy`:

```bash
python manage.py shell -c "from rest_framework.authtoken.models import Token; print(Token.objects.filter(user__is_active=False).delete())"
```

For anyone else you meant to revoke, use `Token.objects.filter(user=...).delete()`, and review who still holds a token. This was verified on a real DRF install: on 3.17.2 `TokenProxy.delete()` left the token in place, the snippet deleted only the deactivated user's token and left the active user's untouched, and on 3.18.2 `TokenProxy.delete()` works.

## Protective measure for the Accept header flaw

`./drf-check.sh mitigate --server-name api.example.com` applies this; `rollback` removes it. Verified on nginx 1.24 proxying to a backend: `Accept` headers of 1023 characters and shorter reach the backend (200), headers of 1024 and 3200 characters get 406, and after `rollback` the long ones pass again.

PrivacySafe recommendation. Real `Accept` headers are far shorter than 1 KB, so rejecting longer ones at the reverse proxy bounds the cost of this attack. In nginx:

```nginx
# in the http { } block
map $http_accept $psf_bad_accept { default 0; "~^.{1024,}$" 1; }

# in the server { } block
if ($psf_bad_accept) { return 406; }
```

On nginx, browser-style and `application/json` headers, an empty header and a 1023-character header pass (200). A 1024-character header and an attack-shaped 3.2 KB header with many media types and long quoted parameters are refused (406). It stops the oversized header from reaching DRF. It does not replace the upgrade.

## Sources

- [DRF 3.18.2 release](https://github.com/encode/django-rest-framework/releases/tag/3.18.2)
- [GitHub advisory GHSA-xw6w-gcfp-cf8m (CVE-2026-114137)](https://github.com/encode/django-rest-framework/security/advisories/GHSA-xw6w-gcfp-cf8m)
- [GitHub advisory GHSA-33wh-fxxf-88vv (CVE-2026-114138)](https://github.com/encode/django-rest-framework/security/advisories/GHSA-33wh-fxxf-88vv)

## Before you run it

- The fix. Update to DRF 3.18.2. Sites on the 0.x and 2.x lines move to 3.18.2 or later.
- Keep Django current as well. The CPU cost of CVE-2026-114138 also involves Django's own header parameter parser, which Django fixed separately in 5.2.18, 6.0.9 and 6.1.2.
- CVE-2026-114137 only applies with `rest_framework.authtoken`. Code that revokes access through a `TokenProxy` instance leaves the token working (DRF tokens do not expire). Revocation through `Token.objects` works on every version, and DRF's own admin delete is not affected.
- There is no hunt. No indicators of exploitation have been published for these flaws.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. In each running container, a read-only probe finds the installed copies by their `dist-info` and `egg-info` folders, plus the lock and requirements files that mention the package. It copies only those names and files into a private temporary folder, and the normal check judges that folder. Python files that mention `rest_framework.authtoken` or `TokenProxy` are copied from the project beside a matching lock file, so the CVE-2026-114137 conditions are judged inside the container too. A staged symlink is never kept and the copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
