# Release packaging

Releases are published as three files, all named `psf-security-patches` and versioned by release date, `YY.MM.DD-X.Y.Z`, for example `26.10.30-1.0.0`:

| File | Name | Version fields |
|---|---|---|
| Source tarball | `psf-security-patches-26.10.30-1.0.0.tar.gz` | whole version in the name |
| Debian package | `psf-security-patches_26.10.30-1.0.0_all.deb` | upstream `26.10.30`, revision `1.0.0` |
| RPM package | `psf-security-patches-26.10.30-1.0.0.noarch.rpm` | Version `26.10.30`, Release `1.0.0` |

Releases before 26.10.30 were named `psf-security-packages`. The `.deb` declares `Replaces` and `Conflicts`, and the `.rpm` declares `Obsoletes`, for that name, so installing the new package takes the old one out.

The date is the release date in UTC. The second part is the revision: it is `1.0.0` for a first release of that date and goes up if the same date needs a rebuild.

## What the packages install

- The whole tree, scripts and documentation, in `/opt/psf-security-patches`.
- The `php2shell-watch` systemd unit in `/usr/lib/systemd/system`, pointed at the `/opt` path. It is not enabled.
- Manual pages in `/usr/share/man`: `psf-security-patches(7)` as the overview and one `psf-NAME(8)` page for each script. The info manual `psf-security-patches` goes in `/usr/share/info`. They are built from the scripts' `--help` text by `packaging/gen-docs.py`, and the generated files are kept in `man/`. Run the generator after you change a script's header, then commit the result.
- The documentation site, built from the READMEs and `packaging/site/home.md` (home page, tools grouped by kind of software, CVE index, how the tools work, install guide, one page per tool and per manual page), as HTML in `/usr/share/doc/psf-security-patches/html` (`psf-security-patches-<version>` on RPM systems; `index.html` is the front page). `packaging/gen-site.py` builds it into `site/` and `packaging/check-site.py` checks every link, anchor and resource. It needs Python 3, `markdown-it-py` and `linkify-it-py` (`python3 -m pip install markdown-it-py linkify-it-py`). The renderer follows CommonMark, the same rules GitHub and Codeberg use, so the pages match how the READMEs look there. If your host serves `404.html` for a missing page, build with `--base-path` set to the folder the site is served from (`/` at the root, or for example `/security-patches/`), so the error page finds its stylesheet and links from any depth. For privacysafe.app, build with `python3 packaging/gen-site.py --theme privacysafe-app --docs-root /path/to/privacysafe-app-site/docs`. It writes `docs/security-patches/` plus `docs/css/docs.css` and `docs/js/docs.js`, uses the site's header, footer, Content Security Policy and `privacysafe.click` metrics script, and adds an Atom feed. Check the whole docs tree with `python3 packaging/check-site.py --webroot /path/to/privacysafe-app-site`. The hub pages (apps, Social, VPN, protocols) come from the hub builder in the site repository. Run both after you change a README, the changelog or a script header, then commit `site/`.
- License material: `LICENSE` and `NOTICE`, plus a Debian `copyright` file (DEP-5, CC0-1.0) or an RPM `License: CC0-1.0` tag.

There are no maintainer scripts, so nothing runs at install or removal time. The only dependencies are bash 4.0 or newer and coreutils.

## Keeping the READMEs and the site consistent

- Every README ends with the same footer: the important notice, how to support PrivacySafe Foundation, how to contribute, more from PrivacySafe, and the license. `python3 packaging/readme-footer.py --write` puts it in every README (only the links to the repository root change, with the folder depth), and `--check` lists any README that differs. Run `--write` after you add a README.
- The READMEs use emoji in their headings. The site shows a drawn icon in their place: solid, one color, kept in `packaging/psf_icons.py`. A build stops on an emoji that has no icon, and `python3 packaging/psf_icons.py sheet out.html` writes a page that shows every icon. Keep `packaging/psf_icons.py` and `packaging/psdocs_layout.py` identical to the copies in the privacysafe.app site (`docs/_build/`).
- The site's home page takes its "Start here" and "Newest" sections from `packaging/site/home.md`, not from the README. Add a row to "Newest" with each release.
- `packaging/check-site.py` also fails a page that still has an emoji, a tool page that lacks a part the others have, and a README footer that leaked onto a tool page.

## Building

```bash
packaging/build-release.sh --date 26.10.30 --rev 1.0.0
```

Output goes to `dist/`, with a `SHA256SUMS-<version>.txt` file. The build needs `tar`, `gzip`, `dpkg-deb` for the `.deb` and `rpmbuild` for the `.rpm`. Output is reproducible: the same tree, date and revision give byte-identical files.

## Verifying and signing

```bash
sha256sum -c SHA256SUMS-26.10.30-1.0.0.txt
gpg --armor --detach-sign psf-security-patches-26.10.30-1.0.0.tar.gz   # maintainers
```

Maintainers should sign each file and the checksums file, and publish the `.asc` files with the release.

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
