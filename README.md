<p align="center">
  <a href="https://privacysafe.app"><img src="privacysafe_horizontal_logo_lock_reg_padded.svg" width="600" /></a>
</p>
<h1 align="center">Security Patches</h1>

<h3 align="center">
Security mitigations and auditing tools shared for the public good.
</h3>

<p align="center">
  <a href="https://privacysafe.foundation"><strong>❤️ Support PrivacySafe Foundation</strong></a>
</p>

This repository contains security mitigations, system-hardening scripts, and auditing tools developed for PrivacySafe and Ivy Cyber infrastructure. We publish these tools so that others can study, adapt, and use them to protect their own systems, including when upstream security fixes are not yet available.

**16 scripts addressing 36 CVEs across 15 software projects and 6 programming languages, plus 4 other global security incidents.**

> 💚 If this work has been useful, please consider [supporting PrivacySafe Foundation](https://privacysafe.foundation), a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, and public-interest privacy and security research.

---

## 📦 Available tools

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [PHP2Shell](php/README.md#php2shell-interim-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 | Interim mitigation |
| [PHP2Shell live watch](php/README.md#watching-live) | PHP-FPM, Apache and nginx logs on any GNU/Linux; optional systemd unit | CVE-2026-109618, CVE-2026-109619 | Read-only live monitor |
| [PHP2Shell on cPanel](php/README.md#php2shell-on-cpanel-easyapache-4) | cPanel/WHM servers running EasyApache 4 PHP (ea-php74 to ea-php85), any handler | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 | Interim mitigation, check and audit |
| [PHP session audit](php/README.md#php-session-audit-cve-2026-115560) | Any PHP host | CVE-2026-115560 | Read-only audit |
| [PHP2Shell edge guards](php/edge/README.md) | Apache httpd and nginx in front of PHP, with request body and header limits | CVE-2026-109618, CVE-2026-109619 | Compensating controls (log-only first) |
| [PHP2Shell detection rules](php/detect/README.md) | auditd, Tetragon and nftables on GNU/Linux | CVE-2026-109618, CVE-2026-109619 | Detection content |
| [Node.js October 2026](node/README.md#nodejs-october-2026-interim-mitigation) | Node.js on GNU/Linux; systemd for the guard | CVE-2026-111497 (Brotli, ecosystem-wide) and 9 Node CVEs | Interim mitigation (Node only) |
| [Brotli checker](brotli/README.md#brotli-checker-quick-start) | libbrotli, and Node/Bun/Python/Envoy/Istio/cdxgen on GNU/Linux | CVE-2026-111497 | Read-only check and audit |
| [Ruby and GitLab Regexp](ruby/README.md#ruby-and-gitlab-regexp-check) | Ruby runtimes, Ruby apps and GitLab on GNU/Linux | CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264 | Read-only check and audit |
| [libheif HEIF/AVIF Decoder](heif/README.md#libheif-heifavif-decoder-check) | libheif, ImageMagick and Discourse on GNU/Linux | [writeup](https://www.hacktron.ai/blog/hacking-openai); DSA-6417-1 | Check, audit and ImageMagick coder mitigation |
| [eMudhra CA Compromise](pki/README.md#emudhra-intermediate-ca-compromise-interim-mitigation) | System CA store on Debian/Ubuntu/Trisquel and derivatives | [disclosure](https://emudhra.we-have-a-problem.com/); Go: CVE-2026-111943 | Interim mitigation |
| [curl HTTP/2 upload](curl/README.md#curl-http2-upload-use-after-free-check) | curl and libcurl on GNU/Linux | CVE-2026-92392 | Read-only check and audit |
| [Nextcloud Collabora Built-in CODE](nextcloud/README.md#nextcloud-collabora-built-in-code-command-injection) | Nextcloud with the richdocumentscode app on GNU/Linux | CVE-2026-110447 | Interim mitigation, check and hunt |
| [nginx October 2026](nginx/README.md#nginx-october-2026-check) | nginx and njs on GNU/Linux | CVE-2026-15176, CVE-2026-93479, CVE-2026-97205, CVE-2026-95101, CVE-2026-97629; njs: CVE-2026-101019, CVE-2026-101025 | Read-only check, config audit and hunt |
| [LiteLLM supply-chain compromise](litellm/README.md#litellm-11070-supply-chain-compromise) | litellm in Python environments and containers on GNU/Linux | [incident](https://github.com/BerriAI/litellm/issues/47826) (litellm 1.107.0, no CVE) | Detect, hunt and contain |
| [Plex Media Server Plex2Shell](plex/README.md#plex-media-server-plex2shell-rce-chain) | Plex Media Server on GNU/Linux | CVE-2026-96651, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656 | Read-only check and hunt |
| [GhostAction developer-machine stealer](ghostaction/README.md#ghostaction-developer-machine-stealer) | Git repositories and developer machines on GNU/Linux | [incident](https://opensourcemalware.com/blog/ghostaction-attack-escalates) (campaign, no CVE) | Scan, hunt and contain |

## 📥 Install from a package

Each release ships three files, all named `psf-security-packages` and versioned by release date, `YY.MM.DD-X.Y.Z` (for example `26.10.25-1.0.0`). Download them from the releases page on [Codeberg](https://codeberg.org/PrivacySafe/security-patches/releases) or [GitHub](https://github.com/PrivacySafe/security-patches/releases).

| File | For |
|---|---|
| `psf-security-packages_26.10.25-1.0.0_all.deb` | Debian, Ubuntu, Trisquel and derivatives |
| `psf-security-packages-26.10.25-1.0.0.noarch.rpm` | RHEL, Alma, Rocky, Fedora, CloudLinux and derivatives |
| `psf-security-packages-26.10.25-1.0.0.tar.gz` | Any GNU/Linux: the source tree, plus the scripts to rebuild the packages |

Check the files against the release's `SHA256SUMS-<version>.txt` before installing, then:

```bash
sha256sum -c SHA256SUMS-26.10.25-1.0.0.txt
sudo apt install ./psf-security-packages_26.10.25-1.0.0_all.deb       # Debian family
sudo dnf install ./psf-security-packages-26.10.25-1.0.0.noarch.rpm    # RPM family
/opt/psf-security-patches/php/php2shell-mitigate.sh check             # read only
```

### Where things go

- **`/opt/psf-security-patches/`** holds the whole tree: each tool in its own folder (`php/`, `nginx/`, `curl/` and so on) with its README, plus the governance documents and a `VERSION` file. Run the scripts from there.
- **`/usr/lib/systemd/system/php2shell-watch.service`** is the live watcher's unit, pointed at the `/opt` path. It is installed but not enabled; see [Watching live](php/README.md#watching-live).
- **License files:** `LICENSE` and `NOTICE` come with the package (`/usr/share/doc/psf-security-packages/` on Debian, `/usr/share/licenses/` on RPM systems), and the `.deb` carries a `copyright` file. Everything is CC0 1.0 Universal.

Installing runs nothing: there are no install or removal scripts. The only dependencies are bash 4.0 or newer and coreutils.

### Upgrading and removing

Install a newer release the same way and it replaces the old one in place. To remove the tools:

```bash
sudo apt remove psf-security-packages     # Debian family
sudo dnf remove psf-security-packages     # RPM family
```

Removing the package deletes only the files it installed. It does not undo what a tool did to your system when you ran it, such as an ini drop-in, an AppArmor profile or a distrusted certificate. Use each tool's own `cleanup`, `remove` or `restore` command, described in its README, before you remove the package.

Each tool still targets the systems named in its own README: for example the PHP2Shell AppArmor mitigation is for Debian-family systems, and the cPanel variant is for EasyApache 4. See [`packaging/`](packaging/README.md) for how releases are built and verified.

## 🗓️ Updates

See the [changelog](CHANGELOG.md) for new tools and changes, newest first.

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
