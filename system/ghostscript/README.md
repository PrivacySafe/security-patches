# Ghostscript security releases

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="upload2shell"></a>

## Upload2Shell: CVE-2026-125396, -dSAFER sandbox escape via a crafted font

**Script:** [`system/ghostscript/ghostscript-upload2shell-check.sh`](ghostscript-upload2shell-check.sh)

CVE-2026-125396 ("Upload2Shell"), found by the pwn.ai research team, fixed in Ghostscript 10.08.0: a use-after-free in the Type 1 font loader. The `.putgstringcopy` procedure in `gs_fonts.ps` calls the privileged `.forceput` operator without checking operand types; a crafted font embedded in a PostScript, EPS or PDF document triggers a type error, a custom error handler recovers `.forceput`, and a use-after-free across a save/restore boundary lets the attacker execute arbitrary code as the user running Ghostscript, even with `-dSAFER` set. There is no Ghostscript setting that disables Type 1 font loading, so there is no in-Ghostscript configuration workaround; the only fixes are upgrading Ghostscript itself or keeping files that might carry a crafted font away from it entirely.

Ghostscript, and the libraries that silently invoke it, identify the file format by content, not by name or declared MIME type, so a file uploaded as `.png` or `.jpg` that is actually PostScript, EPS, or a PDF carrying an embedded Type 1 font still reaches this code path. pwn.ai's own write-up documents working chains through, among others: ImageMagick/Imagick (its default delegate for PS/EPS/PDF input), Pillow (which shells out to Ghostscript once pixels are requested from an EPS file, a separate issue from Pillow's own CVE-2026-112900), WordPress uploads by Authors and above or a public upload form (WordPress's own CVE-2026-65640 covers that specific upload route), Roundcube attachment thumbnails (fixed separately in Roundcube's own CVE-2026-114727, which this collection's [`roundcube-oct2026-check.sh`](../../web-apps/roundcube/README.md) already checks for as part of its own October release), DokuWiki's image resize pipeline, and CUPS print queues shared without a login. On a desktop, simply opening a malicious file in a Ghostscript-based viewer is enough.

`check` and `hunt` change nothing and need no privilege. `mitigate` and `rollback` change the host and require root (or whatever account owns ImageMagick's `policy.xml`), stopping with a clear message otherwise. `check` finds every Ghostscript this host's package manager knows about (via `dpkg`/`rpm`, cross-checked against each distribution's own fixed-package list the same way other scripts in this collection handle a backport that does not change the upstream version string) plus any `gs` binary on `PATH`, and reports each one against 10.08.0. It also audits ImageMagick's `policy.xml`, when present, for whether the coders `mitigate` would block are already blocked.

One real trap `check` watches for: Ghostscript's own 10.08.0 release candidate, tagged and built before the fix commit, reports its version as plain `10.08.0` in `gs --version`, identical to the real fixed release; there is nothing in that output to tell the two apart. Where `check` finds a `gs` binary reporting exactly `10.08.0` with no owning distribution package to cross-check against, it says so explicitly rather than reporting it clean, and asks you to confirm the build's actual date or provenance.

`mitigate` adds the long-standing, community-documented ImageMagick `policy.xml` lines that block the `PS`, `PS2`, `PS3`, `EPS` and `XPS` coders, the formats always routed through Ghostscript with no alternative renderer in ImageMagick. `PDF` is left alone by default, since many ImageMagick users genuinely need PDF read or write and not every PDF workflow touches the Type 1 loader; `mitigate --include-pdf` also blocks the `PDF` coder, which is more thorough but breaks any PDF rasterization or thumbnailing ImageMagick does. This covers ImageMagick only: it has no effect on Pillow, WordPress, Roundcube, DokuWiki, or a print queue that calls Ghostscript directly, each of which needs its own fix (see `rules`). Blocking these coders has a real cost, not just a benefit, since it stops ImageMagick processing those formats at all even where that's wanted, so by default `mitigate` only acts when `check` would report a Ghostscript here as exposed or undetermined (no install found counts as undetermined, not clear, since that could mean a reachable copy this host's package manager doesn't know about); when every Ghostscript found is already confirmed fixed, it changes nothing and says so, unless `--force` is given to add the hardening anyway. `mitigate --dry-run` prints a unified diff of exactly what would change and writes nothing, so, unlike a real `mitigate`, it needs no privilege, and it skips the exposure gate so you can preview the change either way. Both commands back up the file first and verify the result is still well-formed XML (via `xmllint` or Python's `xml.dom.minidom`, whichever is available), rolling back automatically if not. `rollback --dry-run` prints which file would be restored from which backup and writes nothing, so it needs no privilege.

Verified on Ubuntu's Ghostscript 10.02.1~dfsg1-0ubuntu7.10, which `check` recognizes as a fixed build by its exact package version. Against that host's ImageMagick `policy.xml`, `mitigate` adds the five coder lines (six with `--include-pdf`), keeps the file well-formed XML, makes no further change when run again, and `rollback` restores it byte for byte. On a fixed Ghostscript a plain `mitigate` refuses unless `--force` is given, because blocking these coders has a cost; `--dry-run` previews the change either way and needs no privilege.

### Upload2Shell quick start

```sh
curl -O https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/system/ghostscript/ghostscript-upload2shell-check.sh
chmod +x ghostscript-upload2shell-check.sh
./ghostscript-upload2shell-check.sh check
```

If Ghostscript cannot be updated today, preview and then apply the ImageMagick interim measure:

```sh
sudo ./ghostscript-upload2shell-check.sh mitigate --dry-run
sudo ./ghostscript-upload2shell-check.sh mitigate
```

After the update, undo it with `sudo ./ghostscript-upload2shell-check.sh rollback`.

### Upload2Shell commands

| Command | Root | What it does |
|---|---|---|
| `check` (default) | no | Every Ghostscript the package manager knows and any `gs` on `PATH`, judged against the fixed release and the distributions' fixed packages, plus whether ImageMagick blocks the Ghostscript coders. Exit `0` clear, `1` exposed, `2` undetermined (for example a bare `10.08.0` that could be the release candidate) |
| `hunt` | no | Looks for Ghostscript crash signatures in the logs it can read. Exit `1` a match, `2` no match or nothing could be read: a successful exploit need not crash, so a clean log is weak evidence either way |
| `mitigate [--include-pdf] [--dry-run] [--force]` | yes (unless `--dry-run`) | Adds `policy.xml` lines that block the `PS`, `PS2`, `PS3`, `EPS` and `XPS` coders (and `PDF` with `--include-pdf`). Backs up first and checks the file is well-formed. Interim hardening, not a fix |
| `rollback [--dry-run]` | yes (unless `--dry-run`) | Restores the `policy.xml` that `mitigate` changed |
| `rules` | no | Prints what `mitigate` cannot do: the update, and the Pillow, WordPress, Roundcube and CUPS changes |
| `version` | no | Prints the script version |

What this script cannot do: patch Ghostscript itself, or make the Pillow, WordPress, Roundcube or CUPS changes `rules` describes; those are code or configuration changes in applications this script does not control.
<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:103517](https://access.redhat.com/errata/RHSA-2026:103517) | 2026-11-25 | Important | `ghostscript-10.02.1-17.el10_3.1` (RHEL 10.3) | CVE-2026-125396 |
| [RHSA-2026:103523](https://access.redhat.com/errata/RHSA-2026:103523) | 2026-11-25 | Important | `ghostscript-9.54.0-20.el9_9.1` (RHEL 9.9) | CVE-2026-125396 |
| [RHSA-2026:103524](https://access.redhat.com/errata/RHSA-2026:103524) | 2026-11-25 | Important | `ghostscript-9.27-21.el8_10` (RHEL 8.10) | CVE-2026-125396 |

[CVE-2026-112900](https://access.redhat.com/security/cve/CVE-2026-112900): 17 advisories, listed in the [Red Hat advisories section of the pillow README](../pillow/README.md#red-hat-advisories).

<!-- rhsa:end -->

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
