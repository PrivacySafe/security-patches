# libheif: HEIF/AVIF decoder flaw

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="libheif-heifavif-decoder-check"></a>

## libheif HEIF/AVIF Decoder Check

**Script:** [`heif/libheif-oct2026-check.sh`](libheif-oct2026-check.sh)

A heap buffer overflow in `libheif`, the HEIF and AVIF image decoder, was used to get remote code execution on a Discourse forum and then pivot further into the services behind it. The decode path is reached by uploading a crafted HEIF or AVIF image: an app that processes user images hands the file to ImageMagick (or libvips), which calls `libheif`. Disabling a single "image uploads" setting does not reliably close it, because avatars, emoji, oneboxed remote images and other surfaces feed the same conversion path.

The fix is to update `libheif` (and `libde265`, the HEVC codec it calls) and rebuild anything that bundles them. For a Discourse Docker install this means a container rebuild, not a web-interface update, because the old library stays in the image until it is rebuilt:

```bash
cd /var/discourse
git pull
./launcher rebuild app
```

Fixed-version information varies across upstream releases and distribution packages. The upstream heap-write class was fixed across 1.21.0, 1.22.0 and 1.22.1, with security releases continuing into the 1.23.x line. Debian fixed a batch in [DSA-6417-1](https://lists.debian.org/debian-security-announce/2026/msg00328.html) (`libheif 1.19.8-1+deb13u1`, trixie, 8 August 2026), and other distributions backport under their own version strings, so a package can carry the fixes under an older-looking upstream number. This script accounts for that: a distribution build is judged by `FIXED_BUILDS` and its package changelog first, and only falls back to the upstream version floor when it is not a distribution package.

This is a separate issue from the Ruby Regexp CVEs. For Ruby and GitLab, use [`ruby/ruby-regexp-oct2026-check.sh`](../ruby/README.md#ruby-and-gitlab-regexp-check) instead.

### libheif quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/heif/libheif-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/heif/libheif-oct2026-check.sh
   ```

2. Read it before running it. Always.

   ```bash
   less libheif-oct2026-check.sh
   ```

3. Make it executable.

   ```bash
   chmod +x libheif-oct2026-check.sh
   ```

4. See what's exposed. Root is optional, but without it you won't read every library or exec into other users' containers.

   ```bash
   sudo ./libheif-oct2026-check.sh check
   ```

5. Check whether ImageMagick still lets HEIF through. `policy` reports and prints the lines to block it; `harden` writes them for you (reversible with `unharden`).

   ```bash
   sudo ./libheif-oct2026-check.sh policy
   sudo ./libheif-oct2026-check.sh harden
   ```

6. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./libheif-oct2026-check.sh hunt
   ```

To confirm GitHub and Codeberg serve the same file, compare checksums:

```bash
sha256sum libheif-oct2026-check.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/heif/libheif-oct2026-check.sh | sha256sum
```

### libheif commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every `libheif` and `libde265` on the host, the ImageMagick and libvips that reach them, every Discourse install, and `libheif` inside running containers, with whether each `libheif` carries the fixes. For a Discourse container it says a rebuild is needed, not a restart. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable `libheif` is reachable, `2` if something couldn't be judged |
| `policy` | Read-only. Checks whether ImageMagick's `policy.xml` still lets HEIC, HEIF or AVIF through, and prints the lines that block them. Exits `0` if HEIF is blocked everywhere a policy was found, `1` if it is still allowed, `2` if no policy was found |
| `harden` | Writes a managed block into ImageMagick's `policy.xml` that refuses the HEIC, HEIF and AVIF coders, so a crafted upload never reaches `libheif` through ImageMagick. Backs the file up first, is idempotent, and is the one thing this script changes. Needs root. Defence in depth, not a substitute for updating `libheif` |
| `unharden` | Removes the managed block and restores. Needs root. Only touches a block this script wrote; a block added by hand is left alone |
| `mw-harden` | Blocks HEIF, HEIC and AVIF uploads in every MediaWiki found, by adding those MIME types to `$wgMimeTypeExclusions` in `LocalSettings.php`, so a crafted upload is rejected by its detected type before the scaler runs. Backs the file up first, is idempotent, checks the result still parses as PHP before saving, and is reversible. Needs root. Application-level defence, not a substitute for updating `libheif` |
| `mw-unharden` | Removes the MediaWiki block and restores. Needs root. Only touches a block this script wrote |
| `hunt` | Read-only log triage for image-processor crashes: ImageMagick, `libheif` and `libde265` segfaults, HEIF decoder frames in backtraces, services killed by a crash signal, and repeated HEIF decode errors. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What the libheif check looks at

1. **`libheif` on the host.** Every `libheif` shared object on the standard library paths and in `ldconfig`'s cache, judged by its package build or, if it is not a distribution package, by the upstream version floor. The version is read from the library's own soname, never from a stray build string inside it, and the library is never executed.
2. **`libde265`.** The HEVC codec `libheif` calls for HEIC. It has its own CVE history and its own fixed versions, so the script reports its version but does not judge it against the `libheif` floor. Update it from your distribution too.
3. **What reaches `libheif`.** ImageMagick (`magick` or `convert`) and libvips, with whether ImageMagick can even decode HEIF or AVIF. A build with no HEIF delegate is not a path to this bug through that tool.
4. **Discourse.** The Docker launcher under `/var/discourse`, a bare-metal checkout under `/var/www/discourse`, and `discourse/discourse` and `discourse/base` images. A forum's image-upload path runs an attacker-supplied file through ImageMagick into `libheif`, so a Discourse install on top of a vulnerable `libheif` is a path to it. For a Docker install the library lives inside the web container, so the script points at the container section and tells you to rebuild rather than restart.
5. **MediaWiki.** `LocalSettings.php` under the usual web roots. MediaWiki is a path to this bug only when it is configured for it, so the script reads the config rather than assuming: the scaler must be ImageMagick (`$wgUseImageMagick`), not GD (its default when both are installed), and a HEIF-family extension must be in `$wgFileExtensions` (not a default). It reports a wiki as exposed only when both are true, and otherwise says why it is not a path. Reading the PHP config file is not executing it.
6. **`libheif` inside running containers.** For each running Docker or Podman container, the script reads the `libheif` the container actually loads. This is how a Discourse web container still carrying the old library gets caught: a web-interface update does not replace it, only a rebuild does.

### libheif patch detection

For each `libheif` the checks run in order, and the first that applies decides:

1. **`FIXED_BUILDS`.** Distribution builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. **Changelog.** For a `libheif` installed from a Debian or Ubuntu package, the package changelog names DSA-6417-1 or one of the batch CVEs, and its newest entry is the installed build. Because distributions backport under old upstream numbers, this overrides the version floor: a package at `1.17.6` can read as fixed when its changelog proves it.
3. **Upstream floor.** For a library that is not a distribution package (self-built or bundled), the version is at or above `HEIF_FIXED_UPSTREAM` (default 1.22.0). A dpkg-owned build with no changelog proof is reported as unknown rather than fixed, because its number alone cannot clear it.

### libheif disabling the coder as defence in depth

Even after `libheif` is patched, more decoder bugs in this format are likely, so it is worth refusing untrusted HEIF and AVIF at the converter. `policy` reports whether ImageMagick already does, and prints the lines to add inside `<policymap>` in `policy.xml`:

```xml
<policy domain="coder" rights="none" pattern="HEIC" />
<policy domain="coder" rights="none" pattern="HEIF" />
<policy domain="coder" rights="none" pattern="AVIF" />
```

`harden` writes those lines for you, as a marked, managed block, so you don't have to edit the XML by hand:

```bash
sudo ./libheif-oct2026-check.sh harden      # write the block (backs the file up first)
sudo ./libheif-oct2026-check.sh unharden    # take it back out
```

`harden` is the only host-wide change this script makes. It backs the file up under `/var/backups/libheif-oct2026/` first, writes one managed block (running it again refreshes that block rather than adding a second), and creates a `policy.xml` if none exists, since ImageMagick with no policy decodes HEIF by default. `unharden` removes only the block this script wrote and leaves any coder lines you added by hand alone. This stops ImageMagick handing HEIF and AVIF to `libheif`. It is not a substitute for updating the library, and it does not help a caller that reaches `libheif` without going through ImageMagick. Discourse added ImageMagick sandboxing as its own defence in depth.

### libheif blocking HEIF uploads in MediaWiki

The ImageMagick coder policy above is host-wide. If you run a MediaWiki that is configured to accept HEIF (ImageMagick scaler plus a HEIF-family extension in `$wgFileExtensions`), `mw-harden` blocks the upload at the application instead, which is more targeted and survives an ImageMagick reconfigure:

```bash
sudo ./libheif-oct2026-check.sh mw-harden      # block HEIF/HEIC/AVIF uploads in every wiki found
sudo ./libheif-oct2026-check.sh mw-unharden    # take the block back out
```

It appends a marked, managed block to `LocalSettings.php` that adds the HEIF-family MIME types (`image/heif`, `image/heic`, `image/avif`, and the `-sequence` variants) to `$wgMimeTypeExclusions`, mirrors it to the pre-1.37 `$wgMimeTypeBlacklist` name when that is in use, and drops `heif`, `heic` and `avif` from `$wgFileExtensions` if they are there. Excluding by MIME type rejects a crafted file by its detected type, so renaming it to `.jpg` does not get it past. The edit is backed up first, is idempotent, and is checked with `php -l` before it is saved, so a file that would not parse is left untouched (and its backup kept). This is an application-level block; the host `libheif` still needs updating.

### libheif hunting for exploitation

A crafted image corrupts memory while it decodes, so a failed attempt usually shows as a crashed image worker rather than an application error. `hunt` reads the journal and logs, never changes anything, and reports ImageMagick, `libheif` and `libde265` segfaults, `libheif` and `libde265` frames in a backtrace, services killed by a crash signal, heap corruption aborts, and repeated HEIF, HEIC or AVIF handling errors. `HUNT_SINCE` sets how far back it reads the journal, and `HUNT_LOGS` adds your own log files.

A match is a lead, not proof. Image decoders crash on genuinely broken files too. A crash with `libheif` or `libde265` frames on a vulnerable build, or a burst of HEIF decode errors from one source just before a worker died, is worth treating as an incident: check what the process could reach and rotate it. On a forum that includes its admin and session stores.

### libheif configuration

| Variable | Default | Purpose |
|---|---|---|
| `HEIF_FIXED_UPSTREAM` | `1.22.0` | Upstream floor the heap-write class is fixed at, used only for libraries that are not distribution packages |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distribution builds, space-separated full versions |
| `DISCOURSE_ROOT` | `/var/discourse` | Where the Discourse Docker launcher lives |
| `DISCOURSE_APP` | `/var/www/discourse` | Where a bare-metal Discourse checkout lives |
| `POLICY_PATHS` | ImageMagick-6 and -7 config dirs | Where `policy` looks for `policy.xml` |
| `MW_PATHS` | common web roots | Where `check` and `mw-harden` look for MediaWiki's `LocalSettings.php` |
| `HUNT_SINCE` | `2026-07-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### libheif know before you run it

- **The real fix is the update, which this script does not run for you.** Update `libheif` and `libde265`, rebuild anything that bundles them, and for Discourse rebuild the container (`/var/discourse/launcher rebuild app`), which a web-interface update does not do. A package upgrade or a container rebuild is an administrator's call to time, so the script prints it rather than firing it.
- **It changes only two things, and only when asked.** `harden` writes the ImageMagick coder block; `mw-harden` writes the MediaWiki upload block. Both back the file up first and are reversible (`unharden`, `mw-unharden`). Everything else is read-only. A single upload setting is not the fix on its own, because many surfaces reach the decoder; blocking the coder at the converter (or the upload at the wiki) is the reliable interim step while you schedule the update.
- **MediaWiki is only exposed when configured for it.** The check flags a wiki only when it uses ImageMagick and accepts HEIF; a default install uses GD and does not accept HEIF, so it is not a path. `mw-harden` edits `LocalSettings.php`, so it checks the result parses with `php -l` before saving and leaves a file that wouldn't parse untouched.
- **Distribution backports read correctly.** A package can carry the fixes under an older upstream number; the script trusts the package changelog over the version. If you know a build is fixed and the changelog doesn't name it, add it to `FIXED_BUILDS`.
- **`libde265` is reported, not judged.** It has its own fixed versions. Update it from your distribution.
- **Containers need their own fix.** Each image carries its own `libheif`; rebuild on a fixed base. The script reads the library inside running containers but can't see one that was installed in an unusual way.
- **GNU/Linux only.** Library discovery and container inspection assume it.

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
