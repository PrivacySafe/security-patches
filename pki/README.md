# eMudhra: intermediate CA compromise

Part of the [PrivacySafe Security Patches](../README.md) collection.

## eMudhra Intermediate CA Compromise Mitigation

**Script:** [`pki/emudhra-mitigate.sh`](emudhra-mitigate.sh)

On 20 October 2026 it was [disclosed](https://emudhra.we-have-a-problem.com/) that the private keys of eight eMudhra intermediate CAs can be recovered from their certificates. Anyone holding one can impersonate any website. Browsers already block them through OneCRL, CRLite and CRLSets, but your server's system CA store doesn't. Everything that reads it keeps trusting the compromised intermediates until `ca-certificates` is updated: OpenSSL, GnuTLS, curl, wget, apt, git, Python, PHP, Go, Ruby, and Java through ca-certificates-java.

The intermediates reach the store through two roots: emSign ECC Root CA - G3, which cross-signs emSign Root TLS CA - G3, and Sectigo's AAA Certificate Services, which cross-signs all eight. This script:

1. Distrusts those roots in the system store , using `!` lines in `/etc/ca-certificates.conf`, and rebuilds it. It finds affected certificates by public key, not file name, so it also catches copies someone added by hand to `/usr/local/share/ca-certificates` or `/etc/ssl/certs`. It moves those out of the store into the backup directory.
2. Proves the store rejects all of them. The script embeds the 16 published intermediate certificates and checks each against its published SHA-256 before using it. After every change it tests all 16 against the bundle file, the hash directory, and OpenSSL's built-in default paths. It also checks the bundle holds none of the affected certificates, because Go and GnuTLS will treat a lone intermediate in the store as a trust anchor.

The script is designed so it can't break your CA store or leave you exposed by mistake. It checks that the rebuilt bundle lost only affected certificates and still has hash links, and rolls back if not. If `TEST_HOSTS` is set, it checks those hosts before and after so you see any collateral breakage immediately. `cleanup` never removes the distrust unless the store still rejects every compromised intermediate without it, and re-applies it if not.

### eMudhra quick start

1. Download it. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/pki/emudhra-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pki/emudhra-mitigate.sh
   ```

2. Read it before running it. Always.

   ```bash
   less emudhra-mitigate.sh
   ```

3. Make it executable.

   ```bash
   chmod +x emudhra-mitigate.sh
   ```

4. Check the environment. This changes nothing and needs no root.

   ```bash
   ./emudhra-mitigate.sh check
   ```

5. Apply. Set `TEST_HOSTS` to hosts your server actually talks to, so the script flags any that stop verifying after the change.

   ```bash
   sudo TEST_HOSTS="api.example.com:443 mirror.example.org" ./emudhra-mitigate.sh
   ```

To confirm GitHub and Codeberg serve the same script, compare checksums:

```bash
sha256sum emudhra-mitigate.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/pki/emudhra-mitigate.sh | sha256sum
```

Set `TEST_HOSTS` to the hosts your server actually talks to: APIs, package mirrors, webhooks. A host that verifies before the change and fails after it most likely chains to one of the two distrusted roots.

### eMudhra commands

| Command | What it does |
|---|---|
| `check` | Environment report only. Changes nothing and doesn't need root. Exits `0` if clear, `1` on a hard blocker, `2` if `--ignore-env` would be needed |
| `apply` (default) | Distrusts the affected certificates, rebuilds the store, cleans the Java keystore, then verifies |
| `status` | What this script changed, all store tests, Java keystore state, and processes that still need a restart. Exits `1` if the store trusts a compromised intermediate |
| `restore` | Undoes everything this script distrusted. This re-exposes you if `ca-certificates` isn't patched |
| `cleanup` | Once `ca-certificates` is patched, removes this script's distrust, but only if the store still rejects every compromised intermediate. Otherwise it puts the distrust back. `--force` skips the patch check, never the store test |
| `version` | Prints the script version. Every command prints it on its first line too |

### eMudhra environment check

Before changing anything, the script checks your server in this order and prints what it found:

1. Operating system. The same set as PHP2Shell: Debian, Ubuntu, Trisquel, the derivatives the check knows by name, and anything whose `ID_LIKE` names Debian or Ubuntu. It works out the base release so it can compare against the right fixed `ca-certificates` build. Other systems are refused with a pointer to their workaround on the disclosure page.
2. System CA store. The `ca-certificates` version and its patch status (see [Patch detection](#emudhra-patch-detection)). It lists every affected certificate it finds, whether shipped, already distrusted, or added by hand, and tests the current bundle.
3. Other CA stores. This run doesn't fix these, so they're reported with the command that does:
   - Java. The system keystore follows the store. Other JDKs carry their own `cacerts`.
   - Bundled CA files such as Python certifi, vendored pip and Homebrew, found under `SCAN_PATHS`. Debian's patched certifi reads the system store and is recognized as such.
   - Node.js. It ships its own roots unless started with `--use-openssl-ca`.
   - NSS builtin roots , unless `libnssckbi` is p11-kit.
   - Overrides. `SSL_CERT_FILE` or `SSL_CERT_DIR` set in `/etc/environment` or `/etc/profile.d`.
   - Separate environments. Containers, snaps and Flatpaks.
4. System. Root, OpenSSL, the self-check of the embedded certificates, the init system (for restart hints), and required tools.

**Hard blockers** always stop the run: a distribution that isn't Debian-based, `ca-certificates` or `update-ca-certificates` missing, no `openssl`, a failed self-check, missing tools, or not running as root for `apply`, `restore` or `cleanup`.

**Soft blockers** stop the run until you've looked at them, and `--ignore-env` lets you proceed. They cover a process that would keep trusting the compromised intermediates even after a clean run:

- a running Node.js process using its bundled roots;
- a running Java process on a JDK whose own `cacerts` still holds affected certificates;
- a system-wide `SSL_CERT_FILE` or `SSL_CERT_DIR` that points at an exposed store.

### eMudhra patch detection

For `ca-certificates`, three checks run in order, and any one is enough:

1. Fixed build for your release. These are the builds from the disclosure page:

   | Release | Fixed build |
   |---|---|
   | Debian 12 | `20250419~deb12u2` |
   | Debian 13 | `20250419+deb13u1` |
   | Debian testing/unstable | `20260816+nmu1` |
   | Ubuntu 22.04, 24.04, 26.04, 26.10 | `20260816ubuntu0.XX.YY.1` |

   It only compares against the build for your own release, because Debian 12 and 13 share the upstream version `20250419`.
2. `FIXED_BUILDS`. Builds you add, such as an Ubuntu ESM or Debian LTS update. A build only counts for the same upstream version.
3. Changelog. The package changelog names Launchpad bug 2171507 or Debian bug 1151413, both from the disclosure page. The changelog only counts if its newest entry is the installed version. (CVE-2026-111943 is deliberately *not* used here: that CVE is the Go standard library's own `crypto/x509` denylist, fixed in Go 1.26.10 / 1.27.3, so a `ca-certificates` changelog won't cite it. See the Go note below.)

The result is *patched*, *not patched*, or *unknown*. The store tests decide what actually happens: `cleanup` checks the patch status first, but it removes the distrust only if the store still rejects every intermediate without it.

A fixed store isn't enough on its own, because a long-running process keeps the trust it loaded at start. `status` and `apply` list processes started before the current store that loaded a TLS library or a JVM, or are Node.js, and tell you what to restart. One-shot tools like curl, apt and git need nothing.

### eMudhra configuration

| Variable | Default | Purpose |
|---|---|---|
| `TEST_HOSTS` | *(empty)* | `host[:port]` list to TLS-test before and after `apply`, to catch collateral breakage |
| `FIXED_BUILDS` | *(empty)* | Extra fixed `ca-certificates` builds, space-separated full versions |
| `SCAN_PATHS` | `/opt /srv /usr/local /usr/lib /usr/share /home /root /var/www` | Where to look for bundled CA files. Empty disables the scan |
| `SCAN_DEPTH` | `9` | How deep that scan goes |
| `JAVA_STOREPASS` | `changeit` | Password for the Java keystores |

## Before you run it

- This is not a patch. Upgrade `ca-certificates` when your distribution ships the fix, then run `cleanup`.
- It distrusts two whole roots, not just the eight intermediates. The system store can only drop roots, so every site whose chain ends at emSign ECC Root CA - G3 or AAA Certificate Services fails verification until you run `cleanup` or `restore`. Set `TEST_HOSTS` and check `status` after applying. If the store already rejects every compromised intermediate, for example because a patched package cut the path, `apply` leaves those two roots trusted.
- Your browsers are already protected. Firefox, Chrome, Edge and Safari block these intermediates themselves. This script is for everything else on your servers.
- Other CA stores are reported, not changed. Python certifi, Node.js, other JDKs and NSS builtins need their own updates. The report prints the command for each. Programs that compile their roots in, such as Rust's webpki-roots and Electron apps, can't be detected and need updating. One common case is [uv](https://github.com/astral-sh/uv), the Python package manager: Plone's 6.2.2.1 release notes tell uv users to upgrade to 0.13.4 for this incident. If you can't upgrade a Node.js or Electron app right away, the [`kill-emudhra`](https://github.com/IAmJSD/kill-emudhra) package distrusts the eight intermediates from inside the process, by their public-key hash. That protects the process until you reach a fixed Node.js (22.23.4, 24.22.1 or 26.12.1) or Electron (44.9.1, 43.8.1 or 42.11.16).
- Go binaries need their own fix. A Go program built with CGO reads the system store this script fixes, but a pure-Go build carries Go's own certificate verifier, which got a built-in denylist for these intermediates in Go 1.26.10 and 1.27.3 ([CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809)). Rebuild such binaries with a fixed toolchain. This script's check reminds you if a `go` toolchain is present but can't tell which existing binaries are affected.
- Containers get their own fix. Each image carries its own `ca-certificates`. Rebuild images on patched bases. Running this inside a container fixes that container only.
- The distrust survives package upgrades and `dpkg-reconfigure ca-certificates`. Both keep `!` lines in `/etc/ca-certificates.conf`. Check with `status` after any upgrade anyway.
- Debian, Ubuntu, Trisquel and their derivatives only. Fedora/RHEL, openSUSE, Arch, Alpine, NixOS and FreeBSD need a different approach. macOS has its own script, [below](#emudhra-on-macos). See the [disclosure page](https://emudhra.we-have-a-problem.com/#linux).
- Backups of everything the script touches go to `/var/backups/emudhra-mitigation/<timestamp>-<pid>/`, so two runs in the same second never share a directory. A certificate file the script moves out of `/usr/local/share/ca-certificates` or `/etc/ssl/certs` is kept under a numbered name (`01-root.crt`, `02-root.crt`), so two different files with the same name from different directories cannot overwrite each other, and `restore` puts each one back where it came from. The record of what it changed is `/var/lib/emudhra-mitigation/state`.


<a name="emudhra-on-macos"></a>

## eMudhra on macOS

**Script:** [`pki/emudhra-macos-mitigate.sh`](emudhra-macos-mitigate.sh)

macOS blocks the compromised eMudhra intermediates in apps that use Apple's own networking and security frameworks, such as the browsers. The command line tools that ship with macOS and with the Xcode Command Line Tools, `curl`, `git`, `python3`, `ruby`, `perl` and `openssl`, are different: they verify certificates against `/etc/ssl/cert.pem` without checking revocation, and that file still contains the roots the intermediates chain to. Apple's [support page](https://support.apple.com/en-us/149555) says it will update the file in a future release, and that a macOS update can replace a file you edited. Hosted macOS CI runners are affected the same way, and so is anything on them that uses Homebrew's `curl` or `git`, because their images disable Homebrew updates and so keep the old `ca-certificates`.

This script does what Apple's support page and the [disclosure page](https://emudhra.we-have-a-problem.com/#macos-curl) describe, with a backup, a check and a way back. It cuts the root out of the bundle with the same `awk` command and writes the file with the same `install -m 0644 -o root -g wheel` command as Apple's steps:

1. `check` reports whether emSign ECC Root CA - G3 and AAA Certificate Services are still in the system bundle and in Homebrew's, the Homebrew `ca-certificates` version against the first fixed one, and whether the built-in `pip` uses the system file. `--online` also connects to the disclosure site's test hosts.
2. `apply` backs up the bundle, removes emSign ECC Root CA - G3 from it, and proves the root is gone. `--include-aaa` also removes AAA Certificate Services. Like Apple's steps it keeps a copy next to the file as `cert.pem.orig`, and when a macOS update has replaced the file it refreshes that copy instead of keeping the stale one.
3. `rollback` puts the original bundle back.

### macOS quick start

1. Download it. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/pki/emudhra-macos-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pki/emudhra-macos-mitigate.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less emudhra-macos-mitigate.sh
   chmod +x emudhra-macos-mitigate.sh
   ```

3. See whether you are exposed. This changes nothing and needs no root. Add `--online` to test against the live hosts.

   ```bash
   ./emudhra-macos-mitigate.sh check
   ./emudhra-macos-mitigate.sh check --online
   ```

4. See the change, then make it. Run it from an admin account with `sudo`.

   ```bash
   sudo ./emudhra-macos-mitigate.sh apply --dry-run
   sudo ./emudhra-macos-mitigate.sh apply
   ```

5. Update Homebrew as your own user, not with `sudo`. The script never runs `brew`.

   ```bash
   brew update && brew upgrade ca-certificates
   ```

### macOS commands

| Command | What it does |
|---|---|
| `check [--online] [--cert-file FILE]` (default) | Read-only. Exits `0` when neither root is in the bundle, `1` when emSign ECC Root CA - G3 is present, an old Homebrew `ca-certificates` is installed or a test host accepted the connection, `2` when only AAA Certificate Services remains or the bundle could not be read in full |
| `apply [--include-aaa] [--pip] [--dry-run] [--cert-file FILE]` | **Changes the host (root).** Backs up the bundle to `/var/lib/psf-security-patches/emudhra-macos/`, removes the root, and checks the result. If the check fails it puts the original back. `--pip` points the built-in `pip` at the system file |
| `rollback [--dry-run] [--force]` | Puts the original bundle back and removes the `pip` line. This re-exposes you. It refuses when the bundle has changed since `apply`, for example after a macOS update, unless you pass `--force` |
| `version` | Prints the script version. Every command prints it on its first line too |

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget:

```bash
sudo ./emudhra-macos-mitigate.sh apply --dry-run
sudo ./emudhra-macos-mitigate.sh apply
sudo ./emudhra-macos-mitigate.sh rollback
```

### macOS on hosted runners

A hosted macOS runner has passwordless `sudo`, so a workflow step can apply the change before anything else makes a TLS connection. Pin the script by its SHA-256, taken from the release you reviewed, so a changed copy is refused. The download itself goes over the system's own trust, which is the thing being fixed, and the hash is what protects it.

```yaml
- name: Distrust the compromised eMudhra root
  run: |
    curl -fsSLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pki/emudhra-macos-mitigate.sh
    echo "${{ vars.EMUDHRA_MACOS_SHA256 }}  emudhra-macos-mitigate.sh" | shasum -a 256 -c -
    chmod +x emudhra-macos-mitigate.sh
    sudo ./emudhra-macos-mitigate.sh apply
    ./emudhra-macos-mitigate.sh check --online
    brew update && brew upgrade ca-certificates
```

### macOS configuration

| Variable | Default | Purpose |
|---|---|---|
| `CERT_FILE` | `/etc/ssl/cert.pem` | The bundle to check and change |
| `STATE_DIR` | `/var/lib/psf-security-patches/emudhra-macos` | Backups and the record that `rollback` reads |
| `BREW_PREFIX` | *(detected)* | Where Homebrew is installed: `/opt/homebrew`, `/usr/local` or Linuxbrew |
| `CURL_BIN` | *(system curl)* | The `curl` that `--online` uses, besides `/usr/bin/curl` and Homebrew's |
| `LIVE_HOSTS` | *(the four hosts on the disclosure page)* | Replaces the hosts `--online` connects to |
| `PSF_NO_ROOT_NOTE` | *(unset)* | `1` hides the note that a change was started from the root account |

### macOS before you run it

- This is not a patch. Apple will ship its own fix. When it does, `check` tells you, and `rollback` is safe to run only if you want your old file back.
- It removes a whole root, not just the intermediates. emSign ECC Root CA - G3 covers the direct chains. The six Sectigo cross-signed intermediates chain to AAA Certificate Services instead, and removing that root can break unaffected sites that chain to it, so it is off unless you pass `--include-aaa`. `check` exits `2` while only that root remains, so the decision stays visible.
- It cuts a block only when the block's certificate has the published SHA-256 fingerprint of the root (`86A1ECBA...BE6B` for emSign ECC Root CA - G3, `D7A7A0FB...9EF4` for AAA Certificate Services), the certificate count drops by exactly the number removed, and OpenSSL can still read every remaining certificate. Otherwise it changes nothing and points you to the manual steps. A header line is any `===` or `###` line that ends with the root's name, so a different order of the subject fields still matches.
- It will not tell you a bundle is clean if it cannot read it. OpenSSL reads nothing at all from a bundle that has one damaged certificate, which would make both roots look absent, so `check` exits `2` and says how many certificates it could read, and `apply` refuses.
- A macOS update may replace `/etc/ssl/cert.pem` and bring the root back. Apple says so, and reports of macOS 27.2 say it did. Run `check` after each update and `apply` again. `rollback` after that skips the records the update made stale instead of putting an out-of-date bundle back. If macOS refuses the write, the original is untouched.
- The browsers and Apple's own frameworks are already protected and are not changed. Homebrew has its own bundle, which `check` reports but `apply` does not change: on a Mac Homebrew builds it from the certificates your Keychain trusts plus Mozilla's list, so versions before 2026-09-25_1 still include both roots, and from that release on its post-install step leaves them out by public key. Update it with `brew upgrade ca-certificates` as your own user. Other bundled copies of the roots, such as Python `certifi`, Node.js, Go and Java, need their own updates; see the [disclosure page](https://emudhra.we-have-a-problem.com/#developers).
- `--pip` appends one line to the system Python's `sitecustomize.py`, as the disclosure page describes. `rollback` removes exactly that line, and the file too if the script created it.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-03) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

This is the Go standard library flaw named above, so the advisories are for Go programs, not for the certificate store.

- [CVE-2026-111943](https://access.redhat.com/security/cve/CVE-2026-111943): 163 advisories, 2026-10-20 to 2026-11-03; 159 important, 4 critical; by stream, RHEL 8 21, RHEL 9 42, RHEL 10 21, Hummingbird 50, RHEL 8 (el8ost) 1, RHEL 8 (el8sat) 1, RHEL 9 (el9ost) 2, RHEL 9 (el9sat) 3, container image 22; most often `rhc` (10), `grafana-pcp` (9), `grafana` (9), `golang` (7). All of them: [Red Hat's CVE page](https://access.redhat.com/security/cve/CVE-2026-111943).

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
