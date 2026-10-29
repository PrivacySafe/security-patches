# eMudhra: intermediate CA compromise

Part of the [PrivacySafe Security Patches](../README.md) collection.

## eMudhra Intermediate CA Compromise Interim Mitigation

**Script:** [`pki/emudhra-mitigate.sh`](emudhra-mitigate.sh)

On 20 October 2026 it was [disclosed](https://emudhra.we-have-a-problem.com/) that the private keys of eight eMudhra intermediate CAs can be recovered from their certificates. Anyone holding one can impersonate any website. Browsers already block them through OneCRL, CRLite and CRLSets, but your server's system CA store doesn't. Everything that reads it keeps trusting the compromised intermediates until `ca-certificates` is updated: OpenSSL, GnuTLS, curl, wget, apt, git, Python, PHP, Go, Ruby, and Java through ca-certificates-java.

The intermediates reach the store through two roots: emSign ECC Root CA - G3, which cross-signs emSign Root TLS CA - G3, and Sectigo's AAA Certificate Services, which cross-signs all eight. This script:

1. **Distrusts those roots in the system store**, using `!` lines in `/etc/ca-certificates.conf`, and rebuilds it. It finds affected certificates by public key, not file name, so it also catches copies someone added by hand to `/usr/local/share/ca-certificates` or `/etc/ssl/certs`. It moves those out of the store into the backup directory.
2. **Proves the store rejects all of them.** The script embeds the 16 published intermediate certificates and checks each against its published SHA-256 before using it. After every change it tests all 16 against the bundle file, the hash directory, and OpenSSL's built-in default paths. It also checks the bundle holds none of the affected certificates, because Go and GnuTLS will treat a lone intermediate in the store as a trust anchor.

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

1. **Operating system.** The same set as PHP2Shell: Debian, Ubuntu, Trisquel, the derivatives the check knows by name, and anything whose `ID_LIKE` names Debian or Ubuntu. It works out the base release so it can compare against the right fixed `ca-certificates` build. Other systems are refused with a pointer to their workaround on the disclosure page.
2. **System CA store.** The `ca-certificates` version and its patch status (see [Patch detection](#emudhra-patch-detection)). It lists every affected certificate it finds, whether shipped, already distrusted, or added by hand, and tests the current bundle.
3. **Other CA stores.** This run doesn't fix these, so they're reported with the command that does:
   - **Java.** The system keystore follows the store; other JDKs carry their own `cacerts`.
   - **Bundled CA files** such as Python certifi, vendored pip and Homebrew, found under `SCAN_PATHS`. Debian's patched certifi reads the system store and is recognized as such.
   - **Node.js.** It ships its own roots unless started with `--use-openssl-ca`.
   - **NSS builtin roots**, unless `libnssckbi` is p11-kit.
   - **Overrides.** `SSL_CERT_FILE` or `SSL_CERT_DIR` set in `/etc/environment` or `/etc/profile.d`.
   - **Separate environments.** Containers, snaps and Flatpaks.
4. **System.** Root, OpenSSL, the self-check of the embedded certificates, the init system (for restart hints), and required tools.

**Hard blockers** always stop the run: a distribution that isn't Debian-based, `ca-certificates` or `update-ca-certificates` missing, no `openssl`, a failed self-check, missing tools, or not running as root for `apply`, `restore` or `cleanup`.

**Soft blockers** stop the run until you've looked at them, and `--ignore-env` lets you proceed. They cover a process that would keep trusting the compromised intermediates even after a clean run:

- a running Node.js process using its bundled roots;
- a running Java process on a JDK whose own `cacerts` still holds affected certificates;
- a system-wide `SSL_CERT_FILE` or `SSL_CERT_DIR` that points at an exposed store.

### eMudhra patch detection

For `ca-certificates`, three checks run in order, and any one is enough:

1. **Fixed build for your release.** These are the builds from the disclosure page:

   | Release | Fixed build |
   |---|---|
   | Debian 12 | `20250419~deb12u2` |
   | Debian 13 | `20250419+deb13u1` |
   | Debian testing/unstable | `20260816+nmu1` |
   | Ubuntu 22.04, 24.04, 26.04, 26.10 | `20260816ubuntu0.XX.YY.1` |

   It only compares against the build for your own release, because Debian 12 and 13 share the upstream version `20250419`.
2. **`FIXED_BUILDS`.** Builds you add, such as an Ubuntu ESM or Debian LTS update. A build only counts for the same upstream version.
3. **Changelog.** The package changelog names Launchpad bug 2171507 or Debian bug 1151413, both from the disclosure page. The changelog only counts if its newest entry is the installed version. (CVE-2026-111943 is deliberately *not* used here: that CVE is the Go standard library's own `crypto/x509` denylist, fixed in Go 1.26.10 / 1.27.3, so a `ca-certificates` changelog won't cite it. See the Go note below.)

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

### eMudhra know before you run it

- **This is not a patch.** Upgrade `ca-certificates` when your distribution ships the fix, then run `cleanup`.
- **It distrusts two whole roots, not just the eight intermediates.** The system store can only drop roots, so every site whose chain ends at emSign ECC Root CA - G3 or AAA Certificate Services fails verification until you run `cleanup` or `restore`. Set `TEST_HOSTS` and check `status` after applying. If the store already rejects every compromised intermediate, for example because a patched package cut the path, `apply` leaves those two roots trusted.
- **Your browsers are already protected.** Firefox, Chrome, Edge and Safari block these intermediates themselves. This script is for everything else on your servers.
- **Other CA stores are reported, not changed.** Python certifi, Node.js, other JDKs and NSS builtins need their own updates. The report prints the command for each. Programs that compile their roots in, such as Rust's webpki-roots and Electron apps, can't be detected and need updating. One common case is [uv](https://github.com/astral-sh/uv), the Python package manager: Plone's 6.2.2.1 release notes tell uv users to upgrade to 0.13.4 for this incident. For a Node.js or Electron app you can't immediately upgrade, the [`kill-emudhra`](https://github.com/IAmJSD/kill-emudhra) package distrusts the eight intermediates from inside the process by their public-key hash, as a stopgap until you reach a fixed Node.js (22.23.4 / 24.22.1 / 26.12.1) or Electron (44.9.1 / 43.8.1 / 42.11.16).
- **Go binaries need their own fix.** A Go program built with CGO reads the system store this script fixes, but a pure-Go build carries Go's own certificate verifier, which got a built-in denylist for these intermediates in Go 1.26.10 and 1.27.3 ([CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809)). Rebuild such binaries with a fixed toolchain; this script's check reminds you if a `go` toolchain is present but can't tell which existing binaries are affected.
- **Containers get their own fix.** Each image carries its own `ca-certificates`. Rebuild images on patched bases; running this inside a container fixes that container only.
- **The distrust survives package upgrades and `dpkg-reconfigure ca-certificates`.** Both keep `!` lines in `/etc/ca-certificates.conf`. Check with `status` after any upgrade anyway.
- **Debian, Ubuntu, Trisquel and their derivatives only.** Fedora/RHEL, openSUSE, Arch, Alpine, NixOS, FreeBSD and macOS need a different approach. See the [disclosure page](https://emudhra.we-have-a-problem.com/#linux).
- **Backups** of everything the script touches go to `/var/backups/emudhra-mitigation/<timestamp>-<pid>/`, so two runs in the same second never share a directory. A certificate file the script moves out of `/usr/local/share/ca-certificates` or `/etc/ssl/certs` is kept under a numbered name (`01-root.crt`, `02-root.crt`), so two different files with the same name from different directories cannot overwrite each other, and `restore` puts each one back where it came from. The record of what it changed is `/var/lib/emudhra-mitigation/state`.

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
