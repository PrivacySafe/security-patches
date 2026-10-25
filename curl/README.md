# curl: CVE-2026-92392

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="curl-http2-upload-use-after-free-check"></a>

## curl HTTP/2 Upload Use-After-Free Check

**Script:** [`curl/curl-oct2026-check.sh`](curl-oct2026-check.sh)

[CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html) is a use-after-free in libcurl's HTTP/2 upload handling. A malicious server that receives an upload can corrupt the uploading client's memory, and the reporter turned that into code execution on the client. The attack runs from the server side: the client uploads roughly 135KB over HTTP/2 to the attacker's HTTPS server (whose certificate must validate), the server stalls and resets the stream, and curl reuses a freed handle on retry. Taking over a client needs exact knowledge of its build, architecture, allocator and heap layout, so curl expects most real attempts to end in a crash, and rates the flaw High rather than Critical. Because libcurl is linked by many other programs (git, package managers, language runtimes), the exposure is not limited to the `curl` command.

The flaw affects curl and libcurl 8.12.0 through 8.22.0 and is not present before 8.12.0. It is fixed upstream in 8.23.0, with branch backports in 8.14.3, 8.16.2 and 8.20.2, and distributions ship their own builds (Debian 13 trixie: `8.14.1-2+deb13u7` via DSA-6558-1; Debian 12 bookworm does not carry the vulnerable code). This script is read-only: it finds what needs updating and reports whether each build is fixed and whether it supports HTTP/2 at all.

### curl quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/curl/curl-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/curl/curl-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less curl-oct2026-check.sh
   chmod +x curl-oct2026-check.sh
   ```

3. See what's exposed. Root is optional, but without it you won't read every library or exec into other users' containers.

   ```bash
   sudo ./curl-oct2026-check.sh check
   ```

4. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./curl-oct2026-check.sh hunt
   ```

### curl commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every `curl` command and `libcurl` on the host, and `libcurl` inside running containers, with whether each carries the fix and whether the build supports HTTP/2. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable curl/libcurl is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for process crashes that look like this bug: curl segfaults and protection faults, `libcurl` frames in a backtrace, use-after-free and heap-corruption aborts, and services killed by a crash signal. A failed attack is most likely a crash, so a crash on an outbound HTTP/2 upload is the signal. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every command prints it on its first line too |

### What the curl check looks at

1. **The `curl` command.** Every `curl` on `PATH` and the usual locations. It reads `curl --version`, which reports both the tool version and the `libcurl/X.Y.Z` the tool links, and whether the build advertises `HTTP2`. The verdict is on the libcurl version, since that is where the flaw lives. A build with no HTTP/2 support cannot reach the upload path, and is reported as such rather than as exposed.
2. **`libcurl` on the host.** Every `libcurl.so` on the standard library paths and in `ldconfig`'s cache. The soname is always `libcurl.so.4`, so the version is read from the package build (for a distribution library) or from the `libcurl/X.Y.Z` string the library carries, never by executing it. Each is noted for whether it links `nghttp2` (HTTP/2 capability).
3. **`libcurl` inside running containers.** For each running Docker or Podman container, the `libcurl` the container actually carries, read from its embedded version string. A rebuild, not a restart, replaces it.

### curl patch detection

For a curl or libcurl installed from a Debian or Ubuntu package, the script judges it by the package build first (a built-in list of known fixed builds plus any you add with `FIXED_BUILDS`, then the package changelog naming `CVE-2026-92392` or `DSA-6558-1`), because a distribution backports the fix under an older-looking upstream number. The built-in list already carries Debian 13's `8.14.1-2+deb13u7`, so a patched trixie host reads as fixed without configuration. For a self-built or bundled library it uses the upstream fix for the version's branch: 8.14.3 for 8.12.0 through 8.14.2, 8.16.2 for 8.15.0 through 8.16.1, 8.20.2 for 8.17.0 through 8.20.1, and 8.23.0 for 8.21.0 through 8.22.x. Anything below 8.12.0 is reported as not affected.

### curl interim mitigation

The fix is to update curl/libcurl and restart the programs that use it. Where you cannot update yet, curl's advice is to avoid HTTP/2 for uploads, because the vulnerable path is HTTP/2 only:

- On the command line, pass `--http1.1`.
- In an application, set `CURLOPT_HTTP_VERSION` to `CURL_HTTP_VERSION_1_1`. curl documents this as a request, since an existing connection on another version may be reused.
- A libcurl built without HTTP/2 cannot negotiate it, so it cannot reach the path at all.

### curl configuration

| Variable | Default | Purpose |
|---|---|---|
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro curl/libcurl builds, space-separated full versions. Checked alongside the built-in known builds, which it does not replace |
| `CURL_SEGMENTS` | `8.12.0:8.14.3 8.15.0:8.16.2 8.17.0:8.20.2 8.21.0:8.23.0` | `introduced:fixed` per maintained branch |
| `CURL_INTRODUCED` | `8.12.0` | Below this the flaw is not present |
| `SCAN_CONTAINERS` | `1` | `0` skips reading libcurl inside running containers |
| `HUNT_SINCE` | `2026-10-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### curl know before you run it

- **This is a check, not a fix.** Update to 8.23.0 (or the 8.14.3 / 8.16.2 / 8.20.2 branch build, or your distribution's fixed build), rebuild anything that bundles libcurl, and restart the programs that use it, since a running process keeps the old library until it restarts.
- **The risk is an outbound HTTP/2 upload to a server you don't control.** A program on this host that uploads over HTTP/2 to an attacker-controlled HTTPS server is the exposure; a plain server that only receives requests is not the target here.
- **A build without HTTP/2 is not a path.** The check reports HTTP/2 capability so you can tell, but HTTP/2 is built into most modern curl packages.
- **Distribution backports read correctly.** A package can carry the fix under an older upstream number; if you know a build is fixed and its changelog doesn't name the CVE, add it to `FIXED_BUILDS`.
- **Containers need their own fix.** Each image carries its own libcurl; rebuild on a fixed base. The script reads the library inside running containers but can't see one installed in an unusual way.
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
