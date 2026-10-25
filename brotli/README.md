# Brotli: CVE-2026-111497 checker and ecosystem notes

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="cve-2026-111497-is-not-only-a-nodejs-bug"></a>

## CVE-2026-111497 is not only a Node.js bug

The guard and scripts here cover Node.js, because that is what we run. The underlying flaw is in Google's Brotli C decoder (`libbrotli` / `libbrotlidec`): the decoder fails to propagate an invalid block-switch when a stream declares only one block type, so a crafted Brotli stream writes past the decoder's output buffer. Node.js bundles that decoder, but so do many other things, and the same CVE has advisories across the ecosystem (some people are now calling the broadened picture "HTTP2Shell", since any HTTP path that decodes untrusted Brotli can be a route to it). Review all applications and services that decompress Brotli data from untrusted sources, not only those using Node.js.

The fix is the upstream library, so for everything other than Node.js the answer is to update the package or runtime. A read-only checker, [`brotli/brotli-oct2026-check.sh`](brotli-oct2026-check.sh), finds `libbrotli` on the host, the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, Envoy, Istio, cdxgen) and `libbrotli` inside running containers, and reports which are fixed. It changes nothing; it only tells you what to update. Fixed versions, reviewed 23 October 2026:

| Where Brotli lives | Fixed versions |
|---|---|
| Google Brotli (upstream C library, `libbrotli`/`libbrotlidec`) | 1.0.10, 1.1.1, 1.2.1 (pick the one for your branch) |
| OS packages (`libbrotli1`, `libbrotlidec1`) | your distribution's build containing 1.0.10, 1.1.1 or 1.2.1 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| Bun | 1.4.4 (bundles Brotli 1.2.1) |
| Envoy | 1.40.0, 1.39.3, 1.38.6, 1.37.8 (1.36.12 has the fix but 1.36 is unsupported) |
| Istio | 1.29.9, 1.30.6, 1.31.2 |
| Python `brotli` extension | 1.2.1 |
| Python `brotlicffi` | 1.2.1.0 (bundles Brotli 1.2.1) |
| cdxgen (SBOM tool, Node-based) | 13.5.0, 12.8.9 (rebuild standalone binaries and images) |

The upstream library is [github.com/google/brotli](https://github.com/google/brotli); update the package your system installs from it rather than vendoring it. If a fixed build is not yet available for something you run, disable Brotli decoding of untrusted data until it is: reject `Content-Encoding: br` before anything decompresses it, turn off automatic Brotli decoding in HTTP clients (dropping `br` from `Accept-Encoding` does not stop a server sending it anyway), and disable Brotli decompressor filters in Envoy and Istio in both directions. Apache and nginx do not decode Brotli by default, so the usual risk is an application, proxy or client that was configured to. OpenAI's write-up at [patchtheplanet.org/brotli](https://patchtheplanet.org/brotli) has per-stack mitigation snippets; the fixed-version facts above come from the Node.js, Envoy and upstream advisories.

## Brotli checker quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/brotli/brotli-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/brotli/brotli-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less brotli-oct2026-check.sh
   chmod +x brotli-oct2026-check.sh
   ```

3. See what's exposed. Root is optional, but without it you won't read every library or exec into other users' containers.

   ```bash
   sudo ./brotli-oct2026-check.sh check
   ```

4. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./brotli-oct2026-check.sh hunt
   ```

## Brotli checker commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every `libbrotli` on the host (`libbrotlidec`, `libbrotlienc`, `libbrotlicommon`), the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, Envoy, Istio, cdxgen), and `libbrotlidec` inside running containers, with whether each carries the fix. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable Brotli is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for process crashes that look like a Brotli decoder overflow: segfaults with `libbrotlidec`/`BrotliDecoder` frames, protection faults, heap corruption aborts, and services killed by a crash signal. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every command prints it on its first line too |

## Brotli checker patch detection

For a `libbrotli` installed from a Debian or Ubuntu package, the script judges it by the package build first (a built-in list of known fixed builds plus any you add with `FIXED_BUILDS`, then the package changelog naming `CVE-2026-111497`), because a distribution can backport the fix under an older upstream number. The built-in list already carries Debian 13's `brotli 1.1.0-2+deb13u1` (23 October 2026), so a patched trixie host reads as fixed without any configuration. For a self-built or bundled library it uses the upstream per-branch fix: 1.0.10 for the 1.0 branch, 1.1.1 for 1.1, 1.2.1 for 1.2. Runtimes are judged by their own fixed releases (Node.js 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; Istio 1.29.9 / 1.30.6 / 1.31.2; Python `brotli` 1.2.1; Python `brotlicffi` 1.2.1.0; cdxgen 13.5.0 / 12.8.9). All of these are overridable with the environment variables documented in the script header.

## Brotli checker know before you run it

- **It is a check, not a fix, and not a mitigation.** The fix is to update `libbrotli` and the runtimes that bundle it, rebuild anything that embeds it, and restart. Unlike the ImageMagick coder policy for libheif, Brotli has no host-wide switch to turn off, so there is nothing safe for a script to write; disabling Brotli decoding is application-specific (see the paragraph above).
- **The decoder is the vulnerable path.** `libbrotlidec` is what matters; `libbrotlienc` and `libbrotlicommon` ship from the same package and are shown so you can see the whole install.
- **Distribution backports read correctly.** If you know a distro build is fixed and its changelog doesn't name the CVE, add it to `FIXED_BUILDS`.
- **Runtime detection reads the command line only.** It reports the versions of Node.js, Bun, Envoy and Istio it can run; it does not inspect every container image or embedded copy. Containers are read for `libbrotlidec` only, and only while running.
- **A Python Brotli binding is a live decode path just by being installed.** Python HTTP clients such as urllib3 and requests decode `Content-Encoding: br` on their own whenever `brotli` or `brotlicffi` is importable, so the risk is present wherever the package exists, not only where code calls a decode function. The checker imports both bindings (confirming each exposes a real `decompress`) and judges `brotli` per branch and `brotlicffi` against 1.2.1.0. Where you cannot upgrade yet, the interim mitigation is to uninstall `brotli` and `brotlicffi` so those clients fall back to gzip and deflate. Automated scanners such as Dependabot can miss these packages, because the CVE record names Google's Brotli repository rather than the PyPI packages, so check installed versions directly.
- **For Node.js, this only reports the version.** The interim require-guard is the separate [Node.js mitigation](../node/README.md#nodejs-october-2026-interim-mitigation).
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
