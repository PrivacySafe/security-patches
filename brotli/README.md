# Brotli: CVE-2026-111497 checker and ecosystem notes

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="cve-2026-111497-is-not-only-a-nodejs-bug"></a>

## CVE-2026-111497 is not only a Node.js bug

CVE-2026-111497 is known as Broccoli2Shell. It was first called Node2Shell, until it was clear that the flaw is in Brotli itself and reaches well beyond Node.js. GitHub rates it 9.2 Critical (CVSS 4.0) and Node.js rates it High. The bug is tracked as CWE-252 (unchecked return value) and CWE-787 (out-of-bounds write).

The guard and scripts here cover Node.js, because that is what we run. The underlying flaw is in Google's Brotli C decoder (`libbrotli` / `libbrotlidec`), versions 1.0.3 through 1.2.0. `DecodeBlockTypeAndLength()` returned a plain boolean, so its callers could not tell a malformed stream from one that only needed more input, and the decoder's fast path ignored the result. A crafted stream can request a block switch that cannot happen (the reported case is a stream that declares only one block type). The decoder read that as "need more input" and kept appending attacker bytes to an eight-byte internal buffer, writing past its end. That corrupts nearby decoder state, which is how a malformed stream becomes a crash, a memory leak or remote code execution. The upstream fix is google/brotli commit `0ed4268` (with `50a9b70`, `b418fa8` and `da98063`), and it returns a hard format error, `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17), to the caller.

Node.js bundles that decoder, but so do many other things, and the same CVE has advisories across the ecosystem (some people are now calling the broadened picture "HTTP2Shell", since any HTTP path that decodes untrusted Brotli can be a route to it). Review all applications and services that decompress Brotli data from untrusted sources, not only those using Node.js.

A read-only checker, [`brotli/brotli-oct2026-check.sh`](brotli-oct2026-check.sh), finds `libbrotli` on the host, the processes that still have it loaded, the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, the Ruby `brotli` gem, the PHP `brotli` extension, Envoy, Istio, cdxgen) and `libbrotli` inside running containers, and reports which are fixed. It changes nothing; it only tells you what to update. For the many projects that vendor their own copy, see [Projects that bundle their own copy](#projects-that-bundle-their-own-copy) below. Fixed versions, reviewed 25 October 2026:

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
| Ruby `brotli` gem | 0.9.1 (bundles Brotli 1.2.1) |
| PHP `brotli` extension | 0.21.1 (bundles Brotli 1.2.1) |

The upstream library is [github.com/google/brotli](https://github.com/google/brotli); update the package your system installs from it rather than vendoring it. If a fixed build is not yet available for something you run, disable Brotli decoding of untrusted data until it is: reject `Content-Encoding: br` request bodies before anything decompresses them (at your proxy, load balancer or WAF; Vercel deployed WAF rules for this on disclosure day), turn off automatic Brotli decoding in HTTP clients, and disable Brotli decompressor filters in Envoy and Istio in both directions. For outbound requests, dropping `br` from `Accept-Encoding` helps less than you would hope, because a malicious server can send Brotli anyway, and a WAF never sees the responses your app fetches. Only the runtime or library upgrade covers that path. Installing an update is also not enough: a running process keeps the old decoder until it restarts, and a container keeps it until you rebuild the image on a patched base and redeploy. Apache and nginx do not decode Brotli by default, so the usual risk is an application, proxy or client that was configured to. OpenAI's write-up at [patchtheplanet.org/brotli](https://patchtheplanet.org/brotli) has per-stack mitigation snippets; the fixed-version facts above come from the Node.js, Envoy and upstream advisories.

### Where untrusted Brotli comes in

You are at risk if your code, or any library it uses, decompresses Brotli data that someone else controls. That happens in more places than you might expect, because HTTP clients decompress Brotli responses on their own.

- **Your app fetches a URL.** Node's built-in `fetch()` decodes `Content-Encoding: br` responses automatically. So do Python's `requests` and `urllib3`, and `aiohttp`, whenever a Brotli package is installed. Any server you talk to can send the payload, through webhooks, link previews, crawlers or "import from URL" features.
- **Your app accepts uploads or request bodies.** Express 5.0.0 to 5.3.0 and body-parser 2.0.0 to 2.3.0 inflate Brotli request bodies in parsers such as `raw()` and `json()`. Python frameworks and middleware that decode `br` bodies are exposed the same way. A bare `node:http` server does not decode bodies by itself.
- **Your app calls the decoder directly.** That means `zlib.brotliDecompress*()`, `createBrotliDecompress()`, Python's `brotli.decompress()`, and any library that uses them on archives, caches or queue messages.

Express and body-parser do not contain the bug. They are only paths to it, so upgrading them does not help. Node.js bundles its own Brotli, so the system `libbrotli` does not matter there; only the Node.js version does.

### Python

The PyPI packages `Brotli` (1.0.3 to 1.2.0) and `brotlicffi` (1.0.3 to 1.2.0.x) compile the same C decoder. Your code does not need to import them to be exposed. If either is installed, urllib3 (and therefore requests), aiohttp, httpx (through the `httpx[brotli]` extra) and crawlers such as Scrapy decode Brotli with it on their own. If your bindings come from your distribution (for example `python3-brotli`) rather than PyPI, the fix arrives through the distribution's security updates.

Do not wait for your scanner. When this was disclosed, pip-audit, Dependabot and Safety did not reliably flag the affected PyPI versions, because the CVE record names the upstream Google repository and not the PyPI packages. GitHub's advisory now lists both packages (PYSEC-2026-4322 and PYSEC-2026-4323), but check installed versions by hand anyway: `pip show Brotli brotlicffi`, and `pipdeptree -r -p Brotli` to see what pulls them in.

### Other languages

The bug is in the reference C decoder. Decoders rewritten in other languages are mostly not a concern: the Java, JavaScript and C# ports (which pdf.js, iText and HtmlUnit use) cannot reach it. The Go port (`andybalholm/brotli`) had the same logic error, but it could only crash, and it was fixed on 23 October. Rust's `brotli-decompressor` catches the condition and returns an error. Code execution is only possible in the C decoder. Bindings that wrap the C code (Java JNI wrappers, PHP and Ruby extensions, Go cgo bindings) are affected: look for a release that bundles 1.0.10, 1.1.1 or 1.2.1.

<a name="projects-that-bundle-their-own-copy"></a>

### Projects that bundle their own copy

Many projects ship a private copy of the C decoder instead of using the system library. A distribution update does not fix those: each project has to update its own copy, and this checker cannot see inside most of them. The lists below come from the survey at [broccoli2shell.com](https://broccoli2shell.com/), which searched GitHub for vendored copies and read their headers, last rechecked on 25 October 2026. A copy is patched if it includes the new `BLOCK_SWITCH` error code. Statuses change quickly, so check the project before you rely on one.

Not fixed yet, as of 25 October 2026:

| Project | Bundled copy | Untrusted input it decodes |
|---|---|---|
| [.NET runtime](https://github.com/dotnet/runtime) | 1.1.0 | `BrotliDecoder`, `BrotliStream`, `HttpClient` automatic decompression, and request bodies in ASP.NET Core apps that use the request decompression middleware |
| [DuckDB](https://github.com/duckdb/duckdb) | unpatched | Brotli-compressed Parquet files; fix in progress in [PR #27791](https://github.com/duckdb/duckdb/pull/27791) |
| [ClickHouse](https://github.com/ClickHouse/ClickHouse) | own fork | Brotli-compressed HTTP bodies, files and Parquet; fix in progress in [PR #127419](https://github.com/ClickHouse/ClickHouse/pull/127419) |
| [Apache Arrow](https://github.com/apache/arrow) (bundled build) | 1.0.9 | Brotli-compressed Parquet files; tracked in [issue #55166](https://github.com/apache/arrow/issues/55166) |
| [v8-jsi](https://github.com/microsoft/v8-jsi) | 1.2.0 | The same paths as Node.js, because it bundles Node.js |
| [7-Zip-zstd](https://github.com/mcmilk/7-Zip-zstd) | 1.2.0 | Archives and `.br` files a user opens; tracked in [issue #579](https://github.com/mcmilk/7-Zip-zstd/issues/579) |
| [p7zip](https://github.com/p7zip-project/p7zip) | 1.0.9 | Archives and `.br` files a user opens |
| [EDK II](https://github.com/tianocore/edk2) | 1.2.0 | Compressed firmware sections; tracked in [issue #13378](https://github.com/tianocore/edk2/issues/13378) |
| [woff2](https://github.com/google/woff2) (Makefile build) | 1.0.3 | WOFF2 fonts passed to `woff2_decompress`; the CMake build links the system library instead; tracked in [issue #207](https://github.com/google/woff2/issues/207) |

Fixed or fixed on the main branch since disclosure:

| Project | Fixed in | Details |
|---|---|---|
| [Ruby `brotli` gem](https://github.com/miyucy/brotli) | 0.9.1 | Bundles Brotli 1.2.1 and refuses to build against an unpatched system libbrotli (24 October) |
| [PHP brotli extension](https://github.com/kjdev/php-ext-brotli) | 0.21.1 | Bundles Brotli 1.2.1 (24 October) |
| [UEFITool](https://github.com/LongSoft/UEFITool) | A76 | Bundles Brotli 1.2.1 (24 October) |
| [MuPDF](https://github.com/ArtifexSoftware/mupdf) | 1.28.0 | Its Brotli fork picked up the upstream fix in April 2026, so every 1.28.x release is patched; 1.27.x still bundles the affected decoder |
| [NanaZip](https://github.com/M2Team/NanaZip) | main branch | Updated to Brotli 1.2.1 on 24 October; not in a release yet (latest is 7.0.1873.0) |
| [GraalJS (graal-nodejs)](https://github.com/oracle/graaljs) | master branch | Merged on 22 October; not in a release yet, since GraalVM ships security updates quarterly (latest is 25.4.4.1.1) |
| [YDB](https://github.com/ydb-platform/ydb) | main branch | Patched with the upstream fix on 23 October; not in a release yet |
| [libjxl](https://github.com/libjxl/libjxl) | main branch | Updated to Brotli 1.2.1 on 24 October; not in a release yet (latest is v0.12.0) |

Fixed before that survey was made: Node.js, Bun, Chromium, Firefox, `brotlicffi`, `ngx_brotli`, Brotli4j, SumatraPDF, Ghostscript, CatBoost and YTsaurus, as well as Gentoo, Solus and VMware Photon packages.

The survey is not complete. GitHub's code search skips submodules and some very large repositories, and private or vendored-at-build-time copies do not show up at all. A project listed here may not reach the decoder in every configuration. If you maintain one of these projects, updating to 1.0.10, 1.1.1 or 1.2.1 (or cherry-picking commit `0ed4268`) fixes it.

### Exploitation status

The Imperva Red Team ran attacker-supplied code on the official, unmodified Node.js 24.22.0 arm64 GNU/Linux image, delivering the payload both as a fetched response and as an Express request body. It took several attempts, and they have not released the exploit. A public proof of concept appeared on GitHub on 22 October; it reportedly reaches code execution only on a deliberately weakened build, and on standard builds causes a crash and a limited memory read. For Python, researchers confirmed the bug with AddressSanitizer (version 1.2.0 accepted a crafted stream of about 23 MB, and 1.2.1 rejected it with error -17) but did not attempt an exploit. As of 22 October no attacks in the wild had been reported. With public proofs of concept out, treat that as likely to change, and run `hunt` on exposed hosts.

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
| `check` (default) | Reports every `libbrotli` on the host (`libbrotlidec`, `libbrotlienc`, `libbrotlicommon`), the running processes that have `libbrotlidec` loaded (flagging any still running a library that was replaced on disk), the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, the Ruby `brotli` gem, the PHP `brotli` extension, Envoy, Istio, cdxgen), and `libbrotlidec` inside running containers, with whether each carries the fix. It also lists dotnet, duckdb and clickhouse if found on `PATH`, because they bundle an unfixed copy; that list is informational and does not affect the exit code. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable Brotli is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for process crashes that look like a Brotli decoder overflow: segfaults with `libbrotlidec`/`BrotliDecoder` frames, protection faults, heap corruption aborts, and services killed by a crash signal. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every command prints it on its first line too |

## Brotli checker patch detection

For a `libbrotli` installed from a Debian or Ubuntu package, the script judges it by the package build first (a built-in list of known fixed builds plus any you add with `FIXED_BUILDS`, then the package changelog naming `CVE-2026-111497`), because a distribution can backport the fix under an older upstream number. The built-in list already carries Debian 13's `brotli 1.1.0-2+deb13u1` (23 October 2026), so a patched trixie host reads as fixed without any configuration. For a self-built or bundled library it uses the upstream per-branch fix: 1.0.10 for the 1.0 branch, 1.1.1 for 1.1, 1.2.1 for 1.2. Runtimes are judged by their own fixed releases (Node.js 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; Istio 1.29.9 / 1.30.6 / 1.31.2; Python `brotli` 1.2.1; Python `brotlicffi` 1.2.1.0; Ruby `brotli` gem 0.9.1; PHP `brotli` extension 0.21.1; cdxgen 13.5.0 / 12.8.9). All of these are overridable with the environment variables documented in the script header.

## Brotli checker know before you run it

- **It is a check, not a fix, and not a mitigation.** The fix is to update `libbrotli` and the runtimes that bundle it, rebuild anything that embeds it, and restart. Unlike the ImageMagick coder policy for libheif, Brotli has no host-wide switch to turn off, so there is nothing safe for a script to write; disabling Brotli decoding is application-specific (see the paragraph above).
- **The decoder is the vulnerable path.** `libbrotlidec` is what matters; `libbrotlienc` and `libbrotlicommon` ship from the same package and are shown so you can see the whole install.
- **Distribution backports read correctly.** If you know a distro build is fixed and its changelog doesn't name the CVE, add it to `FIXED_BUILDS`.
- **Runtime detection reads the command line only.** It reports the versions of Node.js, Bun, Envoy and Istio it can run; it does not inspect every container image or embedded copy. Containers are read for `libbrotlidec` only, and only while running.
- **A Python Brotli binding is a live decode path just by being installed.** Python HTTP clients such as urllib3 and requests decode `Content-Encoding: br` on their own whenever `brotli` or `brotlicffi` is importable, so the risk is present wherever the package exists, not only where code calls a decode function. The checker imports both bindings (confirming each exposes a real `decompress`) and judges `brotli` per branch and `brotlicffi` against 1.2.1.0. Where you cannot upgrade yet, the interim mitigation is to uninstall `brotli` and `brotlicffi` so those clients fall back to gzip and deflate. Automated scanners such as Dependabot can miss these packages, because the CVE record names Google's Brotli repository rather than the PyPI packages, so check installed versions directly.
- **Versions below 1.0.3 are reported as not fixed.** The advisory's affected range starts at 1.0.3, but a copy older than that is unsupported and has no fixed release on its own branch, so the checker tells you to move to 1.0.10, 1.1.1 or 1.2.1.
- **The process check needs root to be complete.** It reads `/proc/*/maps`, so without root it only sees your own processes. A library mapped as deleted means the file was replaced after the process started: restart the process. Node.js, Bun and Python wheels carry their own copy and do not appear there, and neither do statically linked programs.
- **Bundled copies in other projects are mostly invisible to it.** The checker reads the Ruby gem and the PHP extension versions, and notes dotnet, duckdb and clickhouse when present. Everything else in [the list above](#projects-that-bundle-their-own-copy) has to be checked against the project. The PHP check reads the CLI's loaded extension only; PHP-FPM and Apache can load a different build.
- **For Node.js, this only reports the version.** The interim require-guard is the separate [Node.js mitigation](../node/README.md#nodejs-october-2026-interim-mitigation).
- **GNU/Linux only.** Library discovery and container inspection assume it.
- **A pre-release is not the release, and text is not a version.** A runtime that identifies itself as `24.22.1-pre`, `-rc.0`, `-dev` or `-nightly…` is a build made before 24.22.1, so at a fix version it is reported as unknown, not fixed. A `node`, `bun` or similar that prints something other than a version (an error message, a broken version-manager shim) is reported as unknown, never as newer than the fix.
- **Runtimes are found anywhere on `PATH`**, as well as in the usual install locations and the common version-manager directories.

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
