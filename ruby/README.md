# Ruby and GitLab: Regexp CVEs

Part of the [PrivacySafe Security Patches](../README.md) collection.

## Ruby and GitLab Regexp Check

**Script:** [`ruby/ruby-regexp-oct2026-check.sh`](ruby-regexp-oct2026-check.sh)

On 23 October 2026 Ruby released [4.0.9, 3.4.12 and 3.3.13](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/), fixing memory corruption bugs in Onigmo, the engine that compiles Ruby's regular expressions. GitLab found that a crafted pattern could turn them into remote code execution on GitLab servers, and published four CVEs: **CVE-2026-89078**, **CVE-2026-93577**, **CVE-2026-97229** and **CVE-2026-110264**. Two of them, CVE-2026-97229 and CVE-2026-110264, need no login, and CVE-2026-110264 affects every GitLab version from 7.0.

Any Ruby application is exposed if it compiles a pattern an attacker controls: through `Regexp.new`, `Regexp.compile` or `Regexp.union`, or by interpolating it into a literal such as `/#{input}/`. Regexps written by the application's own developers are not affected. Ruby requested no CVEs of its own for these fixes, so a scanner that tracks Ruby CVEs reports nothing; track the GitLab CVEs instead.

There is no switch to turn these bugs off. Ruby says `Regexp.timeout` doesn't protect against them, and limiting pattern length doesn't reliably either, because some are triggered by short patterns. Interpolated literals compile without passing through any method a guard could wrap, so unlike the Node.js section there is no in-process guard. This script is read-only. It finds what needs upgrading, which applications compile patterns from strings, and whether anything has crashed in a way that looks like exploitation.

### Ruby quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/ruby/ruby-regexp-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/ruby/ruby-regexp-oct2026-check.sh
   ```

2. Read it before running it. Always.

   ```bash
   less ruby-regexp-oct2026-check.sh
   ```

3. Make it executable.

   ```bash
   chmod +x ruby-regexp-oct2026-check.sh
   ```

4. See what's exposed. Root is optional, but without it you won't see other users' Rubies and processes.

   ```bash
   sudo ./ruby-regexp-oct2026-check.sh check
   ```

5. Find the code that compiles patterns from strings. Point `SCAN_PATHS` at your application roots if they live somewhere else.

   ```bash
   sudo SCAN_PATHS="/srv /var/www" ./ruby-regexp-oct2026-check.sh scan
   ```

6. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./ruby-regexp-oct2026-check.sh hunt
   ```

To confirm GitHub and Codeberg serve the same file, compare checksums:

```bash
sha256sum ruby-regexp-oct2026-check.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/ruby/ruby-regexp-oct2026-check.sh | sha256sum
```

**If you run GitLab, upgrade it first.** The fixed releases are 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3 and 19.5.1. GitLab patched the Ruby it ships, so upgrading the system `ruby` package does nothing for a GitLab install, and upgrading GitLab is the whole fix for it.

### Ruby commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every GitLab and Discourse install, every Ruby runtime on disk and every running Ruby process, with whether each is fixed. Flags processes still running a Ruby that was replaced on disk since they started. Changes nothing, root optional. Exits `0` if nothing running is exposed, `1` if unfixed Ruby is running or a bundled app is unfixed, `2` if some version couldn't be read |
| `scan` | Read-only. Finds application code that compiles regexps from strings, grouped by application, and grades each line (see [Ruby scan grades](#ruby-scan-grades)). Exits `0` if nothing needs review, `1` if something does, `2` if none of the scan paths exist (nothing was scanned) |
| `hunt` | Read-only log triage. Scans the journal, syslog, kernel log, GitLab's Puma, Sidekiq and Rails logs, and application logs under `/srv` and `/var/www`, for Ruby crash reports, Onigmo frames in backtraces, heap corruption aborts, services killed by a crash signal, and `RegexpError`. Exits `0` if nothing matched, `1` if it found something to look at, `2` if no journal or log could be read (nothing was searched) |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What the Ruby check looks at

1. **GitLab.** Omnibus installs under `/opt/gitlab`, source installs under `/home/git/gitlab`, and `gitlab/gitlab-ce` and `gitlab/gitlab-ee` images in Docker or Podman. The version comes from GitLab's own `VERSION` file or version manifest, or from the image tag. An image tagged `latest` can't be judged and is reported as unknown.
2. **Discourse.** The Docker launcher under `/var/discourse`, a bare-metal checkout under `/var/www/discourse` (or a user home, or `/srv/discourse`), and `discourse/discourse` and `discourse/base` images. Discourse has published no Discourse-version fix for these CVEs, so each install is judged by the Ruby it runs: a bare-metal checkout by its `.ruby-version`, the Docker launcher by the running web process, since that Ruby lives inside the container. Discourse compiles patterns from admin and user input (watched words, search, theme and automation settings), so an unfixed Ruby is reachable. This is the Ruby Regexp issue, separate from the Discourse `libheif` image-upload RCE, which is fixed by rebuilding the container, not by upgrading Ruby.
3. **Ruby runtimes on disk.** Everything on `PATH`, `/usr/bin/ruby*`, `/usr/local/bin/ruby`, chruby's `/opt/rubies`, and every user's rbenv, rvm, asdf, mise and chruby installs.
4. **Vendor-bundled Rubies.** Rubies that ship inside another product, under `/opt/*/embedded` (Chef, Fluentd, Vagrant and others) or `/opt/puppetlabs`, are listed but not judged by version: their fix comes from that vendor's update. GitLab's embedded Ruby is judged by the GitLab version, since GitLab patched it.
5. **Running processes.** Every process whose binary is a Ruby or that has `libruby` loaded, which catches Puma, Sidekiq and Unicorn under their own names, with its user and systemd unit. A process whose Ruby binary or `libruby` was replaced on disk since it started still runs the old code until you restart it.

The script reads each Ruby version from the description string compiled into the binary or into the `libruby` it links. It never executes a Ruby binary, so root never runs one planted in a user's version manager.

### Ruby patch detection

For each runtime, three checks run in order, and the first that applies decides:

1. **`FIXED_BUILDS`.** Distro builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. **Changelog.** For a Ruby installed from a Debian or Ubuntu package, the changelog of the interpreter package or of its `libruby` package names one of the four GitLab CVEs. The changelog only counts if its newest entry is the installed version. Because Ruby requested no CVEs, a distro may describe the fix without naming them; if you know your build is fixed, add it to `FIXED_BUILDS`.
3. **Upstream version.** The runtime is at or above the fixed release for its line: 3.3.13, 3.4.12 or 4.0.9. Older lines got no fixed release, so they read as not fixed. A line newer than 4.0 reads as unknown: check that the build includes ruby/ruby#13332, #19020 and #16801.

GitLab is judged the same way against its fixed release for each minor line. A minor line older than 18.11 got no fixed release; a line newer than 19.5 shipped after the fixes and reads as fixed.

### Ruby scan grades

`scan` searches `.rb`, `.rake`, `.erb`, `.haml`, `.slim` and `.ru` files and skips literal patterns. What's left gets one of two grades:

| Grade | Meaning |
|---|---|
| `review` | The pattern comes from a variable or expression. Trace where it comes from: if a user can set it (request parameters, CI configuration, saved filters, webhook payloads, search syntax), that application is exposed until its Ruby is fixed |
| `escaped` | The dynamic part goes through `Regexp.escape` or `Regexp.quote`, or it's a `Regexp.union` of strings, which escapes them. A much smaller surface that is still compiled, so still worth a look |

The interim fix lives in the application: stop compiling the user's text, or pass it through `Regexp.escape` so it is matched literally. GitLab's tree is skipped because GitLab is judged by its version. Installed gems and `vendor/bundle` are skipped by default because they are noisy; set `SCAN_GEMS=1` to include them.

### Ruby hunting for exploitation

These bugs corrupt memory while a pattern compiles, so a failed attempt usually shows as a crashed worker rather than an application error. `hunt` reads the journal and logs, never changes anything, and reports:

- Ruby crash reports, the `[BUG] Segmentation fault` blocks Ruby prints when it dies;
- Onigmo and Regexp frames (`onig_compile`, `rb_reg_initialize`, `regparse.c` and others) in a backtrace;
- glibc heap corruption aborts such as `double free or corruption`;
- kernel segfault and protection fault lines from Ruby, Puma, Sidekiq and Unicorn processes;
- services killed by `SIGSEGV`, `SIGABRT` or `SIGBUS`;
- `RegexpError`, which someone probing patterns leaves behind.

`HUNT_SINCE` sets how far back it reads the journal, and `HUNT_LOGS` adds your own log files.

A match is a lead, not proof. Native gems crash Ruby too, and `RegexpError` is ordinary when users type bad patterns. A crash with Onigmo frames on an unfixed Ruby, or a burst of `RegexpError` from one source just before a worker died, is worth treating as an incident: check what the process could reach and rotate it. On GitLab that includes runner registration tokens and CI/CD variables.

### Ruby configuration

| Variable | Default | Purpose |
|---|---|---|
| `RUBY_FIXED_33`, `RUBY_FIXED_34`, `RUBY_FIXED_40` | `3.3.13`, `3.4.12`, `4.0.9` | First fixed release for each line |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro builds, space-separated full versions |
| `GITLAB_FIXED` | `18.11.13 19.0.10 19.1.9 19.2.9 19.3.6 19.4.3 19.5.1` | First fixed GitLab release for each minor line |
| `GITLAB_ROOT` | `/opt/gitlab` | Where Omnibus GitLab is installed |
| `DISCOURSE_ROOT` | `/var/discourse` | Where the Discourse Docker launcher lives |
| `DISCOURSE_APP` | `/var/www/discourse` | Where a bare-metal Discourse checkout lives |
| `SCAN_PATHS` | `/srv /opt /var/www /home /usr/local/lib` | Where `scan` looks for code |
| `SCAN_DEPTH` | `10` | How deep `scan` goes |
| `SCAN_GEMS` | `0` | `1` also scans installed gems and `vendor/bundle` |
| `SCAN_SHOW` | `5` | Findings printed per application and grade |
| `HUNT_SINCE` | `2026-09-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### Ruby know before you run it

- **This is a check, not a mitigation.** Upgrade GitLab, upgrade Ruby to 4.0.9, 3.4.12 or 3.3.13, and restart what runs on it. Ruby 3.3 normally gets only security fixes; Ruby says it included these as an exception.
- **No setting protects you.** `Regexp.timeout` and length limits don't. Until you can upgrade, the only interim fix is in the application: don't compile patterns from untrusted input.
- **GitLab is fixed by upgrading GitLab**, not by upgrading the system Ruby.
- **Vendor-bundled Rubies need the vendor's update.** The script lists them so you know they exist.
- **Containers get their own fix.** Each image carries its own Ruby; rebuild on `ruby:3.3.13`, `3.4.12`, `4.0.9` or later. The script checks GitLab images by tag but can't see Rubies inside other images.
- **`scan` is a grep.** It misses patterns built across several lines or in another file, and it can flag interpolated strings that aren't regexps. Use it to find where to look, not as a verdict.
- **GNU/Linux only.** Process inspection reads `/proc`.

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
