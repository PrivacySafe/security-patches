# Ruby and GitLab: Regexp and String case conversion CVEs

Part of the [PrivacySafe Security Patches](../README.md) collection.

## Ruby and GitLab Regexp and case conversion check

**Script:** [`ruby/ruby-regexp-oct2026-check.sh`](ruby-regexp-oct2026-check.sh)

On 23 October 2026 Ruby released [4.0.9, 3.4.12 and 3.3.13](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/), which fix memory corruption bugs in Onigmo, the engine behind Ruby's regular expressions. GitLab showed that a crafted pattern can turn them into remote code execution on a GitLab server, and published four CVEs: **CVE-2026-89078**, **CVE-2026-93577**, **CVE-2026-97229** and **CVE-2026-110264**. Two of them, CVE-2026-97229 and CVE-2026-110264, need no login, and CVE-2026-110264 affects every GitLab version from 7.0.

On 18 November 2026 Ruby released [4.0.10, 3.4.13 and 3.3.14](https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/) for seven more flaws in the same two areas, reported directly to Ruby rather than through GitLab, so none has a CVE yet: Ruby's advisory tracks them by GHSA ID until one is assigned to each. Five are in the regex engine (a double free compiling a character class intersection, two heap buffer overflows, an integer overflow and two out-of-bounds reads); two are in string case conversion (`String#upcase`/`downcase`/`capitalize`/`swapcase` and their bang forms), a one-byte overflow and an integer overflow when the converted result exceeds 4 GiB. Three are rated critical, three high, one moderate, and Ruby says it has seen working proof-of-concept code reaching remote code execution for six of the seven.

A Ruby application is exposed to the regex half if it compiles a pattern an attacker controls, through `Regexp.new`, `Regexp.compile`, `Regexp.union` or a literal such as `/#{input}/`; patterns your own developers wrote are not affected. The case-conversion half has no such narrowing: calling `.upcase`, `.downcase`, `.capitalize` or `.swapcase` on an attacker-influenced string is reached by code far more ordinary than pattern compilation, so an unfixed Ruby should be treated as exposed to it by default. Neither Ruby's October fixes nor its November fixes got a CVE of their own: the October ones are tracked by GitLab's four CVEs, the November ones by their GHSA IDs, so a scanner that follows Ruby CVEs shows nothing for either batch.

`Regexp.timeout` and length limits do not protect against any of these bugs, so the fix is to upgrade Ruby (and, for the October batch's GitLab CVEs, GitLab too). `check` finds what needs upgrading and reports whether it's fixed for October, November, both or neither; `scan` finds applications that compile patterns from strings, which narrows down the regex half only; and `hunt` looks for crashes that look like exploitation.

Self-hosted software that bundles its own Ruby needs that product's own update on its own schedule. As of 19 November 2026, public tracking (https://verialabs.com/ruby2shell/) showed the current release of GitLab, GitHub Enterprise Server, Mastodon, OpenProject, Discourse and Chatwoot all still running an unfixed Ruby. This script checks GitLab's and Discourse's bundled Ruby directly against the November thresholds; it has no install detection for GitHub Enterprise Server, Mastodon, OpenProject or Chatwoot, so check those directly against their own vendor's advisory. A few trackers have started calling the November batch "Ruby2Shell"; that name is not Ruby's own and this script does not rely on it.

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

**If you run GitLab, upgrade it first.** For GitLab's own CVE-2026-110264, the fixed releases are 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3 and 19.5.1. GitLab patched the Ruby it ships for that one, so upgrading the system `ruby` package does nothing for a GitLab install, and upgrading GitLab is the whole fix for it. That list says nothing about the November batch: as of 19 November 2026 no GitLab release bundles Ruby 4.0.10, 3.4.13 or 3.3.14, so this script checks GitLab's embedded Ruby binary directly to say whether that half is fixed, rather than relying on a GitLab version number that doesn't yet exist.

### Ruby commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every GitLab and Discourse install, every Ruby runtime on disk and every running Ruby process, with whether each is fixed. Flags processes still running a Ruby that was replaced on disk since they started. Changes nothing, root optional. Exits `0` if nothing running is exposed, `1` if unfixed Ruby is running or a bundled app is unfixed, `2` if some version couldn't be read |
| `scan` | Read-only. Finds application code that compiles regexps from strings, grouped by application, and grades each line (see [Ruby scan grades](#ruby-scan-grades)). Exits `0` if nothing needs review, `1` if something does, `2` if none of the scan paths exist (nothing was scanned) |
| `hunt` | Read-only log triage. Scans the journal, syslog, kernel log, GitLab's Puma, Sidekiq and Rails logs, and application logs under `/srv` and `/var/www`, for Ruby crash reports, Onigmo frames in backtraces, heap corruption aborts, services killed by a crash signal, and `RegexpError`. Exits `0` if nothing matched, `1` if it found something to look at, `2` if no journal or log could be read (nothing was searched) |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What the Ruby check looks at

1. GitLab. Omnibus installs under `/opt/gitlab`, source installs under `/home/git/gitlab`, and `gitlab/gitlab-ce` and `gitlab/gitlab-ee` images in Docker or Podman. The version comes from GitLab's own `VERSION` file or version manifest, or from the image tag. An image tagged `latest` can't be judged and is reported as unknown.
2. Discourse. The Docker launcher under `/var/discourse`, a bare-metal checkout under `/var/www/discourse` (or a user home, or `/srv/discourse`), and `discourse/discourse` and `discourse/base` images. Discourse has published no Discourse-version fix for these CVEs, so each install is judged by the Ruby it runs: a bare-metal checkout by its `.ruby-version`, the Docker launcher by the running web process, since that Ruby lives inside the container. Discourse compiles patterns from admin and user input (watched words, search, theme and automation settings), so an unfixed Ruby is reachable. This is the Ruby Regexp issue, separate from the Discourse `libheif` image-upload RCE, which is fixed by rebuilding the container, not by upgrading Ruby.
3. Ruby runtimes on disk. Everything on `PATH`, `/usr/bin/ruby*`, `/usr/local/bin/ruby`, chruby's `/opt/rubies`, and every user's rbenv, rvm, asdf, mise and chruby installs.
4. Vendor-bundled Rubies. Rubies that ship inside another product, under `/opt/*/embedded` (Chef, Fluentd, Vagrant and others) or `/opt/puppetlabs`, are listed but not judged by version: their fix comes from that vendor's update. GitLab's embedded Ruby is the one exception: it's judged both ways. GitLab's own product version is checked against GitLab's fixed releases for its own CVE-2026-110264 (above), and the embedded Ruby binary is also checked directly against the November thresholds, since no GitLab release bundles the November fix yet and GitLab's fixed-release list only ever tracked the October CVEs.
5. Running processes. Every process whose binary is a Ruby or that has `libruby` loaded, which catches Puma, Sidekiq and Unicorn under their own names, with its user and systemd unit. A process whose Ruby binary or `libruby` was replaced on disk since it started still runs the old code until you restart it.

The script reads each Ruby version from the description string compiled into the binary or into the `libruby` it links. It never executes a Ruby binary, so root never runs one planted in a user's version manager.

### Ruby patch detection

For each runtime, three checks run in order, and the first that applies decides:

1. `FIXED_BUILDS`. Distro builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. Changelog. For a Ruby installed from a Debian or Ubuntu package, the changelog of the interpreter package or of its `libruby` package names one of the seven November GHSA IDs (which counts as fixed for October too, since upstream's November release is built on top of October's fix) or, failing that, one of the four October GitLab CVEs (which counts as fixed for October only, not November). The changelog only counts if its newest entry is the installed version. Because neither batch has a CVE of its own, a distro may describe either fix without naming an identifier the script recognizes; if you know your build is fixed, add it to `FIXED_BUILDS`.
3. Upstream version. The runtime is at or above 3.3.14, 3.4.13 or 4.0.10 for its line: fixed for both batches. At or above 3.3.13, 3.4.12 or 4.0.9 but below that: fixed for October, still exposed to November. Below both: exposed to both. A line newer than 4.0 reads as unknown: check that the build includes both the October and November fixes.

GitLab's own product version is judged the same way against its fixed release for each minor line, for its own CVE-2026-110264: a minor line older than 18.11 moves to a fixed line, and a line newer than 19.5 shipped after the October fix and reads as fixed for it. That check says nothing about the November batch; GitLab's embedded Ruby binary is checked separately and directly against the November thresholds, since GitLab has not (as of this writing) shipped a release that bundles Ruby 4.0.10, 3.4.13 or 3.3.14.

### Ruby scan grades

`scan` searches `.rb`, `.rake`, `.erb`, `.haml`, `.slim` and `.ru` files and skips literal patterns. What's left gets one of two grades:

| Grade | Meaning |
|---|---|
| `review` | The pattern comes from a variable or expression. Trace where it comes from: if a user can set it (request parameters, CI configuration, saved filters, webhook payloads, search syntax), that application is exposed until its Ruby is fixed |
| `escaped` | The dynamic part goes through `Regexp.escape` or `Regexp.quote`, or it's a `Regexp.union` of strings, which escapes them. A much smaller surface that is still compiled, so still worth a look |

The protective fix lives in the application: stop compiling the user's text, or pass it through `Regexp.escape` so it is matched literally. GitLab's tree is skipped because GitLab is judged by its version. Installed gems and `vendor/bundle` are skipped by default because they are noisy. Set `SCAN_GEMS=1` to include them.

### Ruby hunting for exploitation

These bugs corrupt memory while a pattern compiles, so a failed attempt usually shows as a crashed worker rather than an application error. `hunt` reads the journal and logs, never changes anything, and reports:

- Ruby crash reports, the `[BUG] Segmentation fault` blocks Ruby prints when it dies;
- Onigmo and Regexp frames (`onig_compile`, `rb_reg_initialize`, `regparse.c` and others) in a backtrace;
- glibc heap corruption aborts such as `double free or corruption`;
- kernel segfault and protection fault lines from Ruby, Puma, Sidekiq and Unicorn processes;
- services killed by `SIGSEGV`, `SIGABRT` or `SIGBUS`;
- `RegexpError`, which someone probing patterns leaves behind.

`HUNT_SINCE` sets how far back it reads the journal, and `HUNT_LOGS` adds your own log files.

A match tells you exactly where to look. Native gems crash Ruby too, and `RegexpError` is ordinary when users type bad patterns. A crash with Onigmo frames on an unfixed Ruby, or a burst of `RegexpError` from one source just before a worker died, is worth treating as an incident: check what the process could reach and rotate it. On GitLab that includes runner registration tokens and CI/CD variables.

### Ruby configuration

| Variable | Default | Purpose |
|---|---|---|
| `RUBY_FIXED_33`, `RUBY_FIXED_34`, `RUBY_FIXED_40` | `3.3.14`, `3.4.13`, `4.0.10` | First release fixed for both the October and November batches, for each line |
| `RUBY_OCT_FIXED_33`, `RUBY_OCT_FIXED_34`, `RUBY_OCT_FIXED_40` | `3.3.13`, `3.4.12`, `4.0.9` | First release fixed for October only, for each line |
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

## Before you run it

- This is a check, not a mitigation. Upgrade GitLab, upgrade Ruby to 3.3.14, 3.4.13 or 4.0.10 (the release that fixes both batches), and restart what runs on it. Ruby 3.3 normally gets only security fixes; Ruby included both batches as an exception.
- No setting protects you. `Regexp.timeout` and length limits don't help the regex bugs, and there is no setting at all for the case-conversion bugs, since they trigger on ordinary string methods. Until you can upgrade, the only protective fix available for the regex half is in the application: don't compile patterns from untrusted input. The case-conversion half has no equivalent application-level mitigation; upgrading Ruby is the only fix.
- GitLab is fixed for its own CVE-2026-110264 by upgrading GitLab, not by upgrading the system Ruby. GitLab has not yet shipped a release bundling the November Ruby fix at all, so no GitLab upgrade currently closes that half; track GitLab's own advisories.
- Vendor-bundled Rubies need the vendor's update. The script lists most of them so you know they exist, and checks GitLab's and Discourse's bundled Ruby directly. It has no install detection for GitHub Enterprise Server, Mastodon, OpenProject or Chatwoot, all of which bundle Ruby the same way; as of 19 November 2026 all were still confirmed running an unfixed Ruby.
- Containers get their own fix. Each image carries its own Ruby. Rebuild on `ruby:3.3.14`, `3.4.13`, `4.0.10` or later. The script checks GitLab images by tag but can't see Rubies inside other images.
- `scan` is a grep, and only narrows down the regex-compilation half. It misses patterns built across several lines or in another file, and it can flag interpolated strings that aren't regexps. Use it to find where to look, not as a verdict. It has no equivalent for the case-conversion half, since case folding is too ordinary an operation to usefully triage by call site.
- GNU/Linux only. Process inspection reads `/proc`.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-03) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:88861](https://access.redhat.com/errata/RHSA-2026:88861) | 2026-10-23 | Critical | `ruby3.4-3.4.12-33.1.hum1` (Hummingbird) | CVE-2026-110264, CVE-2026-97229, CVE-2026-89078, CVE-2026-93577 |
| [RHSA-2026:88865](https://access.redhat.com/errata/RHSA-2026:88865) | 2026-10-24 | Critical | `ruby4.0-4.0.9-41.hum1` (Hummingbird) | CVE-2026-110264, CVE-2026-97229, CVE-2026-89078, CVE-2026-93577 |
| [RHSA-2026:88880](https://access.redhat.com/errata/RHSA-2026:88880) | 2026-10-24 | Critical | `ruby3.3-3.3.13-23.8.hum1` (Hummingbird) | CVE-2026-110264, CVE-2026-97229, CVE-2026-89078, CVE-2026-93577 |

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
