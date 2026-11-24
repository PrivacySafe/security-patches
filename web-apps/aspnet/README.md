# Idunno.AntiCsrf: CVE-2026-131914 check, hunt and mitigation for IIS and Mono

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="idunno-anticsrf"></a>

## Idunno.AntiCsrf deserialization (ASP.NET WebForms on IIS and Mono)

**Scripts:** [`web-apps/aspnet/idunno-anticsrf-check.sh`](idunno-anticsrf-check.sh) for GNU/Linux (Mono), and [`web-apps/aspnet/idunno-anticsrf-check.ps1`](idunno-anticsrf-check.ps1) for Windows and IIS

This flaw is in an ASP.NET WebForms module. Most sites that use it run on IIS on Windows, and it is being exploited there, so there is a PowerShell tool for Windows. ASP.NET WebForms also runs on GNU/Linux under Mono (mod_mono in Apache, XSP, fastcgi-mono-server behind nginx), and Mono's `System.Web` behaves the same way: a module registered in `web.config` under this name loads and runs on every POST, and Mono's `ObjectStateFormatter` deserializes data with no MAC when it has no key, just like the .NET Framework's. So the bash tool covers Mono hosts, and both tools can search a share, a backup or a deployment tree. Whether the public .NET gadget chains also run under Mono has not been shown; treat a Mono host that registers the module as exposed.

`Idunno.AntiCsrf` is a small anti-CSRF module for ASP.NET WebForms, last released as `0.9.1 Beta` on CodePlex in December 2008. It has no maintainer and there will be no fix. On every `POST` to a WebForms page it hands the CSRF form field to an unkeyed `ObjectStateFormatter`, with no MAC and no type restriction, before the page itself runs. An attacker sends any non-empty CSRF cookie and a Base64 .NET gadget chain in the form field, and the code runs as the IIS worker process (`w3wp.exe`). One request, no login, no valid token.

| | |
|---|---|
| CVE | CVE-2026-131914 (CWE-502, deserialization of untrusted data) |
| Advisory | Mandiant [MNDT-2026-0048](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md), published 18 November 2026 |
| Severity | 9.3 Critical (CVSS 4.0, `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A`) |
| Affected | `Idunno.AntiCsrf.dll` 0.9.1.0 / 0.9.1 Beta, which is every release, and any recompiled or customized copy that keeps the same code |
| Fixed | Nothing. The remedy is to take the module out and use a supported anti-CSRF mechanism |
| Exploited | Yes. Mandiant observed exploitation during incident response; the details were not published |

**Who is at risk.** Any ASP.NET WebForms application that registers `Idunno.AntiCsrf.AntiCsrfModule` in a `Web.config`. Every anonymously reachable `.aspx` page exposes it, and so does any page that checks the user only inside `Page_Load`, because the module runs earlier. A page does not even need a `<form runat="server">`. Pages that implement `ISuppressCsrfCheck` or carry `[SuppressCsrfCheck]` are skipped by the module and are not exposed.

## Quick start (Windows and IIS)

1. Download the script and read it.

   ```powershell
   Invoke-WebRequest https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/web-apps/aspnet/idunno-anticsrf-check.ps1 -OutFile idunno-anticsrf-check.ps1
   notepad idunno-anticsrf-check.ps1
   ```

2. Check, from PowerShell opened with **Run as Administrator** so every site and the machine-wide configuration can be read. This changes nothing.

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\idunno-anticsrf-check.ps1 check
   ```

3. If a `Web.config` registers the module, see what `mitigate` would change, then apply it.

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\idunno-anticsrf-check.ps1 mitigate -DryRun
   powershell -ExecutionPolicy Bypass -File .\idunno-anticsrf-check.ps1 mitigate
   ```

4. Look for exploitation in the IIS logs and for files you did not put in the sites.

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\idunno-anticsrf-check.ps1 hunt
   ```

On GNU/Linux, with [PowerShell 7](https://github.com/PowerShell/PowerShell) installed, name the folders to search:

```bash
pwsh ./idunno-anticsrf-check.ps1 check -Roots /mnt/iis-share,/srv/backups/www
pwsh ./idunno-anticsrf-check.ps1 hunt -Roots /mnt/iis-share -LogDirs /mnt/iis-logs
```

## On GNU/Linux (Mono)

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/web-apps/aspnet/idunno-anticsrf-check.sh
less idunno-anticsrf-check.sh && chmod +x idunno-anticsrf-check.sh
sudo ./idunno-anticsrf-check.sh check
sudo ./idunno-anticsrf-check.sh mitigate --dry-run
sudo ./idunno-anticsrf-check.sh mitigate
sudo ./idunno-anticsrf-check.sh hunt
```

| Command | What it does |
|---|---|
| `check` (default) | Finds the Mono applications (mod_mono `MonoApplications` and `.webapp` files, `.webapp` files of XSP and mono-server, nginx server blocks that send `.aspx` to FastCGI, and running XSP and fastcgi-mono-server processes from their own `--applications`, `--root`, `--appconfigfile` and `--appconfigdir` arguments), then searches them and `ROOTS` for the DLL (by name, by Mandiant's hashes and by the module's own code in any DLL in a `bin` folder; an application DLL that only refers to the module's attributes is listed, not counted), every `web.config` that registers or names the module, Mono's machine-wide `web.config`, the Mono GAC and Mono's ASP.NET shadow copies (`<user>-temp-aspnet-*`), which show an application loaded the module even if it is gone now. Looks in running docker and podman containers too. Read-only. Exits `0` if nothing is found, `1` if something is, `2` if something could not be read or there was nothing to search |
| `hunt` | The module's `PotentialCsrfException` and `ObjectStateFormatter` errors in the Apache, nginx and Mono error logs and the journal; POST requests to `.aspx` pages answered with 500 (listed) and 302 (counted by client); pages, scripts and binaries changed in the applications in the last `HUNT_DAYS` days, marking pages that run commands or load code from the request. Read-only. Exits `0` if nothing is found, `1` for leads, `2` if no log could be read |
| `mitigate [--dry-run] [--restart]` | As root, removes the module's registrations from every `web.config` that has one (applications and Mono's machine-wide file). Needs `python3`. See below for how it writes |
| `rollback [--dry-run] [--restart]` | Puts back every file `mitigate` changed, with its original owner and mode |
| `version` | Prints the script version |

Environment: `ROOTS`, `MAX_DEPTH`, `APACHE_CONF_DIRS`, `NGINX_CONF_DIRS`, `WEBAPP_DIRS`, `MONO_CONF_DIRS`, `MONO_GAC_DIRS`, `SHADOW_DIRS`, `EXTRA_SHA256`, `HUNT_DAYS`, `HUNT_LOG_FILES`, `HUNT_ERROR_LOG_FILES`, `STATE_DIR`, `PSF_LOCK_WAIT`, `SCAN_CONTAINERS`.

**How `mitigate` writes.** A web root usually belongs to the web server's account, which could swap a `web.config` for a symbolic link while root is working on it. So nothing is written through a link: each file is opened without following links and checked to be a regular file, its copy is made from that same open file into a root-only folder, the edited text is checked as XML, and only a result that parses and registers nothing is written, to a new file created next to the original and renamed over it with the original owner and mode. A `web.config` that is a link is reported and left alone; `rollback` writes the same way and refuses a target that has become a link. `check` reports links without reading them.

**Restarting.** Mono's `System.Web` watches `web.config` and unloads an application when it changes, so the next request runs without the module. `--restart` also restarts Apache when it hosts mod_mono and every running service that runs XSP or a Mono FastCGI server, for a server where that watch is turned off.

## Windows commands


| Command | What it does |
|---|---|
| `check` (default) | Reads the IIS configuration (`applicationHost.config`, following IIS shared configuration through `redirection.config`) and each user's IIS Express configuration, and shows every site, application, application pool, pipeline mode and .NET version (a pool with No Managed Code runs no ASP.NET module). Searches each site and `-Roots` for `Idunno.AntiCsrf.dll` by name, by the three SHA-256 hashes Mandiant published, and by the module's own code in any DLL in a `bin` folder (an application DLL that only uses the module's attributes is listed, not counted); every `Web.config` that registers the module (`httpModules` for the Classic pipeline, `modules` for Integrated, also inside `<location>`) or still names it; the machine-wide `web.config` of each .NET version; the Global Assembly Cache; and the copies ASP.NET keeps in `Temporary ASP.NET Files`, which show an application loaded the module even if it is gone now. A `Web.config` that is a symbolic link is reported, never read. Changes nothing. Exits `0` if nothing is found, `1` if the module is registered or on disk, `2` if something could not be read |
| `hunt` | Reads the IIS W3C logs of the last `-Days` days (default 60) from the folders the IIS configuration names, plus `-LogDirs`, and lists `POST` requests to `.aspx` pages answered with `302` or `500` whose request size (`cs-bytes`) is at least `-MinBytes` (default 3000): the pattern Mandiant describes. Reads ASP.NET event 1309 in the Application log for errors that name the module or `ObjectStateFormatter`, lists shells and tools running now under `w3wp.exe`, and reads process creation events (4688) for the same where that auditing is on. Lists pages, scripts, binaries and configuration files changed in the sites in the same period and marks pages that run commands or load code from the request. Changes nothing. Exits `0` if nothing is found, `1` for leads, `2` if no log could be read or sizes were missing |
| `mitigate` | Removes every registration of the module from every `Web.config` that has one (sites, applications and the machine-wide files). Each file is copied to a dated folder under `%ProgramData%\PrivacySafe\idunno-anticsrf` first, edited as XML, read back, and restored from the copy if the registration is still there or the file no longer parses. A file that is not well-formed XML is left alone and reported. The DLL and the `csrfSettings` section stay, because pages may still refer to them. Takes a lock so two runs cannot overlap. `-DryRun` shows the files and writes nothing. Needs Administrator. Exits `0` when done or when there is nothing to do, `1` if a file could not be changed or was left alone, `2` for bad arguments or no rights |
| `rollback` | Puts back every `Web.config` the last `mitigate` saved (or the one in `-BackupDir`), byte for byte, and checks each parses. `-DryRun` shows what it would restore. Exits `0` when restored, `1` if a file could not be restored, `2` if there is no backup |
| `version` | Prints the script version |

Options: `-Roots`, `-ApplicationHostConfig`, `-WindowsDir`, `-IisExpressRoots`, `-LogDirs`, `-Days`, `-MinBytes`, `-StateDir`, `-BackupDir`, `-LockWait` (seconds to wait for another run, default 30), `-ExtraSha256` (more DLL hashes, as they are published) and `-DryRun`. `mitigate` and `rollback` leave a `Web.config` that is a symbolic link or junction alone. `-Help` prints the full usage.

## What `mitigate` changes, and what it does not

IIS restarts an application by itself when its `Web.config` changes, so `mitigate` takes effect at once and the sites it touches restart: sessions held in process are lost. After it, the module no longer runs, so the deserialization no longer happens, and neither does the module's CSRF check. Pages that relied on it are open to cross-site request forgery until you put a supported mechanism in place:

- `System.Web.Helpers.AntiForgery` (`AntiForgery.GetHtml()` in the form and `AntiForgery.Validate()` on `POST`), from `System.Web.WebPages`
- `Page.ViewStateUserKey` set per user, with MAC-checked (and preferably encrypted) ViewState on every postback form
- on ASP.NET Core, the built-in anti-forgery service (`IAntiforgery`)

Then finish what Mandiant recommends: delete `Idunno.AntiCsrf.dll` from each `bin` folder, the `<section name="csrfSettings">` declaration and the `<csrfSettings>` element, and any code that refers to `ISuppressCsrfCheck` or `[SuppressCsrfCheck]`. Run `check` again until it finds nothing.

## If you were exposed

1. Run `mitigate` (or remove the module by hand) before anything else.
2. Run `hunt`. A large `POST` to a `.aspx` page answered with `302` or `500`, from an address you do not know, is what exploitation looks like. Without `cs-bytes` in the logs the size is unknown: turn on the "Bytes Received" field in IIS logging.
3. If anything points to exploitation, treat the server as compromised. Rotate every secret in `Web.config` and `applicationHost.config`, including the `<machineKey>`, encryption keys and database passwords, from another machine. Look in the sites for files you did not put there, and rebuild the server if you cannot account for them.

## Before you run it

- It needs Windows PowerShell 5.1 or PowerShell 7, nothing else. It reads the IIS configuration as XML and does not need the IIS PowerShell modules.
- Without Administrator, `check` and `hunt` see only what this account can read and say so; `mitigate` and `rollback` refuse to run.
- `hunt` reads W3C logs. Logs in another format, or sent elsewhere, are yours to search for the same pattern.
- The file hashes cover Mandiant's three known builds. A copy you built yourself is found by its assembly name, and its registration is found in `Web.config` whatever its name.

Sources: Mandiant's advisory [MNDT-2026-0048](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md), the [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-131914), the [archived CodePlex project](https://web.archive.org/web/20100129114934/http://anticsrf.codeplex.com/) and the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). Status current on 23 November 2026.

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
