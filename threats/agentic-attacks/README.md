# AI-driven attack frameworks: indicators of compromise on GNU/Linux hosts

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="agentic-attacks"></a>

## Agentic attack frameworks: check and hunt

**Script:** [`threats/agentic-attacks/agentic-attack-check.sh`](agentic-attack-check.sh), with its indicator list [`indicators.tsv`](indicators.tsv)

Agentic attack frameworks hand an intrusion to a team of AI agents: a planner decides what to try next, worker agents run nmap, curl, sqlmap, Metasploit and the rest, and every result feeds the next step. They were published for authorized testing. Since August 2026, state-aligned and criminal groups have used them against cloud accounts, identity providers, web applications and internal networks. There is no CVE and nothing to patch: they use weaknesses that are already there, at machine speed.

<a name="artex"></a>

| Framework | What it is | Seen in attacks |
|---|---|---|
| ARTEX | A Go multi-agent pentest platform with a web console (port 8787); forks include ScopeWeaver, AntiFox and LUCK | Since August 2026 by Storm-0940, Storm-3358, VAPOR PANDA and criminal groups; FBI FLASH-20261113-001. Backdoored images on Docker Hub (`tomicdd/artex`, `congdonglinux/artex`) hand the host that runs them to a third party |
| CAIRN | A multi-agent OODA loop (observe, orient, decide, act) whose agents share a "blackboard" | Google GTIG saw it in intrusions against targets including US aerospace |
| CyberStrikeAI | A Go backend that acts as command-and-control and orchestration, connecting language models to more than 100 tools and YAML attack recipes, with implants | Exposed consoles counted from September; implants for Windows, macOS and GNU/Linux |
| HexStrike AI | An MCP server that gives an AI client more than 150 offensive tools and a dozen sub-agents | Used to speed up exploitation of fresh flaws |
| PentAGI | An autonomous offensive framework for less experienced operators | GTIG tracked a customized build scanning organizations across Asia from late August to early October 2026; about 400 exposed consoles |
| Strix, Hermes, RedAmon, Xalgorix, PentestSwarm, Agent Zero | Other agentic offensive frameworks and harnesses | Exposed consoles and intrusion reports through November 2026 |

A GNU/Linux host meets them three ways, and the tool looks at each: as an **operator's host** (a framework, its console, container or MCP server runs here, or a backdoored copy does), as a **victim** (what the agents leave on disk and in logs), and as a **target** (the weaknesses the agents look for first).

## Quick start

1. Download the script and its indicator list into one folder. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   BASE=https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   curl -fLO "$BASE/threats/agentic-attacks/agentic-attack-check.sh"
   curl -fLO "$BASE/threats/agentic-attacks/indicators.tsv"
   ```

2. Read the script before running it, then make it executable.

   ```bash
   less agentic-attack-check.sh
   chmod +x agentic-attack-check.sh
   ```

3. Check this host, then hunt. Both only read; as root they see every container, process, account and log.

   ```bash
   sudo ./agentic-attack-check.sh check
   sudo ./agentic-attack-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Images and containers of the frameworks in docker and podman; consoles answering on this host's own web ports, recognized by page text or by the Shodan-style favicon hash, asked over loopback; running processes whose command line names a framework or whose environment holds one of its variables (names only, never values); framework files and folders under `SEARCH_ROOTS` and in home folders; files whose SHA-256 or MD5 is a published one; AI clients (Claude, Cursor, Codex, VS Code, goose, Gemini) configured with an offensive MCP server or provider; accounts named after a framework; and the weaknesses the agents use on a host: source maps and runtime configuration in web folders, MySQL and MariaDB logs pointed into a web folder, and an empty `secure_file_priv`. Exits `0` if nothing is found, `1` for a finding or something to look at, `2` if the indicator list cannot be read |
| `hunt` | Web access logs (compressed too) for the frameworks' user agents, probe requests, header names, marker strings and source addresses; the auth log, syslog and the journal for published addresses and domains; web folders for the file names the agents leave and for marker strings; shell histories, cron and systemd units; and, running now, shells and download tools started by a web or database service, and connections to published addresses. Exits `0` if nothing is found, `1` for leads, `2` if no log could be read |
| `list` | Counts the indicators by framework and type |
| `export TYPE [--min high\|medium\|low]` | Prints `ips`, `domains`, `user-agents`, `hashes`, `images` or `strings`, one per line, for a firewall, WAF, proxy or SIEM. Default `--min medium`. Changes nothing |
| `version` | Prints the script version |

Environment: `INDICATORS_FILE`, `FRAMEWORKS` (for example `FRAMEWORKS="cairn pentagi"`), `WEB_ROOTS`, `SEARCH_ROOTS`, `HOME_DIRS`, `MAX_DEPTH`, `HASH_MAX_FILES`, `HUNT_LOG_FILES`, `HUNT_SYS_LOG_FILES`, `HUNT_DAYS` (default 120), `PROBE_PORTS`, `MYSQL_CNF_DIRS`, `MYSQL_QUERY`, `SCAN_CONTAINERS`.

## How to read the result

Every indicator carries a confidence. A **high** one (a user agent that names the tool, a backdoored image, a published implant hash, a marker string) is a finding. A **medium** one (a framework's own image, a console title, an address from a report) is a lead: the framework may be an authorized tester's, and an address may have changed hands. A **low** one (a user agent or name that ordinary tools share, such as `claude-cli` or a common scanner) is counted and never acted on.

A match needs investigation, and no match proves nothing. Most addresses belong to hosting providers and are reassigned within days: use them to look back over August to November, and block them only after checking your own traffic. The agents choose many names at run time, so the behavior lasts longer than any string: a web or database service starting a shell, a script written into a web folder, a server posting to a request-collection service.

The tool reads files under `SEARCH_ROOTS`, `WEB_ROOTS` and home folders as root, so it never follows a symbolic link: a link planted there is not read, and nothing is written anywhere. It leaves itself and its indicator list out of every search.

## If you find something

1. Keep the evidence first: access logs, the journal, shell histories, and any container's image and layers.
2. A request is reconnaissance; a web shell, a new account, an implant or a shell under the web server is an incident.
3. A backdoored image or a published implant: take the host off the network, rebuild it, and rotate every secret it held.
4. A framework or console nobody can account for: find who installed it. An authorized test should be on record.
5. Report it: the FBI asks for ARTEX reports to a field office or at [ic3.gov](https://www.ic3.gov/).

## Closing the gaps the agents look for

- Take source maps and runtime configuration off production web servers.
- Give the database account the application uses no FILE privilege, set `secure_file_priv` to a dedicated folder (or to NULL), and keep MySQL's logs outside every web folder.
- Stop servers calling out freely: a web or database server that cannot reach request-collection or tunnel services cannot send results back that way.
- Pull container images only from publishers you know, and pin them by digest.
- Keep consoles and MCP servers off public addresses; an exposed one is how the surveys counted them.

## The indicator list

[`indicators.tsv`](indicators.tsv) has one indicator per line: framework, type, confidence, value, source and date reported. Most rows come from ThreatDefence's [agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections) indicator list, which is under the MIT license; the file keeps that copyright and license notice in its header, as the license requires. The rest come from Wiz's table of addresses used with stolen credentials and from a public survey of exposed consoles. The script that reads it is CC0 and was written for this collection; none of that project's rules or code are used. To add an indicator, add a line in the same format.

Sources: the FBI's [FLASH-20261113-001](https://www.ic3.gov/) on ARTEX; Google Threat Intelligence Group, *ARTEX and Friends: Enter Agentic Offensive Frameworks* and the *GTIG AI Threat Tracker*; Wiz, *Agentic Attacks in the Wild*; ThreatDefence's [ARTEX advisory](https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting) and [indicator list](https://github.com/ThreatDefence/agentic-attack-detections); and the public surveys of exposed ARTEX, CAIRN and PentAGI consoles. Status current on 23 November 2026.

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
