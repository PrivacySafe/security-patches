# BTCPay Server: hot wallet thefts on 2.4.1 and earlier (no CVE)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="btcpay-server-check"></a>

## BTCPay Server check

**Script:** [`btcpayserver/btcpayserver-nov2026-check.sh`](btcpayserver-nov2026-check.sh)

On **1 November 2026** the BTCPay Server project received reports of Bitcoin and Litecoin stolen from hot wallets. Its investigation found that the attacks targeted servers running **BTCPay Server 2.4.1 (released 23 July 2026) or earlier**, using a different method against the vulnerability that **2.4.2** fixed on 7 August. There is no CVE number, and the project has not published the method.

**The fix is not an update.** For a server that ran 2.4.1 or earlier, the project recommends moving to a **fresh server with a new wallet**, after sweeping what is left in the old hot wallet. That holds even if you saw no theft, and even if you updated after the project's warning, because updating cannot remove access an attacker may already have. The project has seen no impact on servers that were already on 2.4.2 or later when it warned operators at 22:25 UTC on 1 November.

This tool exists to get you through that recovery. It finds out whether it applies to you, walks you through it in order, saves your evidence before the old server goes, and fills in the report for the project. Hardening comes after that.

| | |
|---|---|
| Affected | BTCPay Server 2.4.1 and earlier, and any 2.4.2 release candidate (the August advisory covers those too) |
| Not affected by the project's account | Servers already on 2.4.2 or later when it warned; wallets whose keys are held off the server, such as hardware wallets (rebuilding is still recommended) |
| Fix | A fresh server, a new wallet, new credentials. Then keep BTCPay Server current: this script knows 2.4.7 as the newest release |
| CVE | None |

## What to do

1. **Find out.** Run `check`. It reads the version from containers, compose and env files, builds, or a server you reach by address.
2. **If it says exposed, run `recover`.** It prints the plan for your host, in the project's order:
   1. Make a new wallet with a new seed on a trusted device. Sweep what is left in the old hot wallet into it. Never reuse the old seed.
   2. Save the evidence with `preserve`, copy the archive off the host, then take the old server offline with `docker-compose -f "$BTCPAY_DOCKER_COMPOSE" stop`. That keeps the containers and their logs. `btcpay-down.sh` removes them and `btcpay-teardown.sh` erases the volumes, so use neither until the investigation is over.
   3. Provision a fresh server, install the latest release, connect the new wallet. Do not restore the old server onto it.
   4. From a trusted device, replace every credential the old server could reach: hosting, SSH, BTCPay Server logins and API keys, payment-plugin keys, SMTP and DNS, Lightning.
3. **Check your wallet history** for the destination addresses in the incident reports, which `recover` prints.
4. **Report** a loss or unauthorized access to security@btcpayserver.org, and to your local authorities. `recover` prints a report with your versions filled in. Never send seeds, keys or passwords.
5. **Then harden** the new server with `harden`.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/btcpayserver/btcpayserver-nov2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/btcpayserver/btcpayserver-nov2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less btcpayserver-nov2026-check.sh
   chmod +x btcpayserver-nov2026-check.sh
   ```

3. Check this host, then get the plan. Run as root on a Docker host to see containers, the deployment profile and listening ports.

   ```bash
   sudo ./btcpayserver-nov2026-check.sh check
   sudo ./btcpayserver-nov2026-check.sh recover
   sudo ./btcpayserver-nov2026-check.sh preserve --out /root
   ```

   To judge a server you cannot log in to, use its address:

   ```bash
   ./btcpayserver-nov2026-check.sh check --url https://pay.example.com
   ```

## Commands

| Command | What it does |
|---|---|
| `check [--url URL] [DIR ...]` (default) | Finds BTCPay Server in running or stopped containers (docker or podman), compose and env files, unpacked builds, or a live server through `--url`, and judges the version. Warns about older images still on disk, a container created after the project's warning, an update that ran after it, LND older than 0.21.1, and an LND API reachable from the network. |
| `recover [--url URL] [DIR ...]` | Runs `check`, then the verdict, then signs on the host (SSH access, custom fragments, the `btcpayserver-docker` checkout, server administrators) and, if the host is exposed or cannot be cleared, the recovery plan with this host's details (LND, Core Lightning, phoenixd, Tor, SSH keys) and a report to send the project. |
| `preserve [--out FOLDER] [LOGDIR ...]` | Writes one archive of logs and records so they survive when the old server is replaced. See below. |
| `hunt [LOGDIR ...]` | Reads web server logs (plain and `.gz`) and the logs of the BTCPay Server, LND and nginx containers for requests to the LND wallet setup and unlock routes, requests for `.macaroon` files, and the destination addresses from the incident reports. It covers the unlock, wallet-creation and state routes, over REST and gRPC, and reads the update log archives that `btcpay-update.sh` keeps. |
| `harden [--url URL] [DIR ...]` | Runs `check`, then reviews network-reachable ports, higher-exposure fragments, enabled LND routes, the IPv4 options filter, SSH settings, the keys in root's `authorized_keys`, custom fragments, the `btcpayserver-docker` checkout, the server administrators and Tor, and lists the steps that cannot be checked from here. |
| `tor [status\|enable\|disable]` | Reports whether Tor is enabled and explains the choice. `enable` and `disable` change the host after you confirm; `--dry-run` prints the plan. |
| `version` | Prints the script version |

`SCAN_CONTAINERS=0` skips docker and podman. `--profile FILE` names the deployment profile (default `/etc/profile.d/btcpay-env.sh`). `LOG_TAIL` sets how many log lines are read per container. `NO_COLOR` turns color off. `BTCPAY_BASE_DIRECTORY` names the `btcpayserver-docker` folder when it is not under `/opt`, `/srv` or the home directory; it is also read from the profile file, which `BTCPAY_FRAGMENTS_PROFILE` can point somewhere else. `TOR_SERVICES_DIR` is the folder with the Tor service's `hostname` files (default: the `generated_tor_servicesdir` Docker volume). `PSF_LOCK_WAIT` is the number of seconds a run that changes the host (`harden`, `tor`) waits for another one that is already changing it (default 30).

Exit codes: `0` nothing to act on, `1` an exposed version, a hunt hit, or a version that could not be read, `2` bad arguments, or a hunt that could not read every log.

`check`, `hunt` and `harden` run without root, but a plain account cannot read other users' files, root-only logs or the Docker socket, and the tool says what it missed. Commands that change the host (`tor enable`, `tor disable`) need root: run them with `sudo` from a named admin account, and the tool prints the exact `sudo` command if you forget.

## How to read the result

- **Exposed version** (`CRIT`, exit `1`): follow the plan above. Updating in place is not the fix.
- **Fixed version, created after the project's warning** (`WARN`): `recover` asks the one question that matters. If the host was already on 2.4.2 or later when the warning went out, the project has seen no impact: update to the newest release and harden. If it ran 2.4.1 or earlier and was updated after the warning, or you do not know, follow the plan.
- **Fixed version behind the newest** (`WARN`, exit `0`): update. This is routine, not a recovery.
- **A version that cannot be read** (a `latest` tag, no tag, or a build without `BTCPayServer.deps.json`): reported, exit `1`. Pin a version or use `--url`.
- **Older images still on disk** (`WARN`): a sign the host once ran an old version. Remove them once the host is rebuilt, and never start one again. An empty list tells you little, because `btcpay-update.sh` removes unused images by default.
- **A hunt that could not read a log is not clean.** A log that exists but belongs to root, or no log source at all, makes `hunt` say so and exit `2`. Run it with `sudo`.
- **A clean `hunt` is not clearance.** Its indicators come from the August flaw and the project's 2.4.4 report of bots probing LND routes. The project says the November attacks used a different method, so these logs may not show them. On a stack that blocks LND's unlock and wallet routes in nginx (2.4.4 and later), those requests are deliberately not written to the access log, so a clean result for them means little; LND's own container log is the better source. Logs also rotate, Docker keeps only a few megabytes per container by default, and an attacker can avoid logs altogether.
- **LND "invalid passphrase"** in a hunt is a warning, not an attack: some Docker nodes were left locked after updates on 11 to 14 September. The project's recovery guide is in its [Lightning Network FAQ](https://docs.btcpayserver.org/FAQ/LightningNetwork/#lnd-wallet-stays-locked-invalid-passphrase-for-master-public-key). Your funds are not lost.

## Signs on the host

An attacker who reached the application, or the host, tends to leave something that outlasts a rebuild of the containers. These checks run in `recover` and `harden`, and their findings go into the evidence archive.

- **Update history.** `btcpay-update.sh` saves the compose logs of the running stack to `btcpay-update-logs/update-<UTC time>.log.gz` before it replaces the containers, and keeps the five newest. Their names give the update times. An update after the project's warning (22:25 UTC on 1 November) is flagged, because a host that ran 2.4.1 or earlier and was updated after it still needs the fresh server. `hunt` also reads these archives, since they are the only logs that outlive a recreated container.
- **SSH access.** Before 2.4.4 the BTCPay Server container held a key that logged in to the host as root. The Docker deployment now installs a key limited to one command (`restrict,command=.../Generated/btcpay-host-proxy`, comment `btcpay-host`) and removes the old one (comment `btcpayserver`). The tool flags a legacy key, a `btcpay-host` key without that restriction, and a restricted key that runs a different command. It counts any other keys so you can confirm each is yours.
- **Custom fragments.** A `*.custom.yml` fragment adds containers and settings on every update, and Git ignores it. Each one is listed so you can confirm you wrote it.
- **The `btcpayserver-docker` checkout.** `btcpay-update.sh` pulls it and runs its scripts as root. The tool flags local changes (modified or new files, ignoring what Git ignores) and an `origin` that is not the project's repository, and records the commit.
- **Server administrators.** A read-only query (`SELECT` only, with the session set read-only) lists the accounts with the server administrator role and whether each uses two-factor sign-in. An address you do not recognize is a sign of unauthorized access.
- **Lightning.** LND older than 0.21.1, the version the August advisory called for, is flagged. Core Lightning and phoenixd on the host are named in the recovery plan next to LND.

## Preserve the evidence

The project asks you to keep relevant logs and transaction records before the old server is replaced. Container logs disappear with the containers, so run `preserve` first.

```bash
sudo ./btcpayserver-nov2026-check.sh preserve --out /root
```

It writes one `btcpay-evidence-HOST-TIME.tar.gz`, mode 0600, and never overwrites one. It contains host time and system details, recent logins, SSH key fingerprints, listening ports, container and image records, the logs of the BTCPay Server, LND, Core Lightning, phoenixd, nginx and other stack containers, the update log archives and `btcpay-update.log`, any web server logs it finds (name a folder to add one), the deployment profile, the findings above (including the list of server administrators), and a SHA-256 manifest.

It never contains wallet files, seeds, keys, macaroon files or databases. Values after words such as password, token, secret, seed and api key, authorization headers, macaroon values and very long hex strings are replaced with `[redacted]`. Redaction matches common patterns and cannot catch everything, so read the files before you share them. Transaction IDs and addresses are kept on purpose. Copy the archive off the host.

## For scheduled jobs and monitoring

Every command accepts two more options.

- `--strict` exits `1` on any warning as well as any `CRIT`, so a hardening finding fails a scheduled job. Without it only an exposed version, a hunt hit or an unreadable version exits `1`.
- `--json` prints one JSON document instead of text: `tool`, `version`, `command`, `host`, `strict`, `exit`, a `summary` of counts, `findings` (each with `level`, `section`, `message` and `suggest`), `advice`, `steps`, `report`, `manual` steps and `commands`. No color codes, nothing else on standard output. A usage error prints a small error object and exits `2`.

```bash
sudo ./btcpayserver-nov2026-check.sh check --json > /var/lib/node_exporter/btcpay-check.json
```

`--json` cannot be combined with `tor enable` or `tor disable`, which ask for confirmation, unless you add `--dry-run`.

## Harden the new server

`harden` prints a suggested command beside each warning. Nothing is applied for you. It matters most on the fresh server, which should start clean.

- **Ports.** The default Docker stack publishes only 80, 443 and the Lightning peer port. A published Bitcoin P2P port (`opt-expose-unsafe`), Bitcoin RPC, NBXplorer, PostgreSQL, Tor SOCKS or control, or DNS port is flagged, and so are LND 8080 and 10009.
- **Fragments.** `opt-expose-unsafe` and `opt-add-pihole` are warnings. Watchtower, Tor relay, public ElectrumX and Cloudflare Tunnel are noted.
- **LND routes.** The project turned off external LND API access by default after the August incident, and its reverse proxy blocks LND's unauthenticated wallet setup and unlock routes. If `lnd-rest` or `lnd-grpc` is enabled you are told how to remove it with `btcpay-routes`.
- **Host.** The IPv4 options filter, explicit SSH password or root logins, and a pending reboot.
- **Manual steps.** Hot wallet balance (keep only what daily operations need; the project's advice is to hold the rest in a wallet whose keys are off the server), two-factor sign-in, registration policy, API keys, LND password and macaroon rotation, backups, updates, firewall and monitoring.

The deployment profile is read as text and never run, so a modified profile cannot execute code through this tool.

## Tor: enable or disable

Since BTCPay Server 2.4.5 Tor is opt-in in the Docker deployment: it is no longer included by default, and a deployment that used it must select it again to keep its onion services (existing Tor data is kept in the Tor volumes).

```bash
./btcpayserver-nov2026-check.sh tor                  # state and guidance
./btcpayserver-nov2026-check.sh tor enable --dry-run # the plan, nothing changed
sudo ./btcpayserver-nov2026-check.sh tor disable
```

**Enable it** if the server sits behind NAT or a firewall you cannot change, or you want customers or point-of-sale devices to have an onion path. **Disable it** if you have a public domain with HTTPS and no need for onion access: it removes a container and the node's onion services.

Tor here is for reachability, not anonymity. The project's own fragment notes say it does not protect against a targeted attack on your privacy and that not all outbound traffic goes through Tor. Never share the BTC-P2P or BTC-RPC onion addresses, and never publish the Tor SOCKS (9050) or control (9051) ports. Disabling Tor breaks anything that uses the `.onion` addresses.

`tor enable` and `tor disable` are the only commands in `tor` that change a host, and like every tool here that changes a host they take `--dry-run` and `--yes`. They must run as root, find the project's own `btcpay-fragments` command, show exactly what they will run, and wait for you to type `yes` (or pass `--yes`). They run only `btcpay-fragments add opt-add-tor` or `btcpay-fragments remove opt-add-tor`. `--dry-run` prints the plan and changes nothing. Each change reapplies setup and briefly restarts services, so run `btcpay-backup.sh` first.

## Sources

- [Security Incident Affecting BTCPay Server 2.4.1 and Earlier, 2 November 2026](https://blog.btcpayserver.org/): the affected versions, the recovery steps, the timeline and the destination addresses. Look for the post under that title.
- [Security Advisory: Update BTCPay Server to 2.4.2 Immediately, 7 August 2026](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/): the flaw 2.4.2 fixed, and the LND credential risk.
- [BTCPay Server 2.4.4, 8 September 2026](https://blog.btcpayserver.org/btcpay-server-2-4-4/): LND wallet passwords, the blocked unauthenticated routes, restricted host management.
- [BTCPay Server 2.4.5, 5 October 2026](https://blog.btcpayserver.org/btcpay-server-2-4-5/): Tor becomes opt-in, `btcpay-routes`, the locked LND wallets.
- [btcpayserver-docker documentation](https://github.com/btcpayserver/btcpayserver-docker/tree/master/docs)
- To report a security issue to the project: security@btcpayserver.org

## Before you run it

- The fix. A fresh server and a new wallet for any host that ran 2.4.1 or earlier, then the newest release. The newest release this script knows is 2.4.7 (`NEWEST` at the top of the script).
- It reads and reports. Nothing is written, deleted, restarted or sent anywhere, except the one request `--url` makes, the one archive `preserve` writes, and `tor enable` or `tor disable` after you confirm.
- It cannot tell whether a host was already compromised. It judges versions and exposure, and looks for the indicators the project published. The project has not published how the November attacks worked.
- The two destination addresses sit in `IOC_ADDRESSES` at the top of the script. They are the ones the project's incident post lists. The project says some activity at them predates the thefts, so they are indicators and not a total of losses.
- Versions are read from the image tag, from `BTCPayServer.deps.json` in a build, or from `/api/v1/server/info` with `--url`. When none of them gives a version the tool says so and exits `1` instead of guessing.
- `ss` or `netstat`, and root, are needed for the full port review and for container logs.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`.

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
