# Apache Pulsar: CVE-2026-105869, CVE-2026-105942 and Pulsar Manager CVE-2026-105944

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="pulsar-check"></a>

## Apache Pulsar check

**Script:** [`pulsar/pulsar-check.sh`](pulsar-check.sh)

The Apache Pulsar PMC published **14 advisories on 21 October 2026**, all fixed in **4.0.14, 4.2.5 and 5.0.0**, and a separate advisory for **Pulsar Manager**, which has reached end of life. This tool covers three of them, the ones whose exposure depends on configuration or on what is installed.

| | CVE-2026-105869 | CVE-2026-105942 | CVE-2026-105944 |
|---|---|---|---|
| Component | Broker | Broker | **Pulsar Manager** |
| Severity | Critical, CVSS 4.0 9.2 | High, 7.7 | **Critical, CVSS 4.0 10.0** |
| Affected | 2.8.1 before 4.0.14, and 4.1.0 before 4.2.5 | 2.8.1 before 4.0.14, and 4.1.0 before 4.2.5 | 0.1.0 through 0.4.0, **every release** |
| Fixed | 4.0.14, 4.2.5, 5.0.0 | 4.0.14, 4.2.5, 5.0.0 | **No fix, and none will ship**: the Pulsar PMC retired the project |
| What | With `MultiRolesTokenAuthorizationProvider` and a **non-empty `anonymousUserRole`**, HTTP and WebSocket requests whose credentials fail authentication fall back to the anonymous role, and the provider authorizes them with the roles in the **unverified** bearer token. A forged or unsigned token can claim a superuser role. The binary protocol is not affected | For requests a proxy sends on behalf of a user, the broker authorized the original principal with the proxy's own authentication data. With `MultiRolesTokenAuthorizationProvider` the user gains the roles in the proxy's token; whatever the provider, the tenant admin check of a proxied admin REST request passed without checking the original principal when the proxy role was a tenant admin | In 0.3.0 and later anyone who can reach it over the network can take full control (the call that creates the first administrator needs no authentication and stays available after setup). In all versions, when it holds an HTTP authentication credential for a cluster, any user who can reach it can perform the admin operations that credential permits, and can make it send the credential to a host of their choosing |
| Needs | `MultiRolesTokenAuthorizationProvider`, non-empty `anonymousUserRole`, authorization enabled | `proxyRoles` set, authorization enabled | Pulsar Manager installed and reachable |

**None of the two broker flaws is reachable on a default broker.** Pulsar's shipped `broker.conf` has `authenticationEnabled=false`, `authorizationEnabled=false`, an empty `anonymousUserRole` and an empty `proxyRoles`.

The other twelve advisories in the 21 October announcement (cross-tenant access, missing authorization checks and similar) are fixed by the same upgrade. They are not counted separately here.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/pulsar/pulsar-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pulsar/pulsar-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less pulsar-check.sh
   chmod +x pulsar-check.sh
   ```

3. Check this host. By default it searches `/opt /srv /usr/local /var/lib /etc /home /root`; pass directories to narrow it.

   ```bash
   ./pulsar-check.sh check
   ./pulsar-check.sh check /opt/pulsar
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds brokers by their jars (`pulsar-broker-X.Y.Z.jar` and `org.apache.pulsar-pulsar-broker-X.Y.Z.jar`), reads `conf/broker.conf` and `conf/standalone.conf` beside each, scans `broker.conf`, `standalone.conf`, compose files, Helm `values*.yaml` and `*.env` files for the exposing settings, and looks for Pulsar Manager (jars, running processes, listeners on 7750 and 9527, container images) |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected broker with an exposing configuration (or whose configuration could not be read), an exposing configuration of unknown version, or Pulsar Manager present, `2` bad arguments.

## How to read the result

- **Broker in an affected range and the exposing settings present:** exposed. Upgrade to 4.0.14, 4.2.5 or 5.0.0 or newer. Until then (our reasoning, not the vendor's): empty `anonymousUserRole`, do not expose the HTTP and WebSocket ports to untrusted clients, and keep the broker behind the proxy with strict network rules.
- **Affected range, no exposing settings:** exit `0` with a reminder that the upgrade is still needed.
- **Affected broker with no `conf/` beside it:** unverified, exit `1`. The settings may come from environment variables or a mounted file.
- **A fixed broker** (4.0.14 and later, 4.2.5 and later, 5.0.0 and later) is fine even if its configuration contains the settings: the check is on the version, and the file is not flagged separately.
- **Versions older than 2.8.1:** the two configuration-dependent flaws start at 2.8.1, but those releases are unsupported and affected by other advisories in the set: upgrade.
- **Containers:** a compose file or Helm values file with the exposing settings is reported without a version, because the image is not opened. Check the tag: below 4.0.14, any 4.1.x, or 4.2.x below 4.2.5 is exposed.
- **Pulsar Manager, any version, any state:** stop and remove it. There will be no fix. If it was reachable from a network you do not fully trust, treat the Pulsar credential or token signing key it held as compromised and replace it, and check its user list for administrators you did not create. The Pulsar documentation lists alternatives: https://pulsar.apache.org/docs/administration-ui

## Sources

- [Advisory for CVE-2026-105869](https://pulsar.apache.org/security/CVE-2026-105869/)
- [The Pulsar PMC's combined announcement of 14 CVEs (oss-security)](https://seclists.org/oss-sec/2026/q4/296)

## Apache Pulsar know before you run it

- **This is a check, not a fix.** Brokers: update to 4.0.14, 4.2.5 or 5.0.0. Pulsar Manager has no fix and will not get one: the Pulsar PMC retired it, and the advice is to stop using it and remove it.
- **The broker flaws depend on configuration.** Neither CVE-2026-105869 nor CVE-2026-105942 is reachable on a default broker: authentication, authorization, `anonymousUserRole` and `proxyRoles` are off or empty by default. The script reads `broker.conf`, `standalone.conf`, configuration, compose, Helm and env files for the exposing settings.
- **It does not open container images.** For containers it reads the files beside them and tells you to check the tag. It also looks for Pulsar Manager (jars, running processes, listeners on 7750 and 9527).
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container copies the broker jar names as empty files (only the name carries the version) and, from each `broker.conf`, `standalone.conf`, compose, Helm and `.env` file, only the lines that mention `authorizationProvider`, `anonymousUserRole`, `authorizationEnabled` or `proxyRoles`, so token secrets and client credentials never leave the container. A `broker.conf` that has none of those settings is still staged, so it is reported as clean rather than as unreadable. The script runs once per container in isolation. `/pulsar`, where the official image installs, is searched in containers.

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
