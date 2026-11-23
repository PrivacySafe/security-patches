# Apache Roller security releases

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="xmlrpc"></a>

## XML-RPC deserialization: CVE-2026-129448 / CVE-2026-82384, unauthenticated remote code execution

**Script:** [`apache-roller/apache-roller-xmlrpc-check.sh`](apache-roller-xmlrpc-check.sh)

CVE-2026-129448, published 17 November 2026 by the Apache Software Foundation, found by n0mi1k and reported by Matt Raible: critical (CVSS 3.1 9.8, CWE-502 Deserialization of Untrusted Data), unauthenticated remote code execution in Apache Roller through the `/roller-services/xmlrpc` endpoint. It is the same underlying flaw as CVE-2026-82384 (published September 2026), which named only Roller 6.1.5 as affected; the November advisory widens the affected range back to 4.0.0 and reports active exploitation. CISA added it to the Known Exploited Vulnerabilities catalog on 20 November 2026.

Roller's XML-RPC servlet, which serves the legacy Blogger and MetaWeblog APIs, ships with the underlying XML-RPC library's `enabledForExtensions` option set to `true`, so it accepts a non-standard vendor value type carrying a base64-encoded Java-serialized object, and deserializes it before any authentication check runs. A suitable class on the server's classpath turns one unauthenticated `POST /roller-services/xmlrpc` into code execution. The servlet mapping for that path ships in every affected release regardless of application settings, and critically, Roller's own admin-UI toggle for XML-RPC (`webservices.enableXmlRpc`) does **not** gate this servlet on an unpatched install: the deserialization happens before that setting is ever read, so an administrator who believed they'd turned XML-RPC off was not protected.

Fixed in Apache Roller 6.1.6 (11 November 2026), which disables the vendor extension types outright and adds a new servlet filter, `XmlRpcEnabledFilter`, that finally makes the admin-UI toggle work as expected. Roller 6.1.7, the current release, also fixes CVE-2026-123374 (an unrelated deserialization bug in weblog update ping responses) and 15 further, lower-severity issues this script does not audit for; upgrading past 6.1.6 to 6.1.7 is worth doing for those alone.

`check` and `hunt` change nothing and need no privilege. `mitigate` and `rollback` change the host and require root (or whatever account owns the deployed webapp directory), stopping with a clear message otherwise. `check` finds every Tomcat instance this host has, the same discovery this collection's `tomcat-oct2026-check.sh` uses: explicit `CATALINA_HOME`/`CATALINA_BASE`, every running Java process's `-Dcatalina.home=`/`-Dcatalina.base=` (which also catches an install at a non-default path, and a `CATALINA_BASE` whose `webapps/` does not live under its `CATALINA_HOME` in a multi-instance setup), then the usual filesystem locations as a fallback for an install that is not currently running. It walks each instance's `webapps/*/WEB-INF/web.xml` (plus `ROLLER_WEBXML` for an explicit path) for any `web.xml` carrying the `/roller-services/xmlrpc` servlet mapping, and reports, per install: whether `enabledForExtensions` is on, whether the mapping is still live, and whether the post-fix `XmlRpcEnabledFilter` is present. That filter's presence is this script's one reliable signal for "patched 6.1.6 or later": a deployed WAR does not reliably carry its own version number anywhere on disk, so rather than guess at a version string, `check` treats the fix's own code as the signal. `hunt` greps readable Tomcat/web-server access logs for `POST` requests to the endpoint; a match only shows something used the route, not that it carried the malicious payload, since a legitimate Blogger/MetaWeblog client logs the same way.

`mitigate` applies the first of Apache's own two named workarounds by default: setting `enabledForExtensions` to `false` in `web.xml`. Since this only turns off the dangerous vendor extension type rather than the endpoint itself, it has no real cost to legitimate Blogger/MetaWeblog API use, so it always runs. `mitigate --remove-mapping` instead comments out the `<servlet-mapping>` for the endpoint (Apache's other named workaround), which does have a real cost: it takes the legitimate API offline entirely. Because of that cost, `--remove-mapping` by default only acts when `check` would report a Roller install here as exposed (not found, or unreadable, counts as not-yet-confirmed-fixed for this purpose, not as clear); when every install found is already confirmed fixed, it changes nothing and says so, unless `--force` is given to remove the mapping anyway. Both actions back up the file first and verify the result is still well-formed XML (via `xmllint` or Python's `xml.dom.minidom`, whichever is available), rolling back automatically if not. `mitigate --dry-run` prints a unified diff of exactly what would change in every `web.xml` found and writes nothing, so, unlike a real `mitigate`, it needs no privilege, and it skips the exposure gate on `--remove-mapping` so you can preview the change either way. Neither Tomcat nor any other servlet container picks up a `web.xml` edit by itself for this bug, since the affected servlet and filter instances are built once at context start, and a context reload is not reliably enough; the advisory says to restart Roller. `--restart` tries `systemctl restart` against a detected Tomcat unit (`tomcat`, `tomcat9`, `tomcat10`, `tomcat11`); without it, restart the container yourself once you're satisfied with the result. `rollback` restores every file `mitigate` backed up, with the same `--restart` option; `rollback --dry-run` prints which file would be restored from which backup and writes nothing, so it needs no privilege.

How `check` decides: the post-fix `XmlRpcEnabledFilter` in `web.xml` means 6.1.6 or later, fixed, whatever `enabledForExtensions` says. Without it, `enabledForExtensions` set to `true` with the servlet mapping present means exposed. A servlet mapping inside an XML comment is not counted as live. A Roller install at a non-default path is found through a running Java process's `-Dcatalina.home=` or `-Dcatalina.base=`, which a search of the usual folders alone would miss. `mitigate --dry-run` prints the exact change and needs no privilege, `--remove-mapping` acts only on an exposed install unless `--force` is given, and `rollback` restores `web.xml` byte for byte.

### XML-RPC quick start

```sh
curl -O https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/apache-roller/apache-roller-xmlrpc-check.sh
chmod +x apache-roller-xmlrpc-check.sh
./apache-roller-xmlrpc-check.sh check
```

If you cannot upgrade to 6.1.7 today, preview and then apply the interim measure, and restart Tomcat:

```sh
sudo ./apache-roller-xmlrpc-check.sh mitigate --dry-run
sudo ./apache-roller-xmlrpc-check.sh mitigate --restart
```

After the upgrade, undo it with `sudo ./apache-roller-xmlrpc-check.sh rollback --restart`.

### XML-RPC commands

| Command | Root | What it does |
|---|---|---|
| `check` (default) | no | Finds each Roller `web.xml` and reports exposed, fixed, interim measure applied, or undetermined. Exit `0` clear, `1` exposed, `2` undetermined or no install found (set `ROLLER_WEBXML` to point at one) |
| `hunt` | no | Reads Tomcat and httpd access logs for `POST /roller-services/xmlrpc`. A match is a lead, not proof. Exit `0` nothing found, `1` a match, `2` no log could be read |
| `mitigate [--remove-mapping] [--restart] [--dry-run] [--force]` | yes (unless `--dry-run`) | Sets `enabledForExtensions` to `false` in `web.xml`, or with `--remove-mapping` comments out the endpoint's servlet mapping, which takes the Blogger and MetaWeblog API offline. Backs up first and checks the result is well-formed XML. `--restart` restarts the Tomcat systemd unit |
| `rollback [--restart] [--dry-run]` | yes (unless `--dry-run`) | Restores every `web.xml` that `mitigate` changed |
| `rules` | no | Prints the two workarounds and the upgrade guidance |
| `version` | no | Prints the script version |

What this script cannot do: upgrade Roller, or tell you whether a deserialization already happened before you ran it. `mitigate` only closes the one path named in this advisory; it has no coverage for CVE-2026-123374 or the other issues 6.1.7 fixes.

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
