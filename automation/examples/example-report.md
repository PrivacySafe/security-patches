# Example security check report

**Status: Signs of compromise.** 4 run(s) on 2 host(s): `db1.example,` `web1.example`. Generated 2026-11-25 06:01 UTC by `psf-report.py` 1.0.0.

## Runs

| Host | Tool | Command | Result | Crit | Warn | Applies here | Time |
|---|---|---|---|---:|---:|---|---:|
| `web1.example` | magento-check 4.1.0 | check | findings | 2 | 5 | yes | 0.11s |
| `web1.example` | nginx-oct2026-check 1.1.0 | check | clean | 0 | 0 | no | 0.04s |
| `db1.example` | expat-check 1.2.0 | check | findings | 3 | 1 | yes | 0.34s |
| `db1.example` | agentic-attack-check 2.1.0 | hunt | clean | 0 | 0 | unknown | 3.29s |

## Needs attention

- **CRIT (compromise)** on `web1.example`, magento-check check: 1 file(s) in pub/media/custom\_options/ are PHP or carry PHP code: treat the store as compromised and run hunt
  code `MAGENTO_UPLOAD_PHP`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **CRIT (exposure)** on `web1.example`, magento-check check: pub/media/custom\_options/.htaccess is missing or does not deny, and Apache or LiteSpeed serves this host (run mitigate)
  code `MAGENTO_UPLOAD_FOLDER_OPEN`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **CRIT** on `db1.example`, expat-check check: `/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1:` expat 2.6.1 is affected; package libexpat1 does not mention the CVE yet
  what to do: <https://privacysafe.app/docs/security-patches/system/expat/>
- **CRIT** on `db1.example`, expat-check check: `/usr/lib/x86_64-linux-gnu/libexpatw.so.1.9.1:` expat 2.6.1 is affected; package libexpat1 does not mention the CVE yet
  what to do: <https://privacysafe.app/docs/security-patches/system/expat/>
- **CRIT** on `db1.example`, expat-check check: /usr/bin/python3.12 (pyexpat): expat 2.6.1 is affected; package python3.12-minimal does not mention the CVE yet
  what to do: <https://privacysafe.app/docs/security-patches/system/expat/>
- **WARN (vulnerability)** on `web1.example`, magento-check check: 2.4.8-p5: confirm the July 2026 fix (APSB26-73): an isolated patch does not change the version string. Adobe lists plain 2.4.9 as affected and 2.4.9-2026-jul as fixed
  code `MAGENTO_POLYSHELL_UNCONFIRMED`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **WARN (vulnerability)** on `web1.example`, magento-check check: 2.4.8-p5: confirm the August 2026 fix (APSB26-92; Adobe's isolated patch 249-2026-08-001-CE on 2.4.9)
  code `MAGENTO_CVE_2026_71362_UNCONFIRMED`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **WARN (vulnerability)** on `web1.example`, magento-check check: no sign of hotfix VULN-39341 (looked in `composer.json,` `composer.lock,` `.magento.env.yaml,` m2-hotfixes/ and patches/). No release carries it, the October 2026 one included: exposed unless it was applied another way. Confirm: vendor/bin/magento-patches -n status \| grep 39341
  code `MAGENTO_STYLESMUGGLER_NO_HOTFIX`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **WARN (vulnerability)** on `web1.example`, magento-check check: 2.4.8-p5: confirm the October 2026 fix (APSB26-153): an isolated patch does not change the version string
  code `MAGENTO_BLOCKSTRAP_UNCONFIRMED`; path `/var/www/shop`; what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>
- **WARN** on `db1.example`, expat-check check: 3 affected copy(ies) of 3 checked. Expat 2.10.0 (2 November 2026) fixes this and three more flaws.
  what to do: <https://privacysafe.app/docs/security-patches/system/expat/>
- **WARN** on `web1.example`, magento-check check: Exposed or unconfirmed install found.
  what to do: <https://privacysafe.app/docs/security-patches/web-apps/magento/>

## Details

### check: magento-check 4.1.0 on `web1.example`

Started 2026-11-25T06:00:00Z; result findings (exit 1).

- `magento-check.sh` 4.1.0 (2026-11-25) - check on `web1.example` at 2026-11-25`T06:00:01Z`
- Magento, Adobe Commerce and Mage-OS: CVE-2026-48356 (PolyShell), CVE-2026-71362, CVE-2026-75650 (StyleSmuggler), CVE-2026-103849 (BlockStrap)

**Looking for Magento, Adobe Commerce or Mage-OS**


**magento 2.4.8-p5 at /var/www/shop**

- -- CVE-2026-48356 (PolyShell, upload through the guest cart, CISA KEV)
- WARN: 2.4.8-p5: confirm the July 2026 fix (APSB26-73): an isolated patch does not change the version string. Adobe lists plain 2.4.9 as affected and 2.4.9-2026-jul as fixed
- CRIT: pub/media/custom\_options/.htaccess is missing or does not deny, and Apache or LiteSpeed serves this host (run mitigate)
- INFO: no nginx, Apache or LiteSpeed process seen: the folder guard was judged from the .htaccess alone
- CRIT: 1 file(s) in pub/media/custom\_options/ are PHP or carry PHP code: treat the store as compromised and run hunt
- -- CVE-2026-71362 (customer account takeover, CISA KEV)
- WARN: 2.4.8-p5: confirm the August 2026 fix (APSB26-92; Adobe's isolated patch 249-2026-08-001-CE on 2.4.9)
- -- CVE-2026-75650 (StyleSmuggler, unauthenticated RCE, CISA KEV)
- WARN: no sign of hotfix VULN-39341 (looked in `composer.json,` `composer.lock,` `.magento.env.yaml,` m2-hotfixes/ and patches/). No release carries it, the October 2026 one included: exposed unless it was applied another way. Confirm: vendor/bin/magento-patches -n status \| grep 39341
- -- CVE-2026-103849 (BlockStrap, bypass of the StyleSmuggler fix)
- WARN: 2.4.8-p5: confirm the October 2026 fix (APSB26-153): an isolated patch does not change the version string

**Verdict**

- WARN: Exposed or unconfirmed install found.
- INFO: Adobe Commerce and Magento Open Source: move to the October 2026 release (-2026-oct), which carries the PolyShell, August and BlockStrap fixes, and apply hotfix VULN-39341 (APSB26-146) separately. Mage-OS: 3.6.0 or later.
- INFO: Close the upload folder now, patched or not: sudo `web-apps/magento/magento-check.sh` mitigate (the .htaccess and an nginx snippet).
- INFO: StyleSmuggler, PolyShell and CVE-2026-71362 were exploited before many stores patched: run hunt, and rotate the encryption key and every credential it protected if hunt finds anything.

### check: nginx-oct2026-check 1.1.0 on `web1.example`

Started 2026-11-25T06:00:03Z; result clean (exit 0); nothing to check on this host.

- `nginx-oct2026-check.sh` 1.1.0 (2026-11-25) - check on `web1.example` at 2026-11-25`T06:00:03Z`
- nginx: CVE-2026-15176 CVE-2026-93479 CVE-2026-97205 CVE-2026-95101 CVE-2026-97629; njs: CVE-2026-101019 CVE-2026-101025; advisory: `https://nginx.org/en/security_advisories.html`

**nginx on the host**

- INFO: no nginx binary found on PATH or the usual locations

**njs (nginx JavaScript module)**

- INFO: njs not detected

**Configuration audit (which flaws your nginx is configured to reach)**

- INFO: no nginx binary to run 'nginx -T' with

**nginx inside running containers**

- INFO: container scan disabled (SCAN\_CONTAINERS=0)

**Verdict**

- NOT APPLICABLE: no nginx or njs on the host (containers not read)
- INFO: No vulnerable nginx/njs found, or none configured to reach the flaws

### check: expat-check 1.2.0 on `db1.example`

Started 2026-11-25T06:00:05Z; result findings (exit 1).

- `expat-check.sh` 1.2.0 (2026-11-25) - check on `db1.example` at 2026-11-25`T06:00:05Z`
- CVE-2026-115506 (and three more); fixed in libexpat 2.10.0

**System libraries**

- CRIT: `/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1:` expat 2.6.1 is affected; package libexpat1 does not mention the CVE yet
- CRIT: `/usr/lib/x86_64-linux-gnu/libexpatw.so.1.9.1:` expat 2.6.1 is affected; package libexpat1 does not mention the CVE yet

**Python interpreters (pyexpat)**

- CRIT: /usr/bin/python3.12 (pyexpat): expat 2.6.1 is affected; package python3.12-minimal does not mention the CVE yet

**Running processes that have libexpat loaded**

- INFO: no readable process has libexpat mapped (run as root to see all processes)

**Verdict**

- WARN: 3 affected copy(ies) of 3 checked. Expat 2.10.0 (2 November 2026) fixes this and three more flaws.
- INFO: Install your distribution's expat or libexpat update as soon as it ships, then restart the processes listed above.
- INFO: Until then, reduce exposure (PrivacySafe recommendation): cap the size of XML bodies at the proxy, and run services that parse untrusted XML under CPU and memory limits (systemd CPUQuota and MemoryMax) so one request cannot starve the host.
- INFO: libexpat exposes tuning calls for its amplification protection, but the upstream notes do not say that tightening them avoids this flaw, so do not rely on that.
- INFO: Upstream: `https://blog.hartwork.org/posts/expat-2-10-0-released/` (backporters: pull request #1439 in particular)

### hunt: agentic-attack-check 2.1.0 on `db1.example`

Started 2026-11-25T06:00:07Z; result clean (exit 0).

- `agentic-attack-check.sh` 2.1.0 (2026-11-25) - hunt on `db1.example` at 2026-11-25`T06:00:10Z`
- AI-driven attack frameworks: ARTEX, CAIRN, CyberStrikeAI, HexStrike AI, PentAGI and others (no CVE)

**Web access logs (last 120 days)**

- INFO: nothing from the indicator list in the logs read

**Web folders**

- INFO: no framework file name or marker under /var/www /srv /usr/share/nginx /opt /home/\*/public\_html /home/\*/www

**Shell histories, cron and systemd units**

- INFO: nothing from the indicator list in histories, cron or units

**Running now**

- INFO: no shell under a web or database service, no connection to a published address

**Verdict**

- INFO: Nothing from the indicator list was found. That does not prove these frameworks never reached this host.

---

**PrivacySafe Security Patches** (<https://privacysafe.app>). Each finding links to its tool's page at <https://privacysafe.app/docs/security-patches/>. A finding is what the tool read on the host; confirm before acting on it.

The records follow, closely rather than exactly, the joint guide Best Practices for Event Logging and Threat Detection (ASD's ACSC, CISA and international partners, 2024), the NIST SP 800-53 Rev. 5 Audit and Accountability (AU) controls and OMB Memorandum M-26-14. See the automation guide for how they line up.

Questions and other issues: <help@privacysafe.net> (GPG `7702 BD22 435B 5F3E B00C 1E78 21FB 9DF4 D742 422D`). Report security issues in these tools to <security@privacysafe.net> (GPG `7E3E C7D6 D965 CF1D 8C76 8F80 74AB DBE3 E3FB C689`).
