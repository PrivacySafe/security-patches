# Vulnerability Disclosure Policy & Bug Bounty Program

_Last updated: September 6, 2026_

## <a name="introduction">Introduction</a>

PrivacySafe is a family of software, public-interest services, protocols, and infrastructure funded by donations to the PrivacySafe Foundation 501(c)(3) nonprofit public charity and commercially published and supported by Ivy Cyber. Together, we're building a better web.

Ivy Cyber provides technical security operations, triage, remediation coordination, infrastructure support, and, where applicable, bug bounty administration for PrivacySafe systems. We welcome good-faith security research that helps us protect users, software, public services, and infrastructure.

We build Free/Libre and Open Source Software (FLOSS) and favor responsible disclosure, reproducible reports, transparent remediation, and acknowledgement of researchers after risks to users and the public have been resolved or mitigated. This policy reflects the commitments to verifiable security, transparency, and non-destructive technical work in [`VALUES.md`](VALUES.md).

## <a name="open-bug-bounty">[Open Bug Bounty](https://www.openbugbounty.org/bugbounty/privacysafe/)</a>

Our program is listed at Open Bug Bounty. Submit there when feasible, or use the official encrypted reporting channel in this document.

[https://www.openbugbounty.org/bugbounty/privacysafe/](https://www.openbugbounty.org/bugbounty/privacysafe/)

The information at the above URL refers to this policy. Researchers who submit through Open Bug Bounty can build a public reputation for their work, and we may provide positive recommendations for responsible researchers.

## <a name="scope">Scope</a>

This policy applies to current PrivacySafe source repositories and public-facing systems owned, maintained, or administered by Ivy Cyber and PrivacySafe Foundation, including: 

* `privacysafe.app`
* `download.privacysafe.app`
* `privacysafe.foundation`
* `ivycyber.com`
* `cryptopay.ivycyber.com`
* `privacysafe.social`
* `privacysafe.is`
* `privacysafe.bot`
* `privacysafe.locker`
* `privacysafe.click`
* `psafe.ly`
* current PrivacySafe repositories at [github.com/PrivacySafe](https://github.com/PrivacySafe) and [codeberg.org/PrivacySafe](https://codeberg.org/PrivacySafe)
* other systems explicitly identified as in scope by a repository, service, or published security notice

### <a name="out-of-scope">Out of Scope</a>

Unless we explicitly say otherwise, this policy does not authorize testing of:

* archived repositories;
* third-party services, federated servers, hosting providers, payment processors, or infrastructure we do not control;
* social engineering of users, staff, contributors, donors, customers, or partners;
* physical facilities, devices, or data centers not owned or controlled by us;
* denial-of-service or resource-exhaustion testing;
* destructive testing or testing that risks another person's data;
* public support, marketing, or social media accounts as attack targets; or
* [Commonplace Reports](#commonplace-reports) listed below without a demonstrated security impact specific to our implementation.

If you discover an issue in a third-party service, report it to that service's operator rather than testing it through our users or systems.

Do not engage in denial-of-service, active exploitation beyond what is necessary to demonstrate a vulnerability safely, physical attacks, or attempts against property or data centers.

## <a name="disclosure">Disclosure</a>

### <a name="non-security-help">Non-security Help</a>

Please report ordinary help requests and non-sensitive issues unrelated to security or privacy vulnerabilities to:

`help@privacysafe.net`

GPG fingerprint:

`7702 BD22 435B 5F3E B00C 1E78 21FB 9DF4 D742 422D`

Verify the key through [keys.openpgp.org](https://keys.openpgp.org/search?q=help%40privacysafe.net).

Do not send passwords, recovery phrases, private keys, full payment credentials, or other secrets through ordinary email.

### <a name="security-issues">Security Issues</a>

We ask that you disclose vulnerabilities, exploits, exposed data, privacy failures, and suspected breaches in a confidential and professional manner. We welcome reports from experts and amateurs alike and appreciate responsible disclosure and non-destructive research.

#### <a name="official-channels">Official Channels</a>

Report security issues to:

`security@privacysafe.net`

GPG fingerprint:

`7E3E C7D6 D965 CF1D 8C76 8F80 74AB DBE3 E3FB C689`

Verify the key through [keys.openpgp.org](https://keys.openpgp.org/search?q=security%40privacysafe.net).

Our canonical `security.txt` is published at [privacysafe.app/security.txt](https://privacysafe.app/security.txt).

If you need to send sensitive material, encrypt it to the security key before transmission. If you use a paste service, encrypt the content first and send only the encrypted material.

Before submission, please review our Open Bug Bounty information:

[https://www.openbugbounty.org/bugbounty/privacysafe/](https://www.openbugbounty.org/bugbounty/privacysafe/)

**Security reports must include:**

* a clear description of the issue;
* the affected service, repository, version, endpoint, or build;
* steps to reproduce the issue or a proof of concept when safe; and
* an explanation of the security or privacy impact.

**Whenever possible, please include:**

* affected software versions;
* the expected and actual behavior;
* screenshots, video, logs, or other useful evidence; and
* a practical mitigation, if known.

Do not access more data than necessary to demonstrate the issue.

Our organization generally follows a **90-day coordinated disclosure timeline** as described in this policy.

## <a name="our-commitments">Our Commitments</a>

When disclosing a security issue according to this policy, you can expect us to:

* respond to your report promptly and work with you to understand and validate it;
* let you know whether the report appears eligible for a bounty reward within five business days;
* keep you reasonably informed about progress while the vulnerability is being processed;
* work to remediate validated vulnerabilities according to severity and operational constraints;
* notify you when a validated issue has been resolved; and
* provide a time window for lifting restrictions around public disclosure.

Where circumstances permit, we use a coordinated disclosure period of up to 90 days. The parties may agree to a different timeline, and urgent circumstances may require faster action.

## <a name="our-expectations">Researcher Expectations</a>

When testing or reporting, you must:

* act in good faith;
* follow this policy and any other terms that apply to the system being tested;
* report vulnerabilities promptly;
* use only systems that are in scope;
* use accounts and data you own or have explicit permission to test;
* avoid violating the privacy of others, disrupting systems, destroying data, or harming user experience;
* avoid persistence, destructive actions, privilege abuse, and denial-of-service;
* avoid social engineering;
* use the [Official Channels](#official-channels) to discuss vulnerability information with us;
* keep vulnerability details confidential until the coordinated disclosure window ends or we approve disclosure; and
* do not engage in extortion.

If a vulnerability provides unintended access to data:

* limit access to the minimum required to demonstrate the issue safely; and
* stop testing and report the issue immediately if you encounter another person's private data, including personally identifiable information, protected health information, payment-card data, private communications, credentials, or confidential business information.

Do not use a vulnerability to access, download, alter, delete, deanonymize, or publish another person's data beyond the minimum strictly necessary to demonstrate the issue safely.

## <a name="safe-harbor">Safe Harbor</a>

We consider research conducted in good faith and in accordance with this policy to be authorized by us with respect to systems we control.

For research that follows this policy, we will not initiate or support legal action based on accidental, good-faith violations of this policy when the researcher promptly stops, reports the issue, and cooperates in remediation. To the extent within our control, we also treat good-faith research under this policy as authorized for purposes of restrictions that would otherwise interfere with legitimate security research.

If legal action is initiated by an independent third party against a researcher who complied with this policy, we may state that the research was conducted in accordance with our policy.

**IMPORTANT:** Safe Harbor applies only to claims under the control of the organizations participating in this policy. It does not bind independent third parties or excuse violations of law unrelated to authorized security research.

If you are unsure whether planned testing is allowed, contact `security@privacysafe.net` through an [Official Channel](#official-channels) before proceeding.

## <a name="bounty-rewards">Bounty Rewards</a>

Rewards depend on severity, report quality, exploitability, impact, and whether the issue is already known.

### Reward Scale

* **Critical:** Up to $500 USD or equivalent cryptocurrency
* **High:** Up to $250 USD or equivalent cryptocurrency
* **Medium or Low:** Merchandise, digital rewards, acknowledgements, recommendations, or other recognition at our discretion

A researcher may request that an approved monetary reward be donated to an eligible charitable organization instead.

Please allow up to one week from the time a report is approved and validated for an eligible reward to be distributed.

### <a name="eligibility">Eligibility</a>

The following requirements apply to bounty eligibility:

* **Report format:** Provide clear reproduction instructions, a practical attack scenario where applicable, and your assessment of security or privacy impact.
* **First come, first served:** Only the first complete report of a previously unknown issue is normally eligible for a monetary reward. Later reports may be treated as duplicates.
* **Play it safe:** Test only with accounts and data under your control or with explicit permission. If demonstrating the issue could expose another person's data, contact us before attempting the proof of concept.
* **Do not disclose too early:** Keep vulnerability details confidential until we confirm that a fix has been deployed or otherwise approve disclosure. Premature disclosure may make the report ineligible for a bounty.
* **No social engineering:** A vulnerability whose practical exploitation could involve social engineering may still be reportable, but do not actually socially engineer users, staff, contributors, donors, customers, or partners.

## <a name="commonplace-reports">Commonplace Reports</a>

In addition to the areas defined as [Out of Scope](#out-of-scope), the following generally do not qualify for a bounty unless the report demonstrates a concrete exploit or material privacy or security impact specific to our implementation:

* lack of a non-critical security feature;
* configuration observations without demonstrated security impact;
* descriptive errors, stack traces, banners, debug information, or public version information without an exploit;
* public files or directories such as `robots.txt`;
* outdated software or library versions without a demonstrated exploitable path;
* automated scan output without a reproducible exploit;
* non-exploitable application or network information;
* missing non-critical security headers;
* enabled HTTP methods without demonstrated impact;
* subdomain or DNS findings that do not demonstrate control, data exposure, or a viable exploit;
* DNS zone transfer or DNSSEC configuration observations without demonstrated impact;
* logout CSRF;
* CSRF on anonymous forms without demonstrated impact;
* self-XSS;
* reflected or non-persistent XSS without demonstrated security impact;
* missing or incomplete cookie flags without demonstrated impact;
* attacks requiring physical access to a user's device;
* username enumeration without an exploit chain;
* rate-limit, brute-force, or account-lockout policy preferences;
* generic SSL/TLS best-practice observations;
* clickjacking without demonstrated impact;
* XML-RPC mirroring or reflection without associated exploitation;
* mail configuration observations such as SPF, DKIM, or DMARC preferences;
* public login panels;
* autocomplete settings;
* password or account-recovery policy preferences;
* lack of email-address verification without demonstrated impact; or
* session-control preferences during email or password changes.

Commonplace issues that are not security vulnerabilities may still be reported through the appropriate project issue tracker.

## <a name="acknowledgements">Acknowledgements</a>

Researchers who responsibly disclose valid findings may be listed on our [Security Acknowledgements](https://privacysafe.app/security-thanks) page with their permission.

---
This document is released under the [CC0 1.0 Universal Public Domain Dedication](https://creativecommons.org/publicdomain/zero/1.0/).
