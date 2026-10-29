# Amazon SageMaker Python SDK: CVE-2026-112408 default bucket takeover

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="sagemaker-check"></a>

## SageMaker Python SDK check

**Script:** [`sagemaker/sagemaker-check.sh`](sagemaker-check.sh)

The SDK's `default_bucket()` uses an S3 bucket named `sagemaker-{region}-{AWS account ID}`. In affected versions it does not check that the bucket belongs to your account. Region and account ID are not secret, so another AWS account can pre-create a bucket with that name; the SDK then reads from and writes to the attacker's bucket, which can give the attacker code execution in your SageMaker execution environment and your IAM credentials.

| | |
|---|---|
| CVE | CVE-2026-112408 (CWE-940, advisory GHSA-5rx8-8fr2-f855, AWS bulletin 2026-142-aws, published 21 October 2026) |
| Severity | Amazon rates it 8.1 (CVSS 3.1); the CNA record also carries 9.4 |
| Affected | V2 before **2.257.3**, and V3 (3.0.0) before **3.10.0** |
| Fixed | **2.257.3 and 3.10.0** (both exist on PyPI). The fix adds an `ExpectedBucketOwner` check to the SDK's S3 operations: comparing the two wheels shows it on the upload, download and bucket-check paths |
| Also | A separate flaw in the same releases (repository credentials written to CloudWatch Logs by `git_utils`) is fixed by the same upgrade. It is not counted separately here |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/sagemaker/sagemaker-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/sagemaker/sagemaker-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less sagemaker-check.sh
   chmod +x sagemaker-check.sh
   ```

3. Check this host. By default it searches `/usr/lib /usr/local/lib /opt /srv /var/lib /home /root`; pass directories to narrow it, such as one virtual environment.

   ```bash
   ./sagemaker-check.sh check
   ./sagemaker-check.sh check ~/ml/.venv
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds installed copies (`sagemaker-*.dist-info` and `egg-info`) and declared pins (`requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `environment*.yml`), and lists the Python files and notebooks that call `default_bucket()`. It makes **no AWS calls** |
| `version` | Prints the script version |

Exit codes: `0` nothing affected, `1` an affected SDK found, `2` bad arguments.

## How to read the result

- **Affected version:** exit `1`. The tool cannot prove your code relies on the default bucket (estimators and processors use it implicitly), so it judges by version and lists the files that call `default_bucket()` directly, excluding the SDK's own source.
- **The SDK's own packages and look-alikes** such as `sagemaker-core` and `sagemaker_studio` are different packages and are not matched, including when listed before the real one in a lock file.
- **It cannot tell whether someone has already pre-created your bucket name.** To check by hand, with the AWS CLI and read access (this script does not run it):

  ```bash
  aws s3api head-bucket --bucket sagemaker-REGION-ACCOUNTID --expected-bucket-owner ACCOUNTID
  ```

  A 404 suggests the name is unclaimed and anyone could take it; a 403 usually means it exists under a different account (or that you lack permission). If it is someone else's, review what the SDK uploaded there.

## Fixing it

```bash
pip install --upgrade 'sagemaker>=2.257.3'   # V2
pip install --upgrade 'sagemaker>=3.10.0'    # V3
```

Interim, until you can upgrade (our reasoning, not the vendor's): pass an explicit bucket you own instead of relying on the default (V2's `Session` documents a `default_bucket` argument; use the equivalent setting in V3), and create the default bucket `sagemaker-<region>-<account-id>` yourself so no one else can.

## Sources

- [AWS security bulletin 2026-142-aws](https://aws.amazon.com/security/security-bulletins/2026-142-aws/)
- [Advisory GHSA-5rx8-8fr2-f855](https://github.com/aws/sagemaker-python-sdk/security/advisories/GHSA-5rx8-8fr2-f855)

## SageMaker SDK know before you run it

- **This is a check, not a fix.** Update the SageMaker Python SDK to 2.257.3 (V2) or 3.10.0 (V3). The same upgrade fixes a separate flaw that wrote repository credentials to CloudWatch Logs.
- **It makes no AWS calls.** It finds installed copies and pinned versions, and lists the Python files and notebooks that call `default_bucket()`.
- **It cannot tell whether someone has pre-created your bucket name.** That is the real exposure, so the script prints a manual check for you to run.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container copies the SageMaker SDK metadata directories and the lock, requirements and `environment*.yml` files that mention it (index URLs and credentials dropped inside the container) into a private temporary directory, and the script runs once per container in isolation against that copy. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME.

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
