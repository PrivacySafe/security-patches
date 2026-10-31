#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: the footer every README ends with
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Every README in the repository ends with the same block: the important notice,
# how to support PrivacySafe Foundation, how to contribute, more from PrivacySafe,
# and the license. Only the links to the files in the repository root change, because
# they depend on how deep the README sits (CONTRIBUTING.md, ../CONTRIBUTING.md,
# ../../CONTRIBUTING.md). This script is the one place the block is written.
#
#   python3 packaging/readme-footer.py --check    list every README whose footer differs
#   python3 packaging/readme-footer.py --write    put the block into every README
#
# --write keeps everything above the footer and replaces the footer. A README that has
# no footer gets one. Run it after you add a README, then run packaging/gen-site.py.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BLOCK = """## ⚠️ Important notice

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy]({up}SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`]({up}CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`]({up}CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`]({up}AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`]({up}SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`]({up}NOTICE) and [`LICENSE`]({up}LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
"""

# The first heading of the footer, with or without an emoji in front of it.
START = re.compile(r"^## (?:[^\w\s#]\S*\s+)?(?:Important notice|Before you run anything|Support PrivacySafe Foundation)\s*$", re.M)


def readmes():
    out = []
    for dp, dn, fn in os.walk(ROOT):
        rel = os.path.relpath(dp, ROOT)
        if rel.split(os.sep)[0] in (".git", "site", "man", "dist", "node_modules"):
            dn[:] = []
            continue
        if "README.md" in fn:
            out.append(os.path.normpath(os.path.join(rel, "README.md")))
    return sorted(out)


def up_for(path):
    depth = path.count(os.sep)
    return "../" * depth


def with_footer(text, up):
    """The README text with the footer in place."""
    block = BLOCK.replace("{up}", up)
    m = START.search(text)
    body = text[:m.start()] if m else text
    body = body.rstrip("\n")
    lines = body.split("\n")
    if lines and lines[-1].strip() == "---":    # the rule that ends the body belongs to the footer
        body = "\n".join(lines[:-1]).rstrip("\n")
    return body + "\n\n---\n\n" + block


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in ("--check", "--write"):
        sys.exit("usage: readme-footer.py --check | --write")
    changed = []
    files = readmes()
    for rel in files:
        p = os.path.join(ROOT, rel)
        text = open(p, encoding="utf-8").read()
        new = with_footer(text, up_for(rel))
        if new != text:
            changed.append(rel)
            if mode == "--write":
                open(p, "w", encoding="utf-8").write(new)
    if mode == "--write":
        print(f"{len(files)} READMEs checked, footer written to {len(changed)}")
    else:
        for rel in changed:
            print("footer differs:", rel)
        print(f"{len(files)} READMEs checked, {len(changed)} differ" if changed else f"all {len(files)} READMEs end with the same footer")
        sys.exit(1 if changed else 0)


if __name__ == "__main__":
    main()
