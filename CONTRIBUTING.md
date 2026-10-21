# Contributing

Thank you for contributing to PrivacySafe and 3NWeb. Contributions may include code, tests, documentation, issue triage, bug reports, protocol and format work, design discussion, review, and other improvements that help the projects.

PrivacySafe and 3NWeb are Free/Libre and Open Source Software (FLOSS) projects with a relatively small group of maintainers supporting software, public services, protocols, documentation, standards work, and infrastructure. Please keep contributions focused and reviewable and understand that not every proposed change can be accepted.

## Before you contribute

Please read and follow:

* [`VALUES.md`](VALUES.md) for the principles that guide PrivacySafe and 3NWeb;
* [`CONTRIBUTOR_GUIDELINES.md`](CONTRIBUTOR_GUIDELINES.md) for project-specific collaboration guidance;
* [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for contributor conduct and project communication;
* [`AI_POLICY.md`](AI_POLICY.md) for AI-assisted contributions; and
* [`SECURITY.md`](SECURITY.md) for vulnerability disclosure and security-sensitive reports.

Community spaces such as PrivacySafe Social and the Learning Commons follow the [PrivacySafe Foundation Community Guidelines](https://privacysafe.foundation/community-guidelines) and, where applicable, the [8 Simple Rules](https://privacysafe.social/about#8-simple-rules). These community rules are separate from the repository Code of Conduct and apply only where the relevant service or space adopts them.

Never send passwords, recovery phrases, private keys, sensitive user data, unreleased vulnerabilities, or other confidential material through public issues or ordinary direct messages.

## How we work

Maintainers are responsible for the direction, architecture, security, maintainability, and release decisions of the projects they maintain.

We consider community feedback and aim to make project decisions transparently where practical, but welcoming contributions does not mean that every proposed feature, design, dependency, refactor, or pull request will be accepted.

Review capacity is limited. A smaller, well-scoped contribution that clearly solves an agreed problem is much easier to review than a broad unsolicited rewrite.

Some technical or organizational discussion may happen outside a public forge. That does not change the requirement that accepted source changes, licensing information, attribution, and relevant project documentation be recorded appropriately in the repository.

## Ways to contribute

Useful contributions include:

* **Bug reports:** identify reproducible problems with enough detail to investigate them.
* **Issue triage:** reproduce reports, identify duplicates, clarify affected versions, and help separate bugs from support questions.
* **Testing:** add or improve tests, test proposed fixes, and report regressions.
* **Documentation and guides:** correct inaccurate material, improve explanations, and document behavior that users, operators, or developers need to understand.
* **Code:** fix bugs, improve maintainability, or implement agreed changes.
* **Protocols and formats:** identify ambiguities, test interoperability, and contribute to 3NWeb architecture, protocol, and file format work where appropriate.
* **Review:** provide focused technical review, test patches, and identify security, privacy, compatibility, or licensing concerns.

## Issues and discussions

Before opening a new issue, search the repository to see whether the same problem, proposal, or question has already been reported, resolved, or declined.

Use a clear and concise title. For bug reports, include the affected repository or component, version or build when known, steps to reproduce, expected behavior, actual behavior, and other information needed to understand the problem.

Do not publish vulnerability details in ordinary issues. Follow [`SECURITY.md`](SECURITY.md).

For a substantial feature, architectural change, protocol change, large refactor, new dependency, or broad design change, open an issue or discussion before producing a large patch. Significant unsolicited changes that do not fit project architecture or direction may be closed without detailed review.

## Submitting changes

### Be intentional

Consider whether the change solves a real problem and is likely to fit the project before investing substantial effort.

### Design first for non-trivial changes

For significant changes, agree on the goal and general approach before producing a large implementation.

This is especially important for:

* major features;
* security-sensitive behavior;
* cryptographic or key-management changes;
* protocol or file-format changes;
* public API changes;
* storage or migration changes;
* new network dependencies or data flows;
* large dependency additions;
* sweeping refactors; and
* substantial visual or brand changes.

### Keep changes focused

A pull request should normally address one coherent problem. Split unrelated work into separate changes.

Do not bundle broad cleanup, formatting, dependency changes, generated rewrites, or unrelated refactors into a patch unless they are necessary for the proposed change.

### Test the result

Run the tests and checks appropriate to the repository before submitting.

Add or update tests when a change introduces behavior that can reasonably be tested. Explain any important testing limitation in the pull request.

A pull request that does not pass applicable automated checks may be returned for correction before substantive review.

### Update relevant documentation

If a change alters user-visible behavior, public APIs, protocols, formats, configuration, deployment requirements, migration behavior, security assumptions, or privacy behavior, update the relevant documentation as part of the work.

Changes to 3NWeb architecture, protocol, or file format documentation may also require corresponding work in the dedicated documentation or IEEE SA Open materials.

### Preserve project history and attribution

Do not remove copyright notices, license notices, authorship information, upstream attribution, `NOTICE` entries, or file-level SPDX information merely for consistency or cosmetic cleanup.

If third-party material is added, identify its source, copyright holder, applicable license, and upstream location.

## Pull requests

Use a clear title that explains what the change does. Prefer wording that is understandable to users, administrators, reviewers, or developers who may encounter the change later in project history.

In the pull request description:

* explain the problem being solved;
* describe the approach taken;
* link the relevant issue or discussion when one exists;
* describe testing performed;
* identify security or privacy implications where relevant;
* identify protocol, API, migration, or compatibility implications where relevant;
* disclose significant AI assistance as required by [`AI_POLICY.md`](AI_POLICY.md); and
* identify third-party material or licensing considerations when applicable.

Keep the set of changes as small as practical for review.

Respond to review comments constructively. A request for changes is about improving the contribution and does not imply that the contributor is unwelcome.

## AI-assisted contributions

AI tools may assist human contributors, but every contribution must have an identifiable human who understands, reviews, and accepts responsibility for the submitted work.

Fully automated pull requests without meaningful human review are not acceptable, except for automated workflows specifically enabled or approved by project maintainers.

Significant AI assistance must be disclosed as described in [`AI_POLICY.md`](AI_POLICY.md).

## Decision making

Maintainers have final responsibility for deciding what is merged into the repositories they maintain.

A contribution may be declined because of architecture, scope, maintenance cost, security, privacy, interoperability, user experience, licensing, roadmap, review capacity, or other project considerations even when the contribution is technically competent.

Declining a particular change is not a rejection of the contributor. Future focused contributions remain welcome.

## Contribution licensing

By submitting a pull request or other contribution, you represent that you have the right to submit it and intend to assign to **Ivy Cyber LLC** all copyright you own in that contribution. Ivy Cyber LLC may require a separate written or electronic confirmation of that assignment before accepting the contribution.

## Software contributions

Unless a repository or file states otherwise, original PrivacySafe and 3NWeb software in this repository is distributed under the **GNU Affero General Public License version 3 or later (`AGPL-3.0-or-later`)**.

A contribution submitted to an AGPL-licensed repository must be compatible with that license. Do not copy code from a project under an incompatible license. If a contribution contains third-party code, identify the source, copyright holder, license, and upstream URL in the pull request and update `NOTICE` or `LICENSES/` when required.

Software source files should carry an `SPDX-License-Identifier: AGPL-3.0-or-later` marker where the format permits one.

## Documentation contributions

Documentation intended for publication with the 3NWeb architecture, protocol specifications, or PrivacySafe guides is licensed under **Apache License 2.0 (`Apache-2.0`)** and is intended to be contributed through [IEEE SA Open](https://opensource.ieee.org/3nweb) under the [IEEE SA Open CLA](https://opensource.ieee.org/community/cla/apache).

Documentation should carry an `SPDX-License-Identifier: Apache-2.0` marker where the format permits one.

Documentation inside an AGPL-licensed software repository is not automatically a separate Apache-licensed class. Unless a file or repository states otherwise, it follows the license of that repository.

## Copyright and provenance

Primary project provenance is recorded in [`CONTRIBUTORS.md`](CONTRIBUTORS.md). Unless a file or component carries a different notice, copyright is held by **Ivy Cyber LLC**.

Third-party code and documentation retain their original copyrights and licenses.

## Security and abuse reports

Security vulnerabilities: see [`SECURITY.md`](SECURITY.md).

Sensitive security reports: `security@privacysafe.net`

Abuse or conduct reports: `abuse@privacysafe.net`

Use the published GPG keys for sensitive reports.

## Thank you

Review, testing, documentation, issue triage, small fixes, careful criticism, and other forms of participation are all valuable. We appreciate the time contributors spend helping PrivacySafe and 3NWeb improve.

---

This document is released under the [CC0 1.0 Universal Public Domain Dedication](https://creativecommons.org/publicdomain/zero/1.0/).
