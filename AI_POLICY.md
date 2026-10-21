# AI Contribution Policy

_Last updated: September 6, 2026_

## 0. Scope and terminology

In this policy, the terms "AI" and "artificial intelligence" are used to refer to systems that utilize machine learning (ML), large language models (LLMs), or related probabilistic techniques to generate or substantially transform code, documentation, tests, issue text, designs, or other project material. Some of these systems are referred to as "generative AI" or "hybrid AI" in academic literature. Examples include ChatGPT, GitHub Copilot, Claude, Gemini, Grok, and similar tools.

## 1. Purpose and principles

PrivacySafe and 3NWeb follow the principles in [`VALUES.md`](VALUES.md), including the commitment that artificial intelligence must remain optional. For contributions, that means AI may assist human work but must not displace human judgment, accountability, or control. Contributions must preserve:

- human accountability;
- verifiable, auditable, and secure code;
- clear copyright and software-license provenance;
- maintainable project architecture;
- PrivacySafe privacy-by-design principles; and
- compatibility with the 3NWeb protocols and formats where applicable.

Quality and maintainability matter more than contribution volume.

## 2. Human responsibility

Every contribution must have an identifiable human contributor who:

- understands what is being submitted and how it behaves;
- can explain significant design and implementation decisions;
- has reviewed the work for correctness, security, privacy, and licensing; and
- accepts responsibility for the contribution.

AI tools may assist a contributor, but an AI system is not a contributor, author of record, maintainer, or reviewer.

A submission may be rejected when the human contributor cannot reasonably explain or defend it.

## 3. AI-assisted contributions

### 3.1 General position

AI-assisted development can be useful for limited tasks such as code completion, drafting tests, or exploring implementation approaches. It can also create risks, including:

- copied or closely reproduced third-party code;
- unclear copyright provenance;
- incompatible software licensing;
- subtle security or privacy defects;
- fabricated APIs, dependencies, or project assumptions; and
- unnecessary review and maintenance burden.

Contributors must review AI-assisted output as carefully as code written from any other untrusted source.

### 3.2 Disclosure

If an AI system generated or substantially transformed a meaningful portion of a contribution, disclose:

- the tool used;
- the part of the contribution it affected; and
- how the output was reviewed, tested, or rewritten.

For code contributions, include a commit trailer when practical:

```text
Assisted-by: <Tool Name and Version>
```

Examples:

```text
Assisted-by: ChatGPT 5.6
Assisted-by: Claude Opus
Assisted-by: GitHub Copilot
```

Ordinary spelling correction, formatting, or trivial autocomplete does not require a disclosure unless a repository says otherwise.

### 3.3 Acceptance criteria

AI-assisted work may be accepted when:

- the contributor can explain the result;
- the change is appropriately scoped;
- tests and documentation are adequate;
- the contribution follows project architecture and style;
- copyright and software-license compatibility can be reasonably established; and
- there is no indication that the submission reproduces third-party material without permission or attribution.

Maintainers may request additional review, provenance information, tests, or a rewrite.

### 3.4 Prohibited uses

The following are not acceptable:

- fully automated pull requests with no meaningful human review;
- large generated changes that the submitter cannot explain;
- fabricated issue reports, test results, citations, APIs, features, or vulnerabilities;
- automated sweeping refactors without prior maintainer agreement;
- submitting generated code merely because it compiles;
- using AI tools to conceal the origin of copied code; or
- sending repository secrets, private keys, credentials, unreleased vulnerabilities, personal information, or confidential material to an AI service without authorization.

## 4. Copyright and software licensing

By contributing, you confirm that:

- you have the right to submit the material;
- the contribution is compatible with the repository's copyright license;
- required copyright notices and attributions are preserved;
- generated or assisted material has been reviewed for suspicious similarity to third-party code or text; and
- your use of the AI tool does not impose incompatible terms on the project.

If provenance or licensing cannot be reasonably established, maintainers may reject the contribution even when the code appears technically correct.

## 5. Contribution workflow

For non-trivial changes:

1. Open an issue or discussion first when the repository requests design coordination.
2. Agree on the goal and architecture before producing a large patch.
3. Keep pull requests focused and reviewable.
4. Add tests appropriate to the change.
5. Document security, privacy, protocol, or migration implications.
6. Disclose significant AI assistance as described above.

Unsolicited bulk changes may be closed without detailed review.

## 6. Security and privacy

Contributions must not introduce hidden telemetry, advertising trackers, opaque network requests, undisclosed data flows, or unnecessary dependencies.

Never put the following into an external AI system unless you are explicitly authorized to do so:

- passwords or recovery phrases;
- private keys or signing material;
- production credentials;
- private vulnerability reports;
- customer, donor, student, or user records;
- non-public source code covered by confidentiality obligations; or
- unpublished incident-response material.

Security-sensitive AI-assisted code should receive additional human review and testing.

## 7. Documentation

Pull requests and issue discussions should reflect the contributor's own understanding. Generated descriptions that are vague, inflated, repetitive, or inconsistent with the actual patch may be rejected or returned for revision.

Documentation must accurately describe what the software does, including limitations and known security or privacy tradeoffs.

## 8. Enforcement

Maintainers may request clarification or revision, reject contributions, close automated submissions, or limit participation when this policy is repeatedly ignored.

These decisions are made to protect project security, copyright and licensing integrity, maintainability, and the time of volunteer and paid maintainers.

## 9. Acknowledgement

This policy was informed by public contribution policies and discussions from projects including [Mastodon](https://github.com/mastodon/.github/blob/main/AI_POLICY.md), CloudNativePG, Ghostty, and the Linux Foundation.

---

This document is released under the [CC0 1.0 Universal Public Domain Dedication](https://creativecommons.org/publicdomain/zero/1.0/).
