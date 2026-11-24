# Contributing

Contributions to ghidra-65816 are welcome. All contributors are expected to follow the guidelines in this document.

## Before contributing

Please review the following documents:

- [DEVELOPMENT.md](DEVELOPMENT.md): Development workflow, testing, and pull request requirements.
- [AGENTS.md](AGENTS.md): Repository-wide technical and implementation guidelines.
- [CONTRIBUTORS](CONTRIBUTORS): Contributor attribution.
- [Supported scope](docs/SUPPORT.md): Supported functionality and project limitations.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): Community standards.

For substantial changes, new dependencies, or functionality outside the current project scope, discuss the proposed changes with the maintainer before implementation.

## Contributor attribution

First-time contributors submitting a pull request must add themselves to `CONTRIBUTORS` using their preferred display name or pseudonym and GitHub username.

Real-world names and personal information are not required. Existing contributors do not need to create another entry.

The maintainer will record the final commit hash and any relevant notes after the contribution is merged. Contributors are not expected to provide a final commit hash themselves.

When adapting external work, identify the original author and source in the pull request. The maintainer will verify and record the appropriate attribution.

Do not remove or modify another contributor's attribution without justification.

## Contribution licensing

This project is distributed under the [MIT License](LICENSE).

By submitting a contribution, you agree that your contribution is licensed under the MIT License and confirm that you have the necessary rights and permissions to submit it under these terms.

Contributors retain copyright over their respective copyrightable contributions. Submitting a contribution does not constitute a transfer of copyright ownership.

All applicable copyright, license, and attribution notices must be preserved.

Contributor registration is required for pull request acceptance. It does not determine or restrict the rights granted under the MIT License.

## External sources and third-party code

The project aims to remain MIT-licensed without unnecessary third-party licensing obligations.

Prefer MIT-licensed sources when incorporating or adapting external implementations.

Code or other material under a different license, including permissive licenses such as BSD, ISC, and Apache-2.0, requires prior maintainer approval before incorporation.

Copyleft-licensed code, including GPL, LGPL, and AGPL, must not be incorporated or bundled without prior approval and verification of its licensing implications. Exceptions will only be considered when genuinely necessary and compatible with the project's licensing objectives.

Do not incorporate proprietary or unlicensed material without appropriate permission.

External implementations under other licenses may be consulted as technical references where legally permitted. Referencing an implementation does not grant permission to reproduce its protected code.

Independently installed development tools, emulators, and test utilities may be used regardless of their license, provided their use does not introduce incompatible licensing obligations into the project.

When incorporating or adapting external material, provide the following in the pull request:

- Original repository or source.
- Original author and relevant commit or version.
- Applicable license.
- Description of the material incorporated or adapted.

These requirements also apply to third-party dependencies, test fixtures, generated code, and documentation.

Do not introduce separate licensing directories, bundled copyleft components, or additional licensing obligations without prior approval.

If the origin or licensing status of any material is uncertain, consult the maintainer before submitting it.

## AI-assisted contributions

The use of AI tools is permitted for development, research, debugging, testing, documentation, commit messages, and pull request descriptions.

Disclosure of AI assistance is optional.

Contributors remain responsible for understanding, reviewing, and validating everything they submit, regardless of how it was produced. AI-generated output is subject to the same technical, licensing, and attribution requirements as manually written material.

Contributions must be submitted under the responsibility of a human contributor.

### Commit authorship

AI tools and service providers must not be credited as authors, co-authors, or contributors solely for providing AI assistance.

Remove AI-generated `Co-authored-by` trailers from commits before submitting a pull request.

Do not include promotional acknowledgments, vendor branding, or automatically generated AI attribution in commit messages or contributed material.

This does not authorize the removal of legitimate human attribution or legally required third-party notices.

### Human communication

Issues, pull request discussions, code reviews, and other project discussions are intended for communication between people.

AI tools may be used to assist with research, translation, grammar, or technical references. However, contributors must communicate their own understanding and judgment.

Do not delegate entire conversations, technical explanations, or responses to review questions to AI systems. Do not use autonomous AI agents to participate in discussions on your behalf.

AI-generated or AI-assisted pull request descriptions are permitted, provided they accurately describe the submitted changes.

Contributors are expected to explain and justify their implementation decisions when requested. If you do not know the answer to a question, state that rather than presenting unverified AI-generated information as fact.

## Review and acceptance

All contributions are subject to maintainer review.

The maintainer may request changes, clarification, additional evidence, licensing verification, or corrected attribution before accepting a contribution.

Contributions may be rejected if they do not comply with the project's technical, licensing, attribution, or communication requirements.

Passing automated checks does not guarantee acceptance.

These guidelines govern contributions to this repository and do not impose additional restrictions on the rights granted under the MIT License.