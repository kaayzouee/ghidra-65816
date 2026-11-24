# Security Policy

## Supported versions

Security fixes are primarily applied to the current `master` branch and subsequent releases. Older releases are not guaranteed to receive backports. Use the latest available release with a compatible Ghidra version.

## Scope

Security reports may include:

- Arbitrary host code execution or unauthorized access to files or sensitive data.
- Unsafe handling of malformed or untrusted inputs, including resource exhaustion with a demonstrable security impact.
- Unauthorized modification or destruction of Ghidra project data.
- Security vulnerabilities in project-maintained scripts, loaders, analyzers, build configurations, CI workflows, dependencies, or distributed extension artifacts.

Ordinary CPU semantics errors, incorrect disassembly, unsupported functionality, and [documented limitations](docs/SUPPORT.md) should be reported through [GitHub Issues](https://github.com/kaayzouee/ghidra-65816/issues) unless a specific security impact can be demonstrated.

Vulnerabilities in Ghidra itself should be reported to the [upstream Ghidra project](https://github.com/NationalSecurityAgency/ghidra/security).

## Reporting a vulnerability

Submit suspected vulnerabilities privately through the project's [GitHub Security Advisories](https://github.com/kaayzouee/ghidra-65816/security/advisories) page using the **Report a vulnerability** option. If this option is unavailable, contact the maintainer privately using an available contact method before sharing sensitive details.

Include, where applicable:

- Affected module release or commit, Ghidra version, and environment.
- Description of the issue, prerequisites, and security impact.
- Reproduction steps, a minimal proof of concept, and relevant logs.

Do not include credentials, personal information, or unrelated proprietary material. Test only against systems and data you are authorized to use.

Please allow a reasonable opportunity for investigation and remediation before publicly disclosing exploitable details.

## Response and disclosure

This project is maintained on a best-effort basis. Response times, remediation deadlines, and fixes for older releases are not guaranteed.

Verified reports may receive attribution under the researcher's preferred display name or GitHub username, unless anonymity is requested.

This project does not operate a paid bug bounty program.
