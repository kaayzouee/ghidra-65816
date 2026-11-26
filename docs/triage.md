# Labeling and human triage

## Initialize after merge

A maintainer with write access sends a repository dispatch using an existing authenticated GitHub CLI session:

```sh
gh api --method POST repos/kaayzouee/ghidra-65816/dispatches -f event_type=create-triage-labels
```

Inspect **Actions → Create missing triage labels**. Dispatch acceptance only acknowledges the request. The job uses its own built-in token. Its summary lists initially missing labels and counts created, skipped and conflicting entries. Repeat the dispatch to verify zero creations. A repository dispatch executes the default-branch workflow, accepts no workflow ref and requires contents write from the sender. The job additionally checks for master and ignores client payloads. [Dispatch API](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event)

[The catalog](../.github/triage/labels.json) defines 36 labels. A single capitalization variant resolves to the existing ID, preserving spelling, color and description. Multiple IDs for one normalized name require manual investigation. After a partial failure, check permissions or wait for a rate limit to reset, then redispatch. Concurrent creation is accepted only after GitHub returns the expected existing entry.

| Prefix | Choices |
| --- | --- |
| type | bug, enhancement, feature, documentation, testing, refactor, discussion |
| area | sleigh, pcode, cpu-context, registers, control-flow, memory, decompiler, loader, compatibility, ci, tests, scripts |
| priority | critical, high, medium, low |
| status | needs-triage, needs-repro, needs-review, needs-test, confirmed, blocked, wontfix |
| cpu | bank-boundary, status-flags, native-mode, emulation-mode |
| platform | snes, 65802 |

## Opening classification

**Issues.** GitHub applies the legacy bug or enhancement label and corresponding prefixed form type at submission. The opening workflow requests `status: needs-triage`. It reads the first dropdown only if the opening and current form types support it and the body is unchanged. Multiple areas are allowed. Selecting **documentation** adds `type: documentation` alongside the report type. Unknown choices, **unsure** (even alongside a known choice), duplicate headings, unexpected layout, legacy forms and missing types defer classification. If a type was missing at submission, a maintainer supplies it manually. Report suspected vulnerabilities privately using [SECURITY.md](../SECURITY.md).

**PRs.** New PRs targeting master enter the same triage queue, including fork PRs and unmatched paths. [Path rules](../.github/triage/paths.json) recognize added, modified and deleted files and both sides of renames. On PRs, documentation requires every affected path to qualify. Dedicated files identify build, test, script and processor areas. Shared instruction includes contain both decoding and semantics. Reviewers decide which specific instructions, flags or CPU modes a change affects. There are no loader implementation paths.

The file lookup reads pages of 100 and checks distinct paths, counts and the opening head and base revisions against a fresh PR read. At 3,000 files, or when the snapshot is inconsistent, review the complete diff manually. The job still requests triage. A file API failure also attempts triage and records a failed job. File pages and label mutation do not share a transaction. [PR file API](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files)

## Human review and recovery

1. Review the report or diff and the workflow summary. Correct labels in the **Labels** sidebar. Maintainers decide reproduction, priority, severity, testing and technical disposition.
2. Remove `status: needs-triage` after review. Bug confirmation and PR approval require separate decisions.
3. Recover a failed opening run from **Actions → failed run → Re-run failed jobs**. Inspect current labels first. Provision missing entries, resolve permission problems or wait for rate limits as appropriate. The rerun uses the original event revision. Finish manually if GitHub's rerun window has elapsed, the classifier needs a newer revision, or the item's scope has changed. A fresh attempt reads state before writing again, including after a timeout with an uncertain mutation outcome. [Rerun behavior](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
4. A closed item, recorded closure, or **any prior label removal** hands the entire item to maintainers. This conservative rule also covers renamed labels and reopenings. Otherwise the job skips current labels and historically assigned candidates and adds only eligible existing IDs. Failure to read history prevents the write. Per-item concurrency serializes workflow attempts. A human can still edit between the final history read and mutation. Make final corrections after the run finishes.

The summary reports catalog candidates, current, historical, missing, conflicting and applied labels as applicable. Missing or ambiguous candidate definitions mark the job failed even when other labels were added. Edits, pushes, reopens and label changes do not start another classification.

## Security and CI

| Operation | Permissions and inputs |
| --- | --- |
| Issue classification | Contents read for checkout. Issues write for the additive GraphQL mutation and reads of issue state, events and repository labels. |
| PR classification | Contents read. Pull requests write for the PR mutation and reads of the issue representation, events, labels, PR metadata and files. |
| Provisioning | Contents read. Issues write for REST label creation and lookup. Only a default-branch administrative dispatch runs this code. |
| Rule tests | Read-only PR workflow, without secrets or persisted checkout credentials. It runs on ordinary PR activity without a paths filter so the check can finish for any PR. |

The privileged PR workflow uses `pull_request_target` so forks can be labeled from reviewed base code. Checkout uses the trusted event SHA. Never check out the fork or load its classifier in this job. File names and form input are data. Only catalog areas, documentation and initial triage can reach the mutation. Action references are pinned. Summaries use catalog names and fixed diagnostics. GitHub token scopes are coarse: classification code uses existing IDs and exposes no create operation to contributor input. Verify effective mutation permissions during deployment. [Workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) · [Label permissions](https://docs.github.com/en/rest/issues/labels) · [Issue events](https://docs.github.com/en/rest/issues/events) · [GraphQL mutation](https://docs.github.com/en/graphql/reference/issues#addlabelstolabelable)

Run `node --test .github/triage/classify.test.cjs` with Node 24. Update both form dropdowns and tests when adding areas. The SLEIGH workflow retains its default PR activities and master push trigger. Full SingleStep remains manual.

## Post-merge smoke test

Use approved examples or the next genuine contributions. Record run links and before/after labels.

1. Snapshot existing names, IDs, colors and descriptions using `gh api --paginate repos/kaayzouee/ghidra-65816/labels`. Dispatch provisioning twice. Check all 36 definitions, zero second-run creations and preservation of the snapshot. This verifies actual administrative token REST writes.
2. Open an authorized issue through a form with two selections. Verify the generated Markdown, actual type, both areas, triage and job summary.
3. Verify documentation and triage on a new documentation-only PR to master. Verify triage and the expected areas on a fork PR touching several components. Compare the trusted checkout revision, successful mutation summary and resulting sidebar labels. This exercises both classification token scopes.
4. Correct an area, assign a manual priority, and remove triage. Explicitly rerun the opening job and verify all corrections survive. Compare SLEIGH run IDs before and after manual and automated label changes. Ordinary PR events should account for the processor checks.
5. Recover an actual failed opening job following the instructions above. To exercise missing labels deliberately, use an authorized disposable repository before provisioning, provision, then rerun that opening job. Verify partial successes persist and reviewed items remain untouched. Keep production definitions intact.

## Rollback

Disable the two classification workflows and provisioning workflow in Actions for immediate containment. Revert the PR through normal review to remove the integration and restore the prior issue forms. Existing issues, PRs and catalog entries retain their labels. Any cleanup is a separate maintainer decision.
