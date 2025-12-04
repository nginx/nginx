# Contributing Guidelines

The following is a set of guidelines for contributing to nginx project.
We really appreciate that you are considering contributing!

## Table of Contents

- [Report a Bug](#report-a-bug)
- [Suggest a Feature or Enhancement](#suggest-a-feature-or-enhancement)
- [Open a Discussion](#open-a-discussion)
- [Submit a Pull Request](#submit-a-pull-request)
- [Issue Lifecycle](#issue-lifecycle)

## Report a Bug

To report a bug, open an issue on GitHub with the label `bug` using the
available [bug report issue form](/.github/ISSUE_TEMPLATE/bug_report.yml).
Please ensure the bug has not already been reported. **If the bug is a
potential security vulnerability, please report it using our
[security policy](/SECURITY.md).**

## Suggest a Feature or Enhancement

To suggest a feature or enhancement, please create an issue on GitHub with the
label `enhancement` using the available
[feature request issue form](/.github/ISSUE_TEMPLATE/feature_request.yml).
Please ensure the feature or enhancement has not already been suggested.

## Open a Discussion

If you want to engage in a conversation with the community and maintainers,
we encourage you to use
[GitHub Discussions](https://github.com/nginx/nginx/discussions) to discuss
the NGINX codebase or the [NGINX Community forum](https://community.nginx.org)
to chat anything else NGINX (including troubleshooting).

## Submit a Pull Request

Follow this plan to contribute a change to NGINX source code:

- Fork the NGINX repository
- Create a branch
- Implement your changes in this branch
- Submit a pull request (PR) when your changes are tested and ready for review

Refer to
[NGINX Development Guide](https://nginx.org/en/docs/dev/development_guide.html)
for questions about NGINX programming.

### Formatting Changes

- Changes should be formatted according to the
[code style](https://nginx.org/en/docs/dev/development_guide.html#code_style)
used by NGINX; sometimes, there is no clear rule, in which case examine how
existing NGINX sources are formatted and mimic this style; changes will more
likely be accepted if style corresponds to the surrounding code

- Keep a clean, concise and meaningful commit history on your branch, rebasing
locally and breaking changes logically into commits before submitting a PR

- Each commit message should have a single-line subject line followed by verbose
description after an empty line

- Limit the subject line to 67 characters, and the rest of the commit message
to 76 characters

- Use subject line prefixes for commits that affect a specific portion of the
code; examples include "Upstream:", "QUIC:", or "Core:"; see the commit history
to get an idea of the prefixes used

- Reference issues in the the subject line; if the commit fixes an issue,
[name it](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
accordingly

### Before Submitting

- The proposed changes should work properly on a wide range of
[supported platforms](https://nginx.org/en/index.html#tested_os_and_platforms)

- Try to make it clear why the suggested change is needed, and provide a use
case, if possible

- Passing your changes through the test suite is a good way to ensure that they
do not cause a regression; the repository with tests can be cloned with the
following command:

```bash
git clone https://github.com/nginx/nginx-tests.git
```

- Submitting a change implies granting project a permission to use it under the
[BSD-2-Clause license](/LICENSE)

### F5 Contributor License Agreement (CLA)

F5 requires all contributors to agree to the terms of the F5 CLA
(available [here](https://github.com/f5/f5-cla/blob/main/docs/f5_cla.md))
before any of their changes can be incorporated into an F5 Open Source
repository (even contributions to the F5 CLA itself!).

If you have not yet agreed to the F5 CLA terms and submit a PR to this
repository, a bot will prompt you to view and agree to the F5 CLA.
You will have to agree to the F5 CLA terms through a comment in the PR
before any of your changes can be merged. Your agreement signature
will be safely stored by F5 and no longer be required in future PRs.

## Issue Lifecycle

To ensure a balance between work carried out by the NGINX engineering team
while encouraging community involvement on this project, we use the following
issue lifecycle:

- A new issue is created by a community member

- An owner on the NGINX engineering team is assigned to the issue; this
owner shepherds the issue through the subsequent stages in the issue lifecycle

- The owner assigns one or more
[labels](https://github.com/nginx/nginx/issues/labels) to the issue

- The owner, in collaboration with the wider team (product management and
engineering), determines what milestone to attach to an issue;
generally, milestones correspond to product releases
