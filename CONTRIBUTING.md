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

A useful report lets maintainers reproduce the problem and assess its
impact without guessing:

- Unexpected behavior is not necessarily a bug; state which documented
behavior or RFC requirement is violated

- Search earlier discussions, including the
[nginx-devel archive](https://mailman.nginx.org/pipermail/nginx-devel/) and
old [Trac tickets](https://trac.nginx.org/nginx/report); maintainers may have
already explained the behavior or declined the change, so link what you find
and address the stated position

- Reproduce the problem with nginx built from the latest `master`;
distribution packages and forks carry their own patches

- Provide a self-contained reproducer: a minimal configuration, exact
requests, and a local upstream script if one is needed; state whether it
reproduces every time and which versions and configurations were tested

- A sanitizer, fuzzer, or static-analysis finding needs a path from real
nginx input under a supported configuration

- Report one problem per issue

- Remove credentials, private key material, and other sensitive data from logs
before sharing them; put sanitized full logs in a gist, and quote in the issue
only the debug log lines that show the problem, with enough context to follow
them

- A root cause or a patch is not required; keep any source analysis separate
from what was observed, and check the code history with `git log -p` and
`git blame`, since odd-looking code is often deliberate

## Suggest a Feature or Enhancement

To suggest a feature or enhancement, please create an issue on GitHub with the
label `enhancement` using the available
[feature request issue form](/.github/ISSUE_TEMPLATE/feature_request.yml).
Please ensure the feature or enhancement has not already been suggested.

Describe the use case in detail: the deployment, the traffic, and what must
happen. Explain why existing directives, variables, `map`, or a combination
of them are insufficient, and search earlier discussions as described for
bug reports.

## Open a Discussion

If you want to engage in a conversation with the community and maintainers,
we encourage you to use
[GitHub Discussions](https://github.com/nginx/nginx/discussions) to discuss
the NGINX codebase or the [NGINX Community forum](https://community.nginx.org)
to chat anything else NGINX (including troubleshooting).

## Submit a Pull Request

Pull requests are welcome. Since every change is reviewed manually, it
helps to agree on the problem and the approach before investing in a
large patch. For anything beyond a small fix with an evident cause, open
an issue or a discussion first: maintainers can confirm that the change
is needed and suggest the right direction, which saves review rounds for
both sides. This is especially important for new features and for changes
to the behavior of existing configurations or to defaults.

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
locally before submitting a PR; make one commit per logical problem,
containing its complete fix, and put necessary preparatory refactoring in a
separate commit with no behavior change; every commit must build and work on
its own

- Each commit message should have a single-line subject line followed by verbose
description after an empty line; the description explains what was wrong,
how it shows up, and why the fix is correct, citing the RFC section when one
applies

- Address review comments by revising the original commits rather than adding
fix-up commits

- Limit the subject and commit message body lines to 72 characters

- Use subject line prefixes for commits that affect a specific portion of the
code; examples include "Upstream:", "QUIC:", or "Core:"; see the commit history
to get an idea of the prefixes used

- If the commit fixes an open issue then you can use the "Closes:" tag/trailer
to reference it and have GitHub automatically close it once it's been merged.
E.g.:

  `Closes: https://github.com/nginx/nginx/issues/9999`

  That should go at the end of the commit message, separated by a blank line,
  along with any other tags.

### Before Submitting

- The proposed changes should work properly on a wide range of
[supported platforms](https://nginx.org/en/index.html#tested_os_and_platforms)

- Try to make it clear why the suggested change is needed, and provide a use
case, if possible

- Fix the root cause and every instance of the same cause; parallel code
often needs the same change: proxy, fastcgi, uwsgi, scgi, and grpc; HTTP,
stream, and mail; HTTP/2 and HTTP/3; report similar but independent problems
separately

- A new directive is permanent API: name it after existing ones (`*_timeout`,
`*_buffer_size`, `$upstream_*`) and prefer a sensible default where possible

- Passing your changes through the test suite is a good way to ensure that they
do not cause a regression; a regression test should fail without the fix and
pass with it. A test is not required up front: a test or reproducer in the
issue or PR is enough to start review. The repository with tests can be
cloned with the following command:

```bash
git clone https://github.com/nginx/nginx-tests.git
```

- For memory-related changes, also run the tests with
[AddressSanitizer](https://nginx.org/en/docs/dev/development_guide.html#debug_memory),
including `NGX_DEBUG_PALLOC=1`

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
