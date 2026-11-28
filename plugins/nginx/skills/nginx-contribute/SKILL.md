---
name: nginx-contribute
description: >-
  Contribute to NGINX: commit message subject prefixes and 72-character lines,
  code style, F5 CLA, PR expectations, and running the nginx-tests suite. Use
  when preparing commits, pull requests, or pre-submit validation for this
  repository.
---

# Contributing to NGINX

Follow `CONTRIBUTING.md` and the
[Development Guide](https://nginx.org/en/docs/dev/development_guide.html).
Submitting a change grants permission to use it under the BSD-2-Clause license
in `LICENSE`. F5 requires agreeing to the F5 CLA before merges into F5-owned
repositories.

## Commit messages

From `CONTRIBUTING.md` and the project history:

- Single-line **subject**, then a blank line, then a verbose **body**
- Limit subject and body lines to **72 characters**
- Use a **subject prefix** for the area touched. Common prefixes seen in this
  tree include `Core:`, `HTTP/2:`, `HTTP/3:`, `QUIC:`, `SSL:`, `Upstream:`,
  `Mail:`, `Resolver:`, `Misc:` — check `git log` for the subsystem you edit
- Explain **what** and **why**; reference behavior and impacted modules
- To close a GitHub issue, end with a trailer separated by a blank line, e.g.
  `Closes: https://github.com/nginx/nginx/issues/1234`

Example:

```
Upstream: reset peer timers when reconnecting after fail

When a peer was retried after an unsuccessful attempt, stale
response timers could fire against the new connection. Clear
the timers before reusing the peer structure.

Closes: https://github.com/nginx/nginx/issues/9999
```

Do not add AI/tooling attribution trailers (`Co-authored-by` for bots,
“Generated with …”, etc.) unless a human co-author truly applies.

## Code changes

- Match the surrounding code style; see Development Guide “Code style”
- Keep history clean: rebase locally, split logical commits before review
- Changes should work across supported platforms listed on nginx.org
- Prefer small, reviewable diffs with a clear use case in the PR description
- Use the repository PR template under `.github/` when opening a pull request

## Testing with nginx-tests

Regression testing uses the separate harness:

```bash
git clone https://github.com/nginx/nginx-tests.git
```

Typical flow after building `objs/nginx` in this repo:

1. Build NGINX with the modules your change needs (`auto/configure && make`)
2. From the `nginx-tests` checkout, run the relevant `.t` files with the
   built binary (see that repo’s README for `TEST_NGINX_BINARY` / prove usage)
3. Prefer targeted tests for the feature you touched; run a broader subset for
   risky core/HTTP changes

When adding user-visible behavior, expect new or updated tests in
`nginx-tests` (often as a follow-up or companion change).

## Practical pre-submit checklist

- [ ] `auto/configure` (with needed flags) and `make` succeed
- [ ] `objs/nginx -t` passes for affected configs
- [ ] Relevant `nginx-tests` cases pass
- [ ] Commit subjects have an area prefix and stay within 72 characters
- [ ] PR describes motivation and any configure/module dependencies
- [ ] Security-sensitive issues follow `SECURITY.md` (do not file public bugs
      for vulnerabilities)

## Agent guidance

- Prefer fixing style and commit form before asking for review
- When unsure about a prefix, copy the dominant prefix from recent commits in
  the same directory (`git log -- path`)
- Do not reformat unrelated code; minimize churn
- For documentation-only or agent-skills-only work, `Misc:` is an appropriate
  subject prefix
