# Working on nginx

Read [CONTRIBUTING.md](CONTRIBUTING.md) before preparing an issue or a
change; it is the contribution policy for everyone. The rules below cover
what coding agents commonly get wrong.

- When asked to fix or contribute a newly found, non-trivial problem that
  has no agreed issue, deliver the investigation and an issue draft first.
- Report only what you observed. Never invent command output, logs,
  versions, line numbers, or test results; label conclusions drawn only
  from reading code.
- Keep issue, PR, and commit message text short and specific. Do not
  restate the template, summarize the diff, or add generic background.
- Do not add AI tool attribution, such as `Co-Authored-By` trailers or
  "generated with" notes, to commits, issues, or PRs.

## Writing a fix

- Fix the cause, not only the place where it showed up. If the defect is
  a pattern that recurs elsewhere, fix the pattern rather than one
  instance, and report the scope you checked, including parallel code.
  If that makes the change large, describe the scope and agree on the
  approach with maintainers before writing it.
- Add nothing beyond the fix: no checks for conditions that cannot occur,
  single-use helpers or macros, extra logging, new configuration, or
  unrelated cleanup.
- Match the comment density of the surrounding code. Comment only what an
  experienced nginx developer cannot infer from the code or the relevant
  standard, and explain why, not what or how. Do not restate the code,
  describe the change, or add comments that only make sense in the
  context of the fix.
- Report which tests were run and skipped, and what was not tested; see
  the [nginx-tests README](https://github.com/nginx/nginx-tests/blob/master/README).
- Do not rewrite published history or force-push without the user's
  approval.
