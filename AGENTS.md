# Working on nginx

Follow [CONTRIBUTING.md](CONTRIBUTING.md): it describes when to open an
issue instead of a pull request and what a useful report contains. The
rules below cover what coding agents commonly get wrong.

- When asked to fix or contribute a newly found, non-trivial problem that
  has no agreed issue, deliver the investigation and an issue draft first.
- Report only what you observed. Never invent command output, logs,
  versions, line numbers, or test results; label conclusions drawn only
  from reading code.
- A harness calling an internal function with inputs nginx never passes
  is not a reproducer.
- Keep issue and PR text short and specific. Do not restate the template,
  summarize the diff, or add generic background.
- Do not add AI tool attribution, such as `Co-Authored-By` trailers or
  "generated with" notes, to commits, issues, or PRs.
- Report suspected vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md), never in a public issue or PR.

## Writing a fix

Read the [Code style](https://nginx.org/en/docs/dev/development_guide.html#code_style)
and [Common Pitfalls](https://nginx.org/en/docs/dev/development_guide.html#common_pitfals)
sections of the Development Guide.

- Write the smallest change that fixes the cause. Do not add checks for
  conditions that cannot occur, single-use helpers or macros, extra
  logging, new configuration, or unrelated cleanup.
- Comment only what an experienced nginx developer cannot infer from the
  code or the relevant standard. Explain why, not what or how.
- Report the scope you checked for other instances of the cause,
  including parallel code.
- For memory-related fixes, also run the tests with
  [AddressSanitizer](https://nginx.org/en/docs/dev/development_guide.html#debug_memory),
  including `NGX_DEBUG_PALLOC=1`.
- Report which tests were run and skipped, and what was not tested; see
  the [nginx-tests README](https://github.com/nginx/nginx-tests/blob/master/README).
- Do not rewrite published history or force-push without the user's
  approval.
