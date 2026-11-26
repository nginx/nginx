# nginx_plus

Research and upstream contributions improving nginx's load balancing (mainly the `least_time` balancer), based on queueing theory, simulation and real benchmarks. The goal is pull requests to nginx/nginx that maintainers can accept on evidence.

## North stars

- **Simulate first.** Every new balancing idea is tried in the simulator (`sim/`) before any C is written, and a feature isn't proposed without simulated evidence across the standard scenarios (and the robustness scenarios in `sim/explore/common.py`). The simulator must reproduce nginx's actual arithmetic, not an idealized version, and stays validated against queueing theory (`sim/validate.py`).
- **Confirm on real nginx.** Simulation results that matter are confirmed with the Linux benchmark (`bench/linux/`) on `-O2` builds.
- **Document failures too.** Ideas that don't work go into `results/rejected_ideas.md` with data, the reason, and what would change the verdict.

## Test-driven development

Follow TDD: write the failing test first, then the code that makes it pass, then clean up.

- **nginx C changes:** add or extend tests in nginx-tests (`upstream_least_time.t`, `stream_upstream_least_time.t`, ...) first and see them fail on the unpatched build, then implement. Run the full `upstream*.t` and `stream_upstream*.t` suites before calling a change done. In the Docker container, run as root with `TEST_NGINX_GLOBALS="user root;"` and use a build that has the rewrite module, or the least_time tests are skipped.
- **Simulator changes:** a new balancer or model gets a test before it is used in experiments, for example a check against a known closed-form result or a tiny hand-computed case. Keep `sim/validate.py` passing.

## Markdown

Don't hard-wrap Markdown: write each paragraph or list item on a single line and let the editor wrap it. GitHub renders line breaks in PR and issue descriptions as visible breaks, so wrapped text looks broken there. This applies to `.md` files, PR texts in `pr/`, and anything pasted into GitHub.

Wrapping rules that do apply elsewhere: git commit messages at 72 columns (nginx style), C code at 80 columns, nginx.org XML docs in their existing style.

## Conventions

- Workspace layout and status: see `PLAN.md` (PR status first) and `Docs.md` (layout, reports, how to reproduce).
- `work/` is the checkout of `least-time-work` and the single copy of the evidence files: the workspace-root `sim`, `bench`, `results`, `patches`, `pr`, `PLAN.md`, `Docs.md` and `CLAUDE.md` are symlinks into it. Edit and commit there.
- Benchmark runs are valid only if the load generator kept pace: the reports exclude runs whose send lag p99 is over 2 ms and over 3x the median of the same cell (a pause of the load generator, not of nginx), and such runs are re-run with the same seed.
- Docs go in `Docs.md`; never create or edit `README.md` or `TODO.md`.
- nginx commits: "Upstream:" prefix, subject plus explanatory body, HTTP and stream changed together. Keep the Claude co-authorship line on commits; PR texts carry no "Generated with Claude Code" line.
- Nothing goes to nginx/nginx, nginx-tests or nginx.org (issues, PRs, comments) without the user's go-ahead. Pushing to the fork github.com/psygo/nginx_plus is fine when asked.
- Exploration work lives on `explore/*` branches (worktrees in `wt/`), based on `least-time-work`; PR branches are `lt-fixed-point` (PR 1) and `lt-smooth` (PR 2).
- Benchmarks need an idle host: don't run simulations or test suites while `bench/linux` measurements are running.
- Public files must not contain local paths or personal details.
