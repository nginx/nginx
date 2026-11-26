# Queueing-theory improvements to nginx load balancing: plan

Workspace layout:

- `nginx/`: upstream clone of github.com/nginx/nginx (1.31.11, master at 6d81cb7c6). Branch `lt-trace` has the trace logging plus compile-time experiment knobs (`NGX_LT_BUCKET`, `NGX_LT_FP`, `NGX_LT_ALPHA`, `NGX_LT_TAU`). Build dir is `objs-debug`.
- `nginx-fp/`: worktree, branch `lt-fixed-point`, holds patch 1 (uncommitted)
- `nginx-bucket/`: worktree, branch `lt-bucket`, holds patch 1 (staged) and patch 2 (unstaged)
- `nginx-smooth/`: worktree, branch `lt-smooth`, holds patches 1+2 (staged) and patch 3 (unstaged)
- `nginx-tests/`: clone of nginx/nginx-tests. Branch `lt-bucket` holds the new bucket and smooth tests (uncommitted).
- `nginx.org/`: clone of nginx/nginx.org (docs), branch `least-time-bucket-smooth`
- `patches/`: exported diffs of the patches, tests and docs
- `sim/`: discrete-event simulator (`lbsim.py`), experiments (`experiments.py pr|sweep|...`), PR report (`report_pr.py`)
- `bench/`: macOS real-nginx harness (Python); `bench/linux/`: the Linux (Docker) harness used for the PR evidence: Go backend and load generator, `run.py`, `matrix.sh`, `report_linux.py`
- `build/`: `mkvariant.sh` (run from `nginx/`), `bin/nginx-<variant>`
- `results/`: `sim_pr.md`, `linux_pr.md` (the PR evidence reports), their JSON/JSONL and SVG figures, older `sim_<h>.json` and `*_real.jsonl`
- `pr/`: commit messages and PR descriptions (`PR1.md`, `PR2.md`)
- `PLAN.md`: this file. PR status first, then findings (section 0), then the original plan.

## PR status (2026-11-26)

Two PRs to nginx/nginx, decided with the user:

- **PR 1, bug fix:** patch `0001` (fixed-point averages). Description in `pr/PR1.md`, commit message in `pr/commit-1-fixed-point.txt`.
- **PR 2, features:** patches `0002` (`bucket=time`) and `0003` (`smooth=time`, weight `min(1, max(0.01, elapsed/smooth))`, 0.01 floor fixed in code), on top of PR 1. Description in `pr/PR2.md`. Companion PRs: nginx-tests (`patches/tests-pr2-...`) and nginx.org docs (`patches/docs-pr2-...`, version 1.31.12 is a placeholder).

Evidence:

- Simulator matrix (`results/sim_pr.md`): 12 scenarios × 4 loads × 7 balancers, 20 paired seeds × 300k requests. P1 is within ±2 %. P1+P2+P3 (b5, s3) gives −2…−46 % p99 on heterogeneous backends and −8…−15 % on bimodal. Regressions are at most +6 % (slowdown_ps@0.85; slow3@0.5 +4 %). The sweep picks bucket 5 / smooth 3 s, and smooth 1 s is bad for slow backends.
- Linux real-nginx matrix (`results/linux_pr.md`): 18 configurations × 6 variants × 5 paired reps, 540 runs, 0 errors, and the sim matches within a few percent.
  - P1 is −4…+4 %.
  - P1+P2+P3 gives −9…−44 % on heterogeneous backends, −11…−14 % on bimodal, and −12 % on slowdown; it is never significantly worse than stock or than least_conn.
- nginx-tests: `upstream*.t` and `stream_upstream*.t` pass on macOS/clang and Linux/gcc 14 (`-Werror`, run as root with `TEST_NGINX_GLOBALS="user root;"`).

Pushed 2026-11-26 to the fork github.com/psygo/nginx_plus (remote `fork` in `nginx/`): `lt-fixed-point` (PR 1), `lt-smooth` (PR 2: P1, bucket, smooth), `lt-bucket`, `lt-trace` (experiment only) and the orphan `least-time-evidence` branch (Docs.md, sim, bench, results, patches, pr). The nginx-tests and nginx.org changes are committed locally only; pushing them needs forks of those repos.

Remaining (the user said not to open PRs yet):

1. Open the PRs (F5 CLA on the first), then fill in the cross-references (`#PR1`, `#PR2`, `#TBD`).
2. Fork nginx-tests and nginx.org, push their branches, open the companion PRs.

## Explorations (2026-11-26)

Six `explore/*` branches, each with code, tests, results and report, have PRs inside the fork (base `least-time-work`, not nginx). The simulations used 10 paired seeds × 200k requests and the 6 robustness scenarios where relevant.

| PR | branch | verdict |
| --- | --- | --- |
| [#1](https://github.com/psygo/nginx_plus/pull/1) | `explore/zone-workers` | Without `zone`, 4 workers cost least_conn +16…36 % and patched least_time +11…20 % p99 on real nginx; the sim agrees. Docs note drafted locally on an nginx.org branch (`zone-workers-note`). |
| [#2](https://github.com/psygo/nginx_plus/pull/2) | `explore/speed-estimator` | Learning `rt = a + b·conns` nearly matches the true-capacity rule, but diverges on processor-sharing backends near saturation (+642 %). Next: lower bound on the slope. |
| [#3](https://github.com/psygo/nginx_plus/pull/3) | `explore/cost-routing` | With exact per-class cost hints, least-work routing gives −15…−58 %. It degrades with noisy hints and needs a way for nginx to get the hint. |
| [#4](https://github.com/psygo/nginx_plus/pull/4) | `explore/admission-control` | `max_conns` / `queue` cut the tail a lot, but this is existing (or NGINX Plus) functionality, so at most a docs note. |
| [#5](https://github.com/psygo/nginx_plus/pull/5) | `explore/learning-augmented` | A least_time shortlist bounds damage (+43 % worst vs +1625 % without), per decision rather than per outcome; eps 0.25 trades −16 %/+16 %. Research only. |
| [#6](https://github.com/psygo/nginx_plus/pull/6) | `explore/smooth-weighting` | Unbiased `smooth=` weightings give no better p99 (+0.4…+1.9 %), so PR 2 stays unchanged. Rejected (`rejected_ideas.md` §5). |

## 0. Findings so far (2026-11-25)

### The integer EWMA has a ±10 ms dead band

`ngx_http_upstream_response_time_avg` stores whole milliseconds with alpha 0.05 and +0.5 rounding. A sample changes the average only if `|v - avg| * 0.05 >= 0.5`, that is, if it differs from the average by at least 10 ms. A backend's estimate therefore sticks anywhere within ±10 ms of its true time, and fast backends ratchet up to about 10 ms and stay there. This shows directly in real nginx: on backends taking about 4.7 ms, the stock trace reads `hdr=10` on every selection, while the fixed-point build tracks 4.7 ms. It is a correctness bug, but at the default 20 ms bucket it is mostly hidden. It becomes the limiting factor as soon as the bucket is made smaller.

### Hypotheses

| # | Verdict | Evidence |
| --- | --- | --- |
| H1 bucket | **Confirmed.** Sim and real nginx agree. | fast3 (2/6/15 ms) at 50 % utilization, p99: lc 60.7, stock lt 47.1, bucket 1 (int) 40.1, bucket 1 + fixed point 25.2. Real nginx at 250 rps: lc 66, lt 48, fp_b1 31. No regression on homogeneous or slow backends. |
| H2 no zone | **Confirmed.** Smaller effect on macOS. | Sim homog8 at 0.7: lc 54 with a zone vs 87 with 8 private workers. Real macOS: about 13 % (accept is skewed across workers). Expect it to be larger on Linux with `reuseport`. Documentation or warning material, not code. |
| H3 SED / service rate | **Rejected as a default.** | Helps FCFS backends (-15 to -22 % vs lt), hurts processor sharing (104 vs 85 at 0.7) and equal servers with mixed requests. Peak EWMA is about equal to lt with bucket 1. Details: `results/rejected_ideas.md`. |
| H4 EWMA | **Confirmed**, as alpha/tau. | Stock lt is worse than lc on bimodal traffic (sim 317 vs 268, real 307 vs 277). A smaller bucket makes it worse (360) because EWMA noise becomes visible. alpha 0.01 with a 3 s time floor fixes it (286) and keeps the gains. |
| H5 random two least_time | **Rejected on latency.** | big64 at 0.7: 75 vs 41 for full least_time. CPU and lock contention are not modeled; revisit only if lock contention shows up on Linux. Details: `results/rejected_ideas.md`. |
| H6 least_work | **Promising, out of tree.** | Bimodal heterogeneous: about −40 % p99 vs lc and lt with learned per-class cost; about −30 % at σ=0.5 estimation error. It needs cost hints, so it belongs in a dynamic module. |

### Staged-patch simulation (p99 ms, 5 seeds, ±95 % CI in `results/sim_staged.json`)

| scenario | lc | stock lt | P1: fp | P1+P2: fp, b5 | P1+P2+P3: fp, b5, α .01, τ 3 s | fp, b1, α .01, τ 3 s |
| --- | --- | --- | --- | --- | --- | --- |
| fast3 @0.5 | 60.7 | 47.1 | 48.2 | 26.8 | **25.4** | 24.5 |
| fast3 @0.85 | 126.2 | 79.7 | 79.7 | 72.9 | **68.3** | 66.5 |
| hetero8 @0.7 | 71.4 | 59.4 | 59.1 | 52.7 | **50.1** | 49.3 |
| hetero8 @0.9 | 115.0 | 96.0 | 96.2 | 90.8 | **85.6** | 85.1 |
| big16 @0.7 | 59.8 | 53.5 | 53.6 | 46.9 | **45.7** | 44.4 |
| slow3 @0.7 | 816.2 | 410.8 | 410.4 | 402.8 | **381.1** | 377.9 |
| bimodal4 @0.5 | 267.8 | 316.8 | 315.1 | 347.8 | **285.4** | 285.7 |
| bimodal4 @0.85 | 637.2 | 735.1 | 726.4 | 745.8 | **666.3** | 649.0 |
| bimodal4_het @0.7 | 487.1 | 464.8 | 476.6 | 498.2 | **393.1** | 395.1 |
| slowdown, during | 229.6 | 141.3 | 142.8 | 135.3 | **128.7** | 124.1 |
| homog8 @0.85 | 70.6 | 76.9 | 76.0 | 71.1 | **70.7** | 70.5 |
| fast3_homog @0.85 | 60.5 | 62.5 | 62.6 | 61.4 | **61.2** | 60.9 |

How to read it:

- P1 alone is neutral, so it is safe as a pure bug fix.
- P2 gives the gain on heterogeneous backends but needs P1: integer bucket 1 reaches 40 at fast3, against 25 with fixed point.
- P2 alone worsens bimodal traffic; P3 removes that, leaving least_time within about 6 % of lc there (285 vs 268) instead of 18 % worse.
- With all three, least_time is never worse than stock and never worse than lc on homogeneous traffic.
- Bucket 5 and bucket 1 are within noise of each other. Bucket 5 keeps more of the 20 ms bucket's re-probing behavior (see below), so it is the better recommendation.

### Patches (in `patches/`, uncommitted)

1. **`0001` fixed-point averages** (HTTP and stream): averages are stored in 1/64 ms, converted back to ms in eta before the 5000 cap and the bucket. They saturate at `NGX_MAX_INT32_VALUE` (9.3 h) instead of overflowing on 32-bit. Default selection is otherwise unchanged. It builds with -Werror and passes all upstream/stream tests (427), including `TEST_NGINX_UNSAFE`.
2. **`0002` `least_time header|last_byte [inflight] [bucket=time]`** (HTTP and stream): the default is 20 ms, and values above 5 s or equal to 0 are rejected. New tests are in `tests-0002-least_time-bucket.patch`; the full suite passes with 429 tests.
   - **Caveat found by the tests:** with `bucket=1`, the existing "response time decay probe" test fails. The 20 ms bucket is also what lets a decayed slow peer tie with a fast one and be probed again; with a 1 ms bucket the decayed peer has to reach about 0 first. This is why the default must stay at 20 and why the docs should recommend 5 ms, not 1 ms.
   - The new tests sit inside the existing `.t` files, so on an nginx without the parameter the whole file skips at `try_run`. Maintainers may prefer a separate file or a version gate.
3. **Smoothing:** since written as `0003` `smooth=time` (see PR status above). Original note: alpha 0.01 per sample with a time floor `alpha = max(0.01, dt/3 s)`. Plain alpha 0.01 gets most of the benefit; the floor matters for low-rate peers and transient slowdowns (slowdown at 0.3 utilization, during window: alpha .005 → 70, alpha .01 → 62, plus τ 3 s → 56). How to expose it (two knobs, one `smoothing=` knob, or a changed default) is a design call to settle with the maintainers in the issue before writing code.

Experiment-only prototype: `nginx/` branch `lt-trace` (FP scale 1000, compile-time knobs).

### Real-nginx A/B (`results/fp_real.jsonl`, `bench/exp_fp.sh`)

macOS, `-O0` trace builds of `lt-trace` (FP scale 1000), one worker, Python FCFS backends, open-loop Poisson load, 3 seeds × 20 s, p99 ms ±95 % CI.

| fast3 (2/6/15 ms) | lc | stock lt | fp b20 | fp b1 | fp b1 α .01 τ 3 s |
| --- | --- | --- | --- | --- | --- |
| 250 rps p99 | 66.2 ±3.9 | 48.0 ±3.4 | 47.2 ±3.7 | 30.8 ±5.2 | **28.6 ±1.1** |
| 450 rps p99 | 89.4 ±1.9 | 63.2 ±5.6 | 63.3 ±1.9 | **48.5 ±4.0** | 49.4 ±4.6 |
| 250 rps mean | 10.2 | 8.7 | 8.8 | 6.8 | 6.5 |

This matches the simulator: fixed point alone is neutral at the default bucket, and fixed point with a small bucket cuts p99 by 23–40 % vs stock least_time and 45–57 % vs least_conn.

Bimodal (4 equal backends, 90 % at 2 ms and 10 % at 80 ms), 8 seeds × 30 s on an idle machine (`results/fp_bimodal_real.jsonl`). The first 3-seed run in `fp_real.jsonl` overlapped other jobs and is too noisy to use.

| bimodal4 | lc | stock lt | fp b1 | fp b1 α .01 τ 3 s | fp b5 α .01 τ 3 s |
| --- | --- | --- | --- | --- | --- |
| 205 rps p99 | 299.6 ±28.3 | 339.0 ±24.9 | 359.8 ±51.7 | 311.9 ±35.2 | **279.1 ±19.0** |
| 205 rps mean | 25.2 | 33.2 | 37.5 | 27.4 | **25.1** |
| 285 rps p99 | 452.2 ±60.3 | 600.0 ±116.7 | 461.5 ±64.3 | **445.3 ±47.7** | 482.5 ±68.2 |
| 285 rps mean | 54.5 | 82.4 | 66.0 | 56.0 | 56.2 |

This also matches the simulator:

- Stock least_time is worse than least_conn on mixed-cost traffic.
- A small bucket without smoothing doesn't fix that.
- With alpha 0.01 and τ 3 s, least_time is back at least_conn's level: about −18 % p99 vs stock at 205 rps and −26 % at 285 rps. It keeps the 23–40 % gains on heterogeneous backends.

**Recommended configuration to propose:** fixed point (P1) + `bucket=5ms` (P2) + smoothing alpha 0.01 with a 3 s time floor (P3).

### Next steps

1. Open an upstream issue with the dead-band analysis, the traces and the staged tables; ask which interface they prefer for P2 and P3. Then send P1 (smallest, pure fix) first.
2. Linux host: re-run H2 (workers with `reuseport`) and the real A/B at higher rates with optimized builds. All macOS numbers here come from `-O0` debug builds and Python backends.
3. `least_work` dynamic module (H6).
4. Documentation PR (nginx.org) for `zone` with multiple workers.

## 1. What the code actually does

The ChatGPT research was mostly right about the shape of things, but the source shows several details it missed or got wrong. Ground truth from `src/http/modules/ngx_http_upstream_least_time_module.c`:

- **Score:** `eta = rt_bucketed * (1 + conns)`, compared as `eta * best->weight < best_eta * peer->weight`. `rt` is an EWMA of `header_time` or `response_time` (`least_time header|last_byte [inflight]`).
- **EWMA** (`ngx_http_upstream_response_time_avg`, round_robin.h:251): fixed alpha 0.05 **per sample**, not per unit of time. A peer at 10 rps adapts 100x slower in wall-clock time than one at 1000 rps. An average of 0 means "unmeasured", so the first sample replaces it outright.
- **Buckets:** `rt += 20 - rt % 20`, capped at 5000 ms. Consequence: **for any backend faster than 20 ms, every peer gets `rt = 20` and `least_time` becomes exactly weighted `least_conn`.** Above 5 s it also degrades to `least_conn`.
- **Decay:** `rt >>= (now - checked) / (fail_timeout + 1)`. This is the known UB shift (issue #1675, fix already under review in PR #1679). **Not ours to fix**; it has to be controlled for in experiments.
- **Inflight mode:** the `inflight_time` EWMA is updated *for every candidate peer on every selection* (inside the scan loop). Its convergence speed therefore depends on the upstream's total request rate, not on events at that peer.
- **Only successful attempts** update the averages. A peer that fails fast never looks fast.
- **Locking:** the whole O(N) scan runs under `ngx_http_upstream_rr_peers_wlock`. With `zone` that is a write lock shared by every worker process.
- **Per-worker state:** without `zone`, each worker process keeps its own `conns` and EWMAs. `worker_processes 8` therefore means **8 independent dispatchers inside one nginx**. This is the multi-dispatcher herd problem ChatGPT left for "later". It shows up in the default config.
- **`random two`** supports only `least_conn` in open-source nginx (`random_module.c:562`). NGINX Plus has `random two least_time=…`. That is a concrete feature gap.
- The stream module (`src/stream/ngx_stream_upstream_least_time_module.c`) mirrors all of this, so any change has to land in both.

### Corrections to the ChatGPT write-up

- Its simulated "Least Time" did not reproduce EWMA alpha, decay, inflight accounting or smooth WRR, and its result files are not available. **The 19–29 % p99 gains are unverified.** Re-derive them.
- The M/M/1 argument that `(L+1)·R ~ mu/(mu-lambda)^2` mixes stationary means with the instantaneous `conns`. It is a useful intuition about double-counting congestion, nothing more. The simulator is where it gets tested.
- Peak EWMA ships in Finagle, Linkerd and ingress-nginx (`load-balance: ewma`, Lua). Envoy's default is P2C least-request, not Peak EWMA.
- Multi-*instance* distributed dispatch stays out of scope. Multi-*worker* dispatch is in scope: it is cheap and real.

## 2. Hypotheses, ordered by cost to test

| # | Hypothesis | Why we believe it | Cheapest test |
| --- | --- | --- | --- |
| H1 | For sub-20 ms backends, `least_time` gives no benefit over `least_conn`; a smaller or relative bucket recovers it | Follows directly from `rt += 20 - rt % 20` | Sim, then real bench |
| H2 | Without `zone`, N workers degrade `least_conn`/`least_time` toward random; `zone` closes most of the gap | Independent per-process state | Sim with N dispatchers, then real bench |
| H3 | `R·(1+n)` double-counts queueing on FCFS/limited-worker backends. A service-rate estimate (e.g. `S ≈ R/(1+n_at_dispatch)`) adapts better to recovery and transient slowdowns | R already contains the wait | Sim across backend models (FCFS, c-server, processor sharing) |
| H4 | Per-sample EWMA misbehaves under uneven rates; a time-decayed EWMA (Peak-EWMA-like) adapts more consistently. Unmeasured peers (avg 0) get flooded at cold start | alpha is per sample; 0 means unmeasured | Sim: rate steps, peer add/recover |
| H5 | `random two least_time` keeps most of `least_time`'s tail benefit at O(1) cost and with less lock contention | P2C theory; Plus already ships it | Sim + CPU/lock profiling in real nginx |
| H6 | "Least work" (sum of per-class cost estimates) beats both on mixed-cost traffic, and stays ahead under moderate estimation error | JSW/SITA literature; ChatGPT sim | Sim, with error sweep σ and a hybrid γ |

Kill criterion for each: if the simulator shows < 5 % p99 improvement at 70–95 % utilization in the target scenario, or a > 2 % regression on homogeneous traffic, drop it.

## 3. Steps

### Phase 0: Setup (about half a day)

1. Build nginx twice: a debug build (`--with-debug --with-http_stub_status_module --with-stream`) and an optimized build with UBSan available.
2. Clone `nginx/nginx-tests`. Run `upstream_least_time.t`, `upstream_least_conn.t`, `upstream_random.t` and the stream equivalents against our build as a baseline.
3. Decide the benchmark host: macOS is fine for development and the simulator; final numbers need bare Linux (see open decisions).

### Phase 1: Observe the real algorithm (1 day)

4. Add a throwaway debug patch that logs `(peer, rt, bucketed rt, conns, eta, chosen)` per selection. This is the oracle for validating the simulator.
5. Run small scripted scenarios (2–4 local backends with fixed sleeps or CPU loops) and record traces. Confirm H1's degeneracy and H2's per-worker divergence directly from the logs.

### Phase 2: Faithful simulator (2–3 days), in `sim/`

6. Write a Python discrete-event simulator (stdlib plus numpy) with:
   - balancers: RR (smooth WRR), least_conn, least_time {header, last_byte} × {plain, inflight}, random two least_conn, plus candidates: random two least_time, bucket variants, service-rate estimator, time-decayed EWMA, least_work, hybrid;
   - an exact port of the eta/EWMA/decay/tie-break logic, kept to a line-by-line mapping with the C code;
   - K dispatchers with private or shared state (models `worker_processes` with and without `zone`);
   - backend models: FCFS single worker, c-worker pool, processor sharing, sleep (I/O-bound);
   - workloads: homogeneous, bimodal (90/10), lognormal, heavy-tailed (Pareto), bursts, capacity steps (throttling, recovery), peer added mid-run;
   - open-loop Poisson arrivals, warm-up discard, many seeds, paired comparisons with 95 % CIs.
7. Validate by replaying the Phase 1 scenarios. The selection distribution must match the nginx traces before any result counts.

### Phase 3: Run the hypotheses in the simulator (2–3 days)

8. Run H1→H6 in order. Each produces a short results note (table plus chart) and a go/no-go call.
9. Go/no-go review together: choose which changes are worth C code.

### Phase 4: Implement in C (per accepted change)

10. **`random two least_time=header|last_byte`** in the HTTP and stream random modules. Plus has this, it is self-contained and it is the most likely to be accepted upstream. Do it even if other hypotheses fail, provided H5 holds. **Outcome: H5 did not hold** (two choices lose to a full scan on latency); not pursued. See `results/rejected_ideas.md`.
11. Bucket fix (H1): a configurable or relative bucket, e.g. `least_time header bucket=5ms`, or a bucket derived from group median rt. Default behavior stays unchanged.
12. Estimator changes (H3/H4) behind an explicit parameter, never a silent default change.
13. `least_work` (H6) as an **out-of-tree dynamic module** first (`--add-dynamic-module`). It needs a new directive and a per-request cost variable, so it is unlikely to be accepted upstream as-is. Account for retries, client aborts and failures so no "phantom work" leaks.
14. For each: nginx-tests style `.t` tests, `-Werror` builds, a UBSan run, HTTP and stream parity.

### Phase 5: Real benchmarks (3–5 days), in `bench/`

15. Go backend with endpoints `/cpu?ms=`, `/sleep?ms=`, `/mix` and a bounded worker pool (FCFS queue). Heterogeneity comes from CPU pinning or cgroup quotas.
16. Load generator: wrk2 (open loop, constant rate, avoids coordinated omission), with k6 as a cross-check.
17. Matrix: balancer × utilization {50, 70, 85, 95 %} × workload × `worker_processes` {1, N} × zone {on, off}. 20–30 paired, randomized repetitions per cell. Record p50/p95/p99/p99.9, errors and nginx CPU.
18. Acceptance (fix in advance): ≥ 15 % p99 reduction on the target workload, ≤ 2 % regression on homogeneous traffic, ≤ 5 % extra nginx CPU, no error-rate increase.

### Phase 6: Upstream and write-up

19. Open a GitHub issue with the sim and bench evidence before sending a PR. The maintainers are responsive (see the review on #1679).
20. PR to nginx/nginx plus a matching nginx-tests PR, following CONTRIBUTING. HTTP and stream go in one commit, as the reviewers asked for on #1679.
21. Optional: a write-up or paper. The H1/H2/H3 analysis of a production balancer is the novel part, not "least work" itself.

## 4. Recommended start

Phases 0–1, then H1 and H2 in the simulator. Both come straight from the code, are cheap to confirm and would justify small, upstreamable changes. In parallel, `random two least_time` (step 10) is a well-defined first C deliverable.

## 5. Open decisions

- **Goal:** upstream PRs, a paper, or both? This decides how much weight Phase 6 versus H6 gets.
- **Benchmark host:** do we have a Linux machine or VM (ideally 2–3 hosts: load generator, nginx, backends)? Docker on macOS is too noisy for final numbers.
- **Scope:** HTTP and stream together from the start (required for upstream), or HTTP-only while prototyping?
