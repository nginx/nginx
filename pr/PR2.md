Title: Upstream: "bucket" and "smooth" parameters of the "least_time" directive

Depends on #PR1 (fixed rounding of least_time averages); this branch contains that
commit plus two more. Documentation: nginx/nginx.org#TBD. Tests: nginx/nginx-tests#TBD.

## Problem

`least_time` selects the server with the lowest `average_time * (active_connections + 1)`,
but two fixed constants limit how much it gains over `least_conn`:

1. **The 20 ms rounding step.** Averages are rounded up to a multiple of 20 ms before
   comparison. Every server faster than 20 ms rounds to 20 ms, and `least_time` behaves
   like `least_conn` among them. A 2 ms server and a 15 ms server look the same.
2. **The fixed per-response weight of 0.05.** With fewer servers in each rounding step, the
   noise of the average starts to matter. With mixed fast and slow requests (an API with
   cheap reads and occasional expensive calls) a few slow responses in a row make a server
   look slow, and requests go elsewhere for no reason. In this case stock `least_time` is
   already 15 % worse than `least_conn` at p99 (simulation, 4 equal servers, 90 % 2 ms /
   10 % 80 ms requests, 50-95 % load; 16 % in the real runs at 85 %).

## Solution

Two optional parameters, both off by default, so existing configurations behave exactly as
before:

    least_time header bucket=5ms smooth=3s;

- **`bucket=time`** (commit 2) sets the rounding step, 1 ms to 5 s, default 20 ms.
  The step is kept rather than removed: a server whose average was halved by the
  inactivity decay gets traffic again once it falls into the same step as the fastest
  server. With `bucket=1ms` that re-probing comes much later, and the existing nginx-tests
  "response time decay probe" test fails, so 1 ms is allowed but 5 ms is recommended.
- **`smooth=time`** (commit 3) replaces the fixed weight by
  `w = min(1, max(0.01, elapsed / smooth))`, where `elapsed` is the time since the
  previous response of the same server. This makes the average a time-based moving average
  over about `smooth`, independent of request rate, in the way of the time-decayed EWMA
  balancers in Finagle and Linkerd:
  - a busy server needs about `smooth` worth of responses, not 20 responses, to change its
    average, so bursts of slow requests no longer swing it;
  - an idle or little-used server still catches up within about `smooth`, and after an
    idle period longer than `smooth` its next response replaces the average outright;
  - the 0.01 floor bounds the memory at about 100 responses for very busy servers, and
    keeps the average moving when several responses complete in the same millisecond
    (`elapsed = 0`).

Implementation notes:

- One `ngx_msec_t avg_updated` per peer, taken from the `NGX_COMPAT` reserve
  (`NGX_COMPAT_BEGIN(7)` becomes `(6)`), as the original least_time commit did, so the
  layout seen by compat modules is unchanged. With `zone` it lives in shared memory like
  the averages and is updated under the same peer lock.
- In `inflight` mode the time of requests still in progress keeps the fixed weight,
  because it is sampled on every selection and is not a response.
- HTTP and stream are changed the same way.

## Results

Evidence repository with the simulator, benchmark code, raw results and reports:
https://github.com/psygo/nginx_plus/tree/least-time-evidence.

### Real nginx

nginx master and patched trees, `-O2`, in a Linux VM (Docker Desktop, 12 vCPUs of an
Apple M2 Max), with nginx, backends and load generator on separate CPU sets. Backends are
single-worker FCFS Go servers holding each request for cost/speed ms. The load generator
is open loop (Poisson arrivals, latency from each request's scheduled send time, so no
coordinated omission). Every repetition uses the same arrival times and per-request costs
for all variants, and variants run in shuffled order. 5 repetitions × 30 s per cell,
540 runs, 0 errors.

p99 change with `bucket=5ms smooth=3s` (geometric mean of paired ratios, 95 % CI):

| scenario | load | vs stock least_time | vs least_conn |
| --- | --- | --- | --- |
| 3 servers, 2/6/15 ms mean | 50 % | **-44 %** [-46, -42] | -55 % [-57, -53] |
| | 70 % | **-25 %** [-27, -22] | -46 % [-48, -45] |
| | 85 % | **-12 %** [-18, -6] | -44 % [-50, -37] |
| 8 servers, speeds 2,2,1,1,1,1,½,½, exp 10 ms | 50 % | **-12 %** [-14, -10] | -32 % [-34, -30] |
| | 70 % | **-15 %** [-17, -13] | -31 % [-33, -29] |
| | 85 % | **-13 %** [-16, -11] | -26 % [-30, -22] |
| same servers, lognormal times (5 ms, σ=1) | 70 % | **-14 %** [-18, -10] | -26 % [-27, -25] |
| | 85 % | **-9 %** [-13, -5] | -23 % [-27, -19] |
| 4 equal servers, 90 % 2 ms / 10 % 80 ms | 70 % | -6 % [-18, +8] | +6 % [-2, +15] |
| | 85 % | **-14 %** [-20, -7] | -0 % [-11, +11] |
| 4 servers, speeds 2,1,1,½, same mix | 70 % | -12 % [-24, +2] | -22 % [-29, -14] |
| | 85 % | -11 % [-23, +2] | -15 % [-25, -4] |
| 3 servers, 20/60/150 ms mean | 70 % | -3 % [-10, +5] | -48 % [-54, -42] |
| 4 equal servers, one at ¼ speed for 20 s (p99 during) | 70 % | **-12 %** [-13, -10] | -47 % [-51, -42] |
| 8 equal servers, exp 10 ms (control) | 70 % | -2 % [-3, -1] | -0 % [-2, +1] |
| | 85 % | -10 % [-14, -5] | -0 % [-3, +2] |
| 4 workers + `zone`: 8 servers as above | 85 % | **-12 %** [-14, -9] | -28 % [-32, -24] |
| 4 workers + `zone`: 4 servers, 2,1,1,½, mixed | 85 % | -16 % [-38, +15] | -18 % [-23, -13] |

No configuration is significantly worse than stock `least_time` or than `least_conn`.

Each parameter is needed. p99 vs stock, same runs:

| scenario | load | bucket=5ms only | smooth=3s only | both |
| --- | --- | --- | --- | --- |
| 3 servers, 2/6/15 ms | 50 % | -41 % | -12 % | -44 % |
| 8 servers, unequal speeds | 70 % | -11 % | -4 % | -15 % |
| lognormal, unequal speeds | 70 % | -7 % | -2 % | -14 % |
| 4 equal servers, mixed | 85 % | -0 % | -9 % | -14 % |
| 4 servers 2,1,1,½, mixed | 85 % | +1 % | -16 % | -11 % |

`bucket` gives most of the gain with servers of different speeds; `smooth` gives it with
mixed request costs, where `bucket` alone tends to make things worse (simulation: +1 to
+8 % on the mixed scenarios).

### Simulation

A discrete-event simulator reproduces the patched C arithmetic exactly (1/64 ms fixed
point, rounding, decay, the weight formula). It covers 12 scenarios × 4 load levels
(50/70/85/95 %), 20 paired seeds × 300,000 requests per cell, and was checked against the
real runs above: p99 and per-server shares agree within a few percent where the real
runs are tight (for example, 3 servers at 50 %: least_conn / stock / patched p99 of
60.2 / 47.7 / 25.8 ms simulated vs 61.2 / 49.2 / 27.5 ms real).

`bucket=5ms smooth=3s` vs stock `least_time`, p99:

- servers of unequal speed (3, 8 and 16 servers, exponential and lognormal times):
  -2 % to -46 %, larger at lower load, except 3 slow servers at 50 % load (below);
- mixed 2 ms / 80 ms requests: -8 % to -15 %;
- a server slowed to ¼ for 20 s (FCFS backends): -11 % at 70 % load;
- equal servers (3 controls): 0 to -8 %;
- vs `least_conn`: -11 % to -57 % except with equal servers (0 to +2 %) and with
  equal servers and mixed requests (+3 to +7 %, where stock is +15 to +16 %).

Regressions, all within 6 %:

| scenario | load | p99 vs stock |
| --- | --- | --- |
| 4 servers, one slowed to ¼, processor-sharing backends | 85 % | +6 % [+5, +7] |
| | 95 % | +2 % [+2, +3] |
| 3 servers, 20/60/150 ms | 50 % | +4 % [+3, +4] |
| 4 servers, one slowed to ¼, FCFS | 95 % | +2 % [-1, +5] |

The first is the cost of smoothing: a busy server that suddenly slows down is noticed
over about 100 responses (the 0.01 floor) instead of 20. With processor-sharing backends,
which get slower gradually instead of queueing, this is the slowest case. Neither shows
up in the real runs (slowdown with FCFS backends: -12 %).

Parameter sweep (8 scenarios, mean p99 change vs stock / worst scenario):

| | smooth off | smooth=1s | smooth=3s | smooth=10s |
| --- | --- | --- | --- | --- |
| bucket=20ms | +0.2 % / +1 % | -3.4 % / +16 % | -6.2 % / -2 % | -5.9 % / +1 % |
| bucket=5ms | -5.6 % / +5 % | -8.3 % / +17 % | **-12.3 % / -4 %** | -12.4 % / -7 % |
| bucket=1ms | -6.8 % / +7 % | -9.3 % / +19 % | -14.1 % / -4 % | -14.2 % / -7 % |

`smooth=1s` is too short for servers with long response times; 3 s and 10 s are both
good, and the docs suggest 3 s with a small `bucket`.

## Testing

- [x] Functional Testing ([nginx-tests](https://github.com/nginx/nginx-tests)): new
      tests for both parameters in `upstream_least_time.t` and
      `stream_upstream_least_time.t` (nginx/nginx-tests#TBD); all `upstream*.t` and
      `stream_upstream*.t` pass on macOS/clang and Linux/gcc 14 (`-Werror`), with and
      without `TEST_NGINX_UNSAFE=1`
- [x] Manual Testing: the benchmark and simulation above (https://github.com/psygo/nginx_plus/tree/least-time-evidence); configuration
      errors for `bucket=0`, `bucket=6s`, `smooth=0` and unknown parameters

## Checklist

- [x] I have read the [CONTRIBUTING](https://github.com/nginx/nginx/blob/master/CONTRIBUTING.md) guidelines
- [x] I have added tests (if applicable) to validate my changes
- [x] All existing tests pass
- [x] I have updated documentation where necessary (nginx/nginx.org#TBD)
- [x] My branch is rebased on the latest master
- [x] This PR targets the master branch from my fork
- [x] My commit message follows NGINX standards

## Release Notes

Feature: the "bucket" and "smooth" parameters of the "least_time" directive.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
