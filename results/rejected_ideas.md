# Rejected and abandoned ideas

These are the ideas that were tried and not proposed, with the data, the reason, and
what would change the verdict. They are kept so they don't get re-tried blindly, and
because a reviewer may well ask "did you consider X?".

All simulation numbers are p99 latency in ms, the mean over seeds. The scenarios are
described in [sim_pr.md](sim_pr.md#scenarios).

The early experiments (H3, H5, H6) used 5 seeds × 100,000 requests, which is weaker
evidence than the 20 × 300,000 of the PR matrix. Differences under about 5 % in them
are noise. The conclusions below rest on larger differences.

## 1. Power of two choices

**Idea.** Instead of scanning every server, pick two at random and send the request to
the better of the two. This is a classic queueing-theory result (Mitzenmacher; Vvedenskaya
et al.): two random choices are exponentially better than one. Finagle and Linkerd
balance this way, and NGINX Plus offers `random two least_time`. Open-source nginx only
has `random two least_conn`, so adding `least_time` there looked like an easy feature.

**Experiment.** H5, in `results/sim_h5.json`. Servers have random speeds between ½ and 2
(`bigN`). Two setups: 1 worker with shared state, and 8 workers each with private state
(nginx without `zone`).

| servers | load | workers | least_conn | least_time | random two least_conn | random two least_time | P2C Peak EWMA |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4 | 0.7 | 1 | 88.2 | 81.2 | 109.7 | 98.3 | 92.0 |
| 16 | 0.7 | 1 | 59.8 | 53.7 | 101.9 | 85.5 | 79.8 |
| 64 | 0.7 | 1 | 47.9 | 40.6 | 89.8 | 75.0 | 69.0 |
| 64 | 0.9 | 1 | 53.9 | 52.3 | 140.2 | 110.7 | 99.1 |
| 16 | 0.7 | 8 private | 155.7 | 73.9 | 205.6 | 109.8 | 108.2 |
| 64 | 0.7 | 8 private | 138.8 | 50.7 | 186.4 | 95.9 | 94.0 |
| 64 | 0.9 | 8 private | 160.0 | 80.4 | 311.7 | 146.0 | 145.3 |

**Verdict: rejected on latency.** Every two-choice variant is worse than full
`least_time`, by 1.1-1.4× at 4 servers and up to 2.2× at 64.

**Why.** The two-choices result compares against picking *one* random server. It
matters when looking at every server is expensive or the information is stale (many
independent dispatchers, remote state). nginx keeps all server state in memory, and
scanning even 64 servers costs nanoseconds, so sampling only throws information away.

**What would change it.** CPU time and lock contention are not modeled. With hundreds
of servers and many workers contending for the `zone` lock, a full scan could become
the bottleneck. That has not been measured. `random two least_time` may still be worth
adding for parity with NGINX Plus, but not on latency grounds.

## 2. A pure service-rate rule ("shortest expected delay")

**Idea.** `least_time` multiplies the average *response* time by the number of requests in
progress. A response time already includes time spent waiting, so the wait gets counted
twice. Queueing theory's shortest-expected-delay rule uses the *service* time instead.
So the idea was to estimate each server's service time as `response_time / (1 + requests
in progress when it was sent)`, which is exact for a server that handles one request at a
time in arrival order (FCFS), and to choose the server with the lowest
`service_time × (1 + in progress)`.

**Experiment.** H3 (`results/sim_h3.json`) covers the slowdown scenarios: one of 4
servers drops to ¼ speed for 20 s, and p99 is measured during the slow window. The
backends are FCFS with 1 worker, FCFS with 4 workers (`_c4`), and processor sharing
(`_ps`). H6 (`results/sim_h6.json`) covers mixed 2 ms / 80 ms requests.

| scenario | load | least_conn | least_time | least_time, bucket 1 | service-rate rule |
| --- | --- | --- | --- | --- | --- |
| slowdown, FCFS 1 worker | 0.7 | 229.6 | 145.9 | 136.6 | **124.6** |
| slowdown, FCFS 4 workers | 0.3 | 92.8 | 60.8 | 52.1 | **47.4** |
| slowdown, FCFS 4 workers | 0.7 | 104.8 | 70.9 | 67.6 | **63.6** |
| slowdown, processor sharing | 0.3 | 92.8 | 60.7 | 51.5 | **48.2** |
| slowdown, processor sharing | 0.7 | 112.6 | **85.1** | 82.3 | 104.0 |
| bimodal4 | 0.85 | **637.2** | 740.9 | 761.1 | 784.1 |
| bimodal4_het | 0.85 | 799.3 | 791.7 | 805.7 | **712.1** |

**Verdict: rejected as a default.** It wins on FCFS backends, by 15-22 % against
`least_time`. It loses by 22 % on processor-sharing backends at 70 % load, and on
equal servers with mixed requests it is the worst of all. A balancer that is sometimes
much better and sometimes much worse can't be nginx's behavior for everyone.

**Why.** The formula `response_time / (1 + in progress)` assumes the backend processes
requests one at a time, in order. A backend that shares its CPU among all requests
(processor sharing), or has several workers, slows down differently as load grows, so
the estimate is biased, in different directions for different backends. nginx has no
way of knowing which kind of backend it is talking to.

**What would change it.** An estimator that learns each backend's behavior, by watching
how its response time grows with the number of requests in progress. Then the service
time and the concurrency could be estimated together. This is the most promising
follow-up (see the headroom measurement in `sim_headroom.json`: on 3 very unequal
servers, a balancer that knows true speeds beats patched `least_time` by 26–38 %).

## 3. Smaller tweaks that lost

| idea | result | where |
| --- | --- | --- |
| `bucket=1ms` as the recommendation | Breaks re-probing of a server whose average was halved by the inactivity decay; the existing nginx-tests "response time decay probe" test fails. 5 ms keeps the re-probing and is within noise of 1 ms on latency. | `PLAN.md`, patch 2 notes |
| A smaller `bucket` with integer averages | Gains mostly vanish because the 10 ms rounding error dominates: -2 to -6 % instead of -9 to -42 %. This is why PR 1 exists. | `pr/PR1.md` table |
| `bucket` without smoothing | Worse on mixed 2 ms / 80 ms requests: +1 to +8 % p99 vs stock. This is why `bucket` and `smooth` travel together in PR 2. | `sim_pr.md`, P1+P2 column |
| `smooth=1s` | Too short for slow backends: +17 to +20 % on 20/60/150 ms servers. 3 s and 10 s are both fine. | `sim_pr.md`, sweep |
| Two smoothing knobs (`alpha=` and a time floor) | Not tested as a separate design; dropped in favor of one `smooth=` time to keep the interface small. | decision, 2026-11-25 |
| Peak EWMA (Finagle/Linkerd estimator) | Good on unequal servers with mixed requests (bimodal4_het, -20 % vs stock), about equal to `least_time` with a small bucket elsewhere. Not pursued: `smooth=` gets most of the same benefit inside the existing directive. | `sim_h3.json`, `sim_h6.json` |

## 4. Benchmark methods that were dropped

| method | problem | replaced by |
| --- | --- | --- |
| macOS, `-O0` debug builds, Python backends | Noisy and slow, and not what production nginx runs. Fine for a first look; all macOS numbers are superseded. | Linux VM, `-O2` builds, Go backends (`bench/linux/`) |
| First macOS bimodal A/B (3 seeds) | Overlapped other jobs on the machine; too noisy to use. | 8-seed rerun on an idle machine (`fp_bimodal_real.jsonl`) |
| Plain `time.Sleep` pacing in the Docker VM | Timer wake-ups 0.3 to 3.5 ms late, which distorts millisecond-scale latencies. | sleep until 2 ms before, then spin |
| Busy "spinner" threads at idle priority to keep CPUs awake | Made the tail worse through contention on the host. | removed |
