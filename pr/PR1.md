Title: Upstream: fixed rounding of least_time average response times.

I've been looking at nginx's load balancing through [queueing theory](https://en.wikipedia.org/wiki/Queueing_theory). I'm not an expert in it, so I worked with an AI assistant (Claude) to build a simulator that reproduces least_time's exact arithmetic, checked it against known queueing results, and confirmed the findings on real nginx builds.

This PR is the smallest of those findings: a rounding error in the averages least_time keeps. On its own it changes little with the default settings (p99 within ±4 % on real nginx), but a follow-up PR depends on it: that PR makes the 20 ms clustering configurable, which improves p99 by 9-44 % on real nginx when servers differ in speed.

The simulator, data and benchmark scripts are in [this branch](https://github.com/psygo/nginx_plus/tree/least-time-evidence). I couldn't find a load-balancing simulator in the nginx ecosystem; if one would be useful, I'd be happy to open a discussion about it.

## Problem

The averages that `least_time` compares are kept in whole milliseconds and updated by `ngx_http_upstream_response_time_avg()` / `ngx_stream_upstream_response_time_avg()` as

    avg = (ngx_msec_t) (0.5 + v * 0.05 + avg * 0.95)

A sample moves the average only if `|v - avg| * 0.05 >= 0.5`, that is, if it differs from the average by at least 10 ms. So:

- the average can sit anywhere within ±10 ms of the actual time, and stays there;
- for a server faster than 10 ms the average can only grow (an occasional slow response pushes it up) and never comes back down. Such averages end up at about 10 ms whatever the real response time is.

For example, with avg = 10 and every new response taking 2 ms: `0.5 + 2 * 0.05 + 10 * 0.95 = 10.1`, truncated to 10, indefinitely.

This shows in a running nginx: with debug logging of the average added to `ngx_http_upstream_least_time_eta()`, two backends answering in about 4.7 ms both show `header_time = 10` on every selection. With this change the logged averages track 4.7 ms.

## Solution

Averages are kept in 1/64 ms units. `ngx_http_upstream_least_time_eta()` (and the stream counterpart) converts back to milliseconds before the 5000 ms limit and the 20 ms clustering, so the selection logic is unchanged apart from the error being removed. Values saturate at `NGX_MAX_INT32_VALUE` (about 9.3 hours of average time) instead of overflowing a 32-bit `ngx_msec_t`. HTTP and stream are changed in the same commit. The macros become `static ngx_inline` functions to hold the saturation.

### Impact

With the default 20 ms clustering the error is mostly hidden, and this change is neutral: in a simulation of 12 scenarios × 4 load levels (20 paired seeds × 300,000 requests each), p99 changes by -2 % to +2 % compared with the current code. On real nginx (Linux, `-O2`, 16 single-worker and 2 four-worker `zone` configurations, 5 paired repetitions each) p99 changes by -4 % to +4 %, and only one 95 % interval excludes zero (-4 % [-7, -2], with slow servers).

It matters as soon as the clustering is finer than the error. A follow-up pull request adds `least_time ... bucket=5ms`. With integer averages a 5 ms bucket gains almost nothing, because the 10 ms error dominates; with fixed-point averages it does what it should:

| scenario (simulated, 70 % load unless noted) | bucket=5ms, integer averages | bucket=5ms, this change |
| --- | --- | --- |
| 3 servers, 2/6/15 ms mean, 50 % load | -4 % p99 | -42 % p99 |
| 3 servers, 2/6/15 ms mean | -2 % | -21 % |
| 8 servers of unequal speed, 10 ms mean | -3 % | -11 % |
| 16 servers of unequal speed, 10 ms mean | -6 % | -13 % |
| 8 servers of unequal speed, lognormal times | -4 % | -9 % |

p99 relative to stock `least_time`, geometric mean over 10 paired seeds.

## Testing

- [x] Manual Testing: debug traces of the averages before and after (above); simulator and Linux benchmark runs (https://github.com/psygo/nginx_plus/tree/least-time-evidence)
- [x] Functional Testing ([nginx-tests](https://github.com/nginx/nginx-tests)): all `upstream*.t` and `stream_upstream*.t` pass, also with `TEST_NGINX_UNSAFE=1`, on macOS/clang and Linux/gcc 14 with `-Werror`

No new test: with the default 20 ms clustering the fix does not change which server is selected, so it cannot be observed from outside nginx, which is how nginx-tests work. It becomes observable with a finer clustering, and the follow-up adds tests there.

## Checklist

- [x] I have read the [CONTRIBUTING](https://github.com/nginx/nginx/blob/master/CONTRIBUTING.md) guidelines
- [ ] I have added tests (if applicable) to validate my changes
  - *Not applicable:* with the default 20 ms clustering the fix does not change which server is selected, so nginx-tests, which observe nginx from outside, cannot see it. The follow-up pull request, which makes the clustering configurable, adds tests.
- [x] All existing tests pass
- [x] I have updated documentation where necessary (no user-visible interface change)
- [x] My branch is rebased on the latest master
- [x] This PR targets the master branch from my fork
- [x] My commit message follows NGINX standards

## Release Notes

Bugfix: the "least_time" balancer could use average response times which differed from actual ones by up to 10 milliseconds.
