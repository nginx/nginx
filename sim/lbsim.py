#!/usr/bin/env python3
"""Discrete-event simulator of nginx upstream load balancing.

The nginx balancers (round robin, least_conn, random [two least_conn],
least_time) are ported line by line from nginx 1.31.11:

    src/http/ngx_http_upstream_round_robin.{c,h}
    src/http/modules/ngx_http_upstream_least_conn_module.c
    src/http/modules/ngx_http_upstream_random_module.c
    src/http/modules/ngx_http_upstream_least_time_module.c

including integer-millisecond timing, the 0.05-per-sample EWMA with its
rounding, 20 ms response-time buckets, the 5000 ms cap, the fail_timeout
decay (with the saturating fix from nginx PR #1679), inflight accounting and
smooth-WRR tie breaking.

Candidate improvements live next to them (see BALANCERS at the bottom).

Model
-----
* Poisson arrivals; each request has a class and a base cost (ms of work at
  speed 1.0).
* K nginx worker processes ("dispatchers"). Each arrival goes to a uniformly
  random worker. With `shared=True` (the `zone` directive) all workers see
  one peer state, otherwise each worker has private conns/EWMA state.
* Backends: `c` workers with a FCFS queue ("fcfs") or processor sharing
  ("ps"). Capacity is `speed`, which may change over time.
* Response time measured by nginx = int(t_done) - int(t_dispatch) in ms;
  header_time == response_time (small responses).

Standard library only.
"""
import heapq
import math
import random
from collections import deque

EPOCH_S = 1_700_000_000          # ngx_time() offset, so checked=0 behaves as in nginx


def ewma(avg, v, alpha=0.05, precise=False):
    """ngx_http_upstream_response_time_avg: integer EWMA, alpha=0.05.

    nginx stores the average as integer ms, so a sample can only move it if
    |v - avg| * alpha >= 0.5.  `precise` keeps a fractional average instead
    (what a fixed-point implementation in C would do)."""
    if avg:
        x = v * alpha + avg * (1 - alpha)
        return x if precise else int(0.5 + x)
    return v


# --------------------------------------------------------------------------
# Peer state as seen by one dispatcher (or shared, when zone is configured)
# --------------------------------------------------------------------------

class PeerState:
    __slots__ = ("idx", "weight", "current_weight", "effective_weight",
                 "conns", "header_time", "response_time", "inflight_time",
                 "inflight_last", "inflight_reqs_changed", "inflight_reqs",
                 "checked", "fail_timeout",
                 # candidate-algorithm state
                 "ew_t", "ew_last", "svc", "work", "speed_est")

    def __init__(self, idx, weight=1, fail_timeout=10):
        self.idx = idx
        self.weight = weight
        self.current_weight = 0
        self.effective_weight = weight
        self.conns = 0
        self.header_time = 0
        self.response_time = 0
        self.inflight_time = 0
        self.inflight_last = 0
        self.inflight_reqs_changed = 0
        self.inflight_reqs = 0
        self.checked = 0
        self.fail_timeout = fail_timeout
        self.ew_t = 0.0
        self.ew_last = None
        self.svc = 0.0
        self.work = 0.0
        self.speed_est = 0.0


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------

class Backend:
    def __init__(self, idx, workers=1, speed=1.0, discipline="fcfs"):
        self.idx = idx
        self.c = workers
        self.speed = speed
        self.discipline = discipline
        self.queue = deque()
        self.busy = 0
        self.jobs = []               # PS: list of [remaining_work, req]
        self.ps_last = 0.0
        self.ps_gen = 0
        self.remaining_total = 0.0   # oracle: unfinished work

    # FCFS ------------------------------------------------------------------
    def fcfs_arrive(self, sim, req, now):
        self.remaining_total += req.cost
        if self.busy < self.c:
            self._start(sim, req, now)
        else:
            self.queue.append(req)

    def _start(self, sim, req, now):
        self.busy += 1
        req.start = now
        sim.push(now + req.cost / self.speed, "done", req)

    def fcfs_done(self, sim, req, now):
        self.busy -= 1
        self.remaining_total -= req.cost
        if self.queue:
            self._start(sim, self.queue.popleft(), now)

    # PS -------------------------------------------------------------------
    def _ps_advance(self, now):
        if self.jobs:
            n = len(self.jobs)
            rate = self.speed * min(1.0, self.c / n)
            dt = now - self.ps_last
            for j in self.jobs:
                j[0] -= dt * rate
        self.ps_last = now

    def _ps_schedule(self, sim, now):
        self.ps_gen += 1
        if not self.jobs:
            return
        n = len(self.jobs)
        rate = self.speed * min(1.0, self.c / n)
        j = min(self.jobs, key=lambda x: x[0])
        sim.push(now + max(0.0, j[0]) / rate, "ps", (self, self.ps_gen))

    def ps_arrive(self, sim, req, now):
        self._ps_advance(now)
        self.remaining_total += req.cost
        req.start = now
        self.jobs.append([req.cost, req])
        self._ps_schedule(sim, now)

    def ps_tick(self, sim, gen, now):
        if gen != self.ps_gen:
            return
        self._ps_advance(now)
        self.jobs.sort(key=lambda x: x[0])
        while self.jobs and self.jobs[0][0] <= 1e-9:
            _, req = self.jobs.pop(0)
            self.remaining_total -= req.cost
            sim.complete(req, now)
        self._ps_schedule(sim, now)

    def arrive(self, sim, req, now):
        if self.discipline == "ps":
            self.ps_arrive(sim, req, now)
        else:
            self.fcfs_arrive(sim, req, now)

    def set_speed(self, sim, speed, now):
        if self.discipline == "ps":
            self._ps_advance(now)
            self.speed = speed
            self._ps_schedule(sim, now)
        else:
            # in-service jobs keep their scheduled completion (approximation)
            self.speed = speed


class Request:
    __slots__ = ("id", "arrival", "cls", "cost", "est_cost", "worker",
                 "peer", "dispatch", "start", "n_at_dispatch", "inflight",
                 "lt_state")

    def __init__(self, rid, arrival, cls, cost):
        self.id = rid
        self.arrival = arrival
        self.cls = cls
        self.cost = cost
        self.est_cost = cost
        self.inflight = False


# --------------------------------------------------------------------------
# nginx balancers (faithful ports)
# --------------------------------------------------------------------------

class RoundRobin:
    """ngx_http_upstream_get_peer (smooth weighted round robin)."""
    name = "round_robin"

    def select(self, sim, peers, req, now):
        best, total = None, 0
        for p in peers:
            p.current_weight += p.effective_weight
            total += p.effective_weight
            if p.effective_weight < p.weight:
                p.effective_weight += 1
            if best is None or p.current_weight > best.current_weight:
                best = p
        best.current_weight -= total
        return best

    def on_dispatch(self, sim, p, req, now):
        p.conns += 1

    def on_done(self, sim, p, req, now, rt):
        p.conns -= 1


def smooth_wrr_among(peers, start, pred):
    """The 'many' branch shared by least_conn and least_time."""
    best = peers[start]
    total = 0
    for p in peers[start:]:
        if not pred(p):
            continue
        p.current_weight += p.effective_weight
        total += p.effective_weight
        if p.effective_weight < p.weight:
            p.effective_weight += 1
        if p.current_weight > best.current_weight:
            best = p
    best.current_weight -= total
    return best


class LeastConn(RoundRobin):
    name = "least_conn"

    def select(self, sim, peers, req, now):
        best, many, start = None, False, 0
        for i, p in enumerate(peers):
            if best is None or p.conns * best.weight < best.conns * p.weight:
                best, many, start = p, False, i
            elif p.conns * best.weight == best.conns * p.weight:
                many = True
        if many:
            b = best
            best = smooth_wrr_among(
                peers, start,
                lambda p: p.conns * b.weight == b.conns * p.weight)
        return best


class Random:
    """random / random two [least_conn] (ngx_http_upstream_random_module)."""

    def __init__(self, two=False):
        self.two = two
        self.name = "random_two_least_conn" if two else "random"

    @staticmethod
    def _peek(sim, peers):
        total = sum(p.weight for p in peers)
        x = sim.rng.randrange(total)
        for p in peers:
            x -= p.weight
            if x < 0:
                return p
        return peers[-1]

    def select(self, sim, peers, req, now):
        if not self.two or len(peers) < 2:
            return self._peek(sim, peers)
        prev = self._peek(sim, peers)
        peer = self._peek(sim, peers)
        while peer is prev:                 # nginx retries until distinct
            peer = self._peek(sim, peers)
        if peer.conns * prev.weight > prev.conns * peer.weight:
            peer = prev
        return peer

    on_dispatch = RoundRobin.on_dispatch
    on_done = RoundRobin.on_done


class LeastTime:
    """ngx_http_upstream_least_time_module, header|last_byte [inflight].

    `bucket` and `cap` expose the hard-coded 20 / 5000 for experiments.
    `relative` replaces the fixed bucket with max(bucket, frac * median rt).
    """

    def __init__(self, inflight=False, bucket=20, cap=5000, relative=None,
                 decay=True, alpha=0.05, tau=None, precise=False):
        self.precise = precise
        self.alpha = alpha
        self.tau = tau
        self.inflight = inflight
        self.bucket = bucket
        self.cap = cap
        self.relative = relative
        self.decay = decay
        self.name = "least_time" + (" inflight" if inflight else "")
        if bucket != 20:
            self.name += f" b={bucket}"
        if relative:
            self.name += f" rel={relative}"
        if alpha != 0.05:
            self.name += f" a={alpha}"
        if tau:
            self.name += f" tau={int(tau)}"
        if precise:
            self.name += " fp"

    def base_rt(self, p):
        return p.header_time

    def _bucket(self, peers):
        if not self.relative:
            return self.bucket
        rts = sorted(self.base_rt(p) for p in peers)
        med = rts[len(rts) // 2]
        return max(self.bucket, int(self.relative * med))

    def eta(self, sim, p, now, bucket):
        rt = int(self.base_rt(p))
        now_s = EPOCH_S + int(now / 1000)
        if self.decay and now_s - p.checked > p.fail_timeout:
            shift = (now_s - p.checked) // (p.fail_timeout + 1)
            rt = 0 if shift >= 64 else rt >> shift      # PR #1679 semantics
        if p.inflight_reqs > 0:
            rt = max(rt, p.inflight_time)
        if rt > self.cap:
            rt = self.cap
        else:
            rt += bucket - rt % bucket
        return rt * (1 + p.conns)

    def select(self, sim, peers, req, now):
        cur = int(now)
        bucket = self._bucket(peers)
        best, many, start, best_eta = None, False, 0, 0
        etas = {}
        for i, p in enumerate(peers):
            if p.inflight_reqs > 0:
                ift = (p.inflight_last // p.inflight_reqs
                       + (cur - p.inflight_reqs_changed))
                p.inflight_time = ewma(p.inflight_time, ift)
            e = self.eta(sim, p, now, bucket)
            etas[p.idx] = e
            if best is None or e * best.weight < best_eta * p.weight:
                best, best_eta, many, start = p, e, False, i
            elif e * best.weight == best_eta * p.weight:
                many = True
        if many:
            b, be = best, best_eta
            best = smooth_wrr_among(
                peers, start,
                lambda p: etas[p.idx] * b.weight == be * p.weight)
        return best

    def on_dispatch(self, sim, p, req, now):
        now_s = EPOCH_S + int(now / 1000)
        cur = int(now)
        if self.inflight:
            if p.inflight_reqs > 0:
                p.inflight_last += (cur - p.inflight_reqs_changed) * p.inflight_reqs
            p.inflight_reqs_changed = cur
            p.inflight_reqs += 1
            req.inflight = True
        if now_s - p.checked > p.fail_timeout:
            p.checked = now_s
        p.conns += 1

    def _inflight_done(self, p, req, now, last):
        cur = int(now)
        if p.inflight_reqs == 1:
            p.inflight_last = 0
        else:
            p.inflight_last += ((cur - p.inflight_reqs_changed) * p.inflight_reqs
                                - last)
            p.inflight_reqs_changed = cur
        p.inflight_reqs -= 1
        req.inflight = False

    def _alpha(self, p, now):
        """Per-sample weight. With `tau` (ms) the weight follows wall-clock
        time since the peer's previous sample, floored at `alpha`, so a
        rarely used peer adapts in ~tau ms regardless of its request rate."""
        if not self.tau:
            return self.alpha
        a = self.alpha
        if p.ew_last is not None:
            a = max(a, 1.0 - math.exp(-(now - p.ew_last) / self.tau))
        p.ew_last = now
        return a

    def on_done(self, sim, p, req, now, rt):
        a = self._alpha(p, now)
        # notify(HEADER) fires first when inflight + header mode
        if self.inflight:
            p.header_time = ewma(p.header_time, rt, a, self.precise)
            self._inflight_done(p, req, now, rt)
        if req.inflight:
            self._inflight_done(p, req, now, rt)
        p.response_time = ewma(p.response_time, rt, a, self.precise)
        if not self.inflight:
            p.header_time = ewma(p.header_time, rt, a, self.precise)
        p.conns -= 1


class LeastTimePatch(LeastTime):
    """least_time as in patches/0001..0003, integer arithmetic mirrored.

    - averages are integers in 1/SCALE ms, updated by
      ngx_http_upstream_response_time_avg(avg, v, w) (+0.5 rounding,
      saturating at 2^31-1)
    - eta: decay shift on the scaled value, max with inflight_time, then
      (rt + SCALE/2) / SCALE, then the 5000 cap and the `bucket`
    - `smooth` (ms): w = 1 if elapsed >= smooth else max(0.01, elapsed/smooth),
      elapsed measured from the previous update of the balancing metric;
      without `smooth`, w = 0.05
    """

    SCALE = 64
    MAX = 0x7fffffff

    def __init__(self, inflight=False, bucket=20, smooth=None):
        super().__init__(inflight=inflight, bucket=bucket)
        self.smooth = smooth
        self.name = ("least_time" + (" inflight" if inflight else "")
                     + f" bucket={bucket}ms"
                     + (f" smooth={smooth / 1000:g}s" if smooth else "") + " [patched]")

    def avg(self, avg, v, w):
        a = float(v) * self.SCALE
        if avg:
            a = 0.5 + a * w + float(avg) * (1.0 - w)
        return int(a) if a < self.MAX else self.MAX

    def weight(self, p, now):
        if not self.smooth:
            return 0.05
        cur = int(now)
        elapsed = cur - (p.ew_last or 0)
        p.ew_last = cur
        if elapsed >= self.smooth:
            return 1.0
        return max(elapsed / self.smooth, 0.01)

    def eta(self, sim, p, now, bucket):
        rt = self.base_rt(p)
        now_s = EPOCH_S + int(now / 1000)
        if self.decay and now_s - p.checked > p.fail_timeout:
            shift = (now_s - p.checked) // (p.fail_timeout + 1)
            rt = 0 if shift >= 64 else rt >> shift
        if p.inflight_reqs > 0:
            rt = max(rt, p.inflight_time)
        rt = (rt + self.SCALE // 2) // self.SCALE
        if rt > self.cap:
            rt = self.cap
        else:
            rt += bucket - rt % bucket
        return rt * (1 + p.conns)

    def select(self, sim, peers, req, now):
        cur = int(now)
        for p in peers:
            if p.inflight_reqs > 0:
                ift = (p.inflight_last // p.inflight_reqs
                       + (cur - p.inflight_reqs_changed))
                # C updates it inside the scan; each peer's eta depends only
                # on its own state, so updating first is equivalent
                p.inflight_time = self.avg(p.inflight_time, ift, 0.05)
        bucket = self._bucket(peers)
        best, many, start, best_eta = None, False, 0, 0
        etas = {}
        for i, p in enumerate(peers):
            e = self.eta(sim, p, now, bucket)
            etas[p.idx] = e
            if best is None or e * best.weight < best_eta * p.weight:
                best, best_eta, many, start = p, e, False, i
            elif e * best.weight == best_eta * p.weight:
                many = True
        if many:
            b, be = best, best_eta
            best = smooth_wrr_among(
                peers, start,
                lambda p: etas[p.idx] * b.weight == be * p.weight)
        return best

    def on_done(self, sim, p, req, now, rt):
        rt = int(rt)
        if self.inflight:
            # header mode + inflight: notify() updates header_time with the
            # smoothing weight, free() updates response_time with 0.05
            p.header_time = self.avg(p.header_time, rt, self.weight(p, now))
            self._inflight_done(p, req, now, rt)
            p.response_time = self.avg(p.response_time, rt, 0.05)
        else:
            w = self.weight(p, now)
            p.response_time = self.avg(p.response_time, rt, w)
            p.header_time = self.avg(p.header_time, rt, w)
        p.conns -= 1


class RandomTwoLeastTime(LeastTime):
    """Candidate: `random two least_time=header` (NGINX Plus has it)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.name = "random_two_" + self.name

    def select(self, sim, peers, req, now):
        prev = Random._peek(sim, peers)
        peer = Random._peek(sim, peers)
        while peer is prev:
            peer = Random._peek(sim, peers)
        bucket = self._bucket(peers)
        cur = int(now)
        for p in (prev, peer):
            if p.inflight_reqs > 0:
                ift = (p.inflight_last // p.inflight_reqs
                       + (cur - p.inflight_reqs_changed))
                p.inflight_time = ewma(p.inflight_time, ift)
        if (self.eta(sim, peer, now, bucket) * prev.weight
                > self.eta(sim, prev, now, bucket) * peer.weight):
            peer = prev
        return peer


# --------------------------------------------------------------------------
# Candidate balancers
# --------------------------------------------------------------------------

class ServiceTimeSED(RoundRobin):
    """H3: shortest expected delay with a *service time* estimate.

    On completion, estimate the request's service time as
    rt / (1 + n_at_dispatch) -- the conditional mean for FCFS single-server
    backends -- and keep a per-sample EWMA of it (same alpha as nginx).
    Score = S_hat * (1 + conns) / weight, no bucketing (float compare with a
    small tolerance, ties broken by smooth WRR).
    """

    def __init__(self, alpha=0.05, tol=0.05):
        self.alpha = alpha
        self.tol = tol
        self.name = "sed_service_time"

    def select(self, sim, peers, req, now):
        best, bs = None, None
        scores = {}
        for p in peers:
            s = (p.svc or 1.0) * (1 + p.conns) / p.weight
            scores[p.idx] = s
            if bs is None or s < bs:
                best, bs = p, s
        tied = [p for p in peers if scores[p.idx] <= bs * (1 + self.tol)]
        if len(tied) > 1:
            return smooth_wrr_among(tied, 0, lambda p: True)
        return best

    def on_dispatch(self, sim, p, req, now):
        req.n_at_dispatch = p.conns
        p.conns += 1

    def on_done(self, sim, p, req, now, rt):
        s = max(1.0, rt) / (1 + req.n_at_dispatch)
        p.svc = s if not p.svc else (1 - self.alpha) * p.svc + self.alpha * s
        p.conns -= 1


class PeakEWMA(RoundRobin):
    """H4: Finagle/Linkerd-style Peak EWMA, time-decayed (tau in ms).

    cost = ewma_rt * (conns + 1); ewma jumps to a sample above it (peak),
    otherwise decays toward samples with weight 1 - exp(-dt/tau).
    `two=True` uses power-of-two choices like Finagle.
    """

    def __init__(self, tau=10000.0, two=False, peak=True):
        self.tau = tau
        self.two = two
        self.peak = peak
        self.name = (f"{'p2c_' if two else ''}"
                     f"{'peak_' if peak else ''}ewma tau={int(tau)}")

    def cost(self, p, now):
        return (p.ew_t or 1.0) * (p.conns + 1) / p.weight

    def select(self, sim, peers, req, now):
        if self.two and len(peers) > 1:
            a = Random._peek(sim, peers)
            b = Random._peek(sim, peers)
            while b is a:
                b = Random._peek(sim, peers)
            return a if self.cost(a, now) <= self.cost(b, now) else b
        best = min(peers, key=lambda p: self.cost(p, now))
        bc = self.cost(best, now)
        tied = [p for p in peers if self.cost(p, now) <= bc * 1.0001]
        if len(tied) > 1:
            return smooth_wrr_among(tied, 0, lambda p: True)
        return best

    def on_done(self, sim, p, req, now, rt):
        v = float(max(rt, 0.5))
        if p.ew_last is None:
            p.ew_t = v
        elif self.peak and v > p.ew_t:
            p.ew_t = v
        else:
            w = math.exp(-(now - p.ew_last) / self.tau)
            p.ew_t = p.ew_t * w + v * (1 - w)
        p.ew_last = now
        p.conns -= 1


class LeastWork(RoundRobin):
    """H6: join-the-shortest-(estimated)-work.

    Each request carries an estimated cost (class mean x lognormal error,
    set by the workload). A peer's outstanding work is the sum of estimates
    of its in-flight requests. If `learn_speed`, capacity is learned as an
    EWMA of est_cost / service-time estimate; otherwise `weight` is the
    configured relative capacity.
    """

    def __init__(self, learn_speed=False, alpha=0.05):
        self.learn_speed = learn_speed
        self.alpha = alpha
        self.name = "least_work" + (" learn_speed" if learn_speed else "")

    def speed(self, p):
        if self.learn_speed:
            return p.speed_est or 1.0
        return p.weight

    def select(self, sim, peers, req, now):
        best, bs = None, None
        for p in peers:
            s = (p.work + req.est_cost) / self.speed(p)
            if bs is None or s < bs - 1e-9:
                best, bs = p, s
        return best

    def on_dispatch(self, sim, p, req, now):
        req.n_at_dispatch = p.work
        p.work += req.est_cost
        p.conns += 1

    def on_done(self, sim, p, req, now, rt):
        p.work -= req.est_cost
        if self.learn_speed:
            # FCFS single worker: rt ~= (work_ahead + own) / speed
            sp = (req.n_at_dispatch + req.est_cost) / max(1.0, rt)
            p.speed_est = (sp if not p.speed_est else
                           (1 - self.alpha) * p.speed_est + self.alpha * sp)
        p.conns -= 1


class Oracle(RoundRobin):
    """Join the backend with least true unfinished work / true speed."""
    name = "oracle_jsw"

    def select(self, sim, peers, req, now):
        return min(peers, key=lambda p: (sim.backends[p.idx].remaining_total
                                         + req.cost)
                   / sim.backends[p.idx].speed)


# --------------------------------------------------------------------------
# Simulation driver
# --------------------------------------------------------------------------

class Sim:
    def __init__(self, backends, balancer, workload, rate, n_requests,
                 workers=1, shared=True, weights=None, seed=1,
                 warmup=0.2, events=(), fail_timeout=10):
        self.rng = random.Random(seed)
        self.backends = backends
        self.balancer = balancer
        self.workload = workload
        self.rate = rate
        self.n = n_requests
        self.warmup = warmup
        self.heap = []
        self.seq = 0
        weights = weights or [1] * len(backends)
        nstates = 1 if shared else workers
        self.states = [[PeerState(i, weights[i], fail_timeout)
                        for i in range(len(backends))]
                       for _ in range(nstates)]
        self.workers = workers
        self.shared = shared
        self.done = []
        for t, ev in events:
            self.push(t, "event", ev)

    def push(self, t, kind, payload):
        self.seq += 1
        heapq.heappush(self.heap, (t, self.seq, kind, payload))

    def complete(self, req, now):
        rt = int(now) - int(req.dispatch)
        peers = self.states[0 if self.shared else req.worker]
        self.balancer.on_done(self, peers[req.peer], req, now, rt)
        self.done.append((req.arrival, now - req.arrival, req.peer, req.cls))

    def run(self):
        t = 0.0
        for rid in range(self.n):
            t += self.rng.expovariate(self.rate / 1000.0)
            cls, cost, est = self.workload(self.rng)
            r = Request(rid, t, cls, cost)
            r.est_cost = est
            self.push(t, "arrive", r)
        while self.heap:
            now, _, kind, x = heapq.heappop(self.heap)
            if kind == "arrive":
                x.worker = self.rng.randrange(self.workers)
                peers = self.states[0 if self.shared else x.worker]
                p = self.balancer.select(self, peers, x, now)
                x.peer = p.idx
                x.dispatch = now
                self.balancer.on_dispatch(self, p, x, now)
                self.backends[p.idx].arrive(self, x, now)
            elif kind == "done":
                self.backends[x.peer].fcfs_done(self, x, now)
                self.complete(x, now)
            elif kind == "ps":
                b, gen = x
                b.ps_tick(self, gen, now)
            elif kind == "event":
                x(self, now)
        return self.summary()

    def summary(self, window=None):
        d = sorted(self.done)
        d = d[int(len(d) * self.warmup):]
        if window:
            d = [x for x in d if window[0] <= x[0] < window[1]]
        lat = sorted(x[1] for x in d)
        share = [0] * len(self.backends)
        for x in d:
            share[x[2]] += 1

        def q(p):
            return lat[min(len(lat) - 1, int(p * len(lat)))] if lat else float("nan")

        return {"n": len(lat), "mean": sum(lat) / max(1, len(lat)),
                "p50": q(0.5), "p95": q(0.95), "p99": q(0.99),
                "p999": q(0.999), "share": share}


# --------------------------------------------------------------------------
# Workloads: return (class, true_cost_ms, estimated_cost_ms)
# --------------------------------------------------------------------------

def exp_workload(mean):
    def w(rng):
        c = rng.expovariate(1.0 / mean)
        return 0, c, mean
    w.mean = mean
    return w


def classes_workload(classes, sigma=0.0):
    """classes: list of (prob, mean_ms); per-class cost is exponential.
    The estimate is the class mean x exp(N(0, sigma))."""
    probs = [c[0] for c in classes]
    mean = sum(p * m for p, m in classes)

    def w(rng):
        i = rng.choices(range(len(classes)), probs)[0]
        m = classes[i][1]
        c = rng.expovariate(1.0 / m)
        est = m * math.exp(rng.gauss(0, sigma)) if sigma else m
        return i, c, est
    w.mean = mean
    return w


def lognormal_workload(median, sigma):
    mu = math.log(median)
    mean = math.exp(mu + sigma * sigma / 2)

    def w(rng):
        c = rng.lognormvariate(mu, sigma)
        return 0, c, mean
    w.mean = mean
    return w


def rate_for(util, backends, workload):
    cap = sum(b.c * b.speed for b in backends)        # work-ms per ms
    return util * cap / workload.mean * 1000.0         # requests per second
