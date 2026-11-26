#!/usr/bin/env python3
"""Validate the simulator against exact queueing-theory results.

Each case is a configuration of lbsim.Sim for which the answer is known in
closed form. The simulator is run with independent seeds, and its mean and
p99 latency are compared with the formula.

  M/M/1      one FCFS server, exponential service: latency ~ Exp(mu - lambda),
             mean = S/(1-rho), p99 = ln(100) S/(1-rho)
  random     N identical servers, random routing: each server is an M/M/1 at
             the same load (Poisson splitting), so the same formulas hold
  M/M/c      one server with c workers and a shared FCFS queue: Erlang C for
             the probability of waiting, exact latency distribution for p99
  M/G/1      FCFS with non-exponential service (the bimodal and lognormal
             workloads): Pollaczek-Khinchine mean
  M/G/1-PS   processor sharing: mean = E[S]/(1-rho) whatever the service
             distribution (insensitivity), which checks the PS code
  JSQ bounds least_conn on N identical servers ("join the shortest queue") has
             no closed form; its mean must lie between M/M/N (one central
             queue, the best any dispatcher can do) and random routing

  python3 sim/validate.py [--seeds 20] [--n 300000] [--jobs N]

Writes results/sim_validation.json and results/sim_validation.md.
"""
import argparse
import json
import math
import os
from multiprocessing import Pool

from lbsim import (Backend, LeastConn, Random, Sim, classes_workload,
                   exp_workload, lognormal_workload, rate_for)

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(os.path.dirname(HERE), "results")

BIMODAL = [(0.9, 2.0), (0.1, 80.0)]        # as the bimodal4 scenarios
LOGN = (5.0, 1.0)                          # median 5 ms, sigma 1, as lognorm_*


# --------------------------------------------------------------------------
# Formulas (times in ms)
# --------------------------------------------------------------------------

def erlang_c(c, a):
    """Probability that an arrival waits in M/M/c with offered load a = lambda/mu."""
    rho = a / c
    top = a ** c / math.factorial(c) / (1 - rho)
    return top / (sum(a ** k / math.factorial(k) for k in range(c)) + top)


def mmc(c, rho, s):
    """Mean and p99 latency (wait + service) of M/M/c, mean service s."""
    mu = 1.0 / s
    lam = rho * c * mu
    pw = erlang_c(c, lam / mu)
    theta = c * mu - lam                    # rate of the conditional wait
    mean = pw / theta + s

    def tail(t):                            # P(latency > t)
        if abs(theta - mu) < 1e-12:
            conv = (1 + mu * t) * math.exp(-mu * t)
        else:
            conv = (theta * math.exp(-mu * t) - mu * math.exp(-theta * t)) / (theta - mu)
        return (1 - pw) * math.exp(-mu * t) + pw * conv

    lo, hi = 0.0, 1.0
    while tail(hi) > 0.01:
        hi *= 2
    for _ in range(100):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if tail(mid) > 0.01 else (lo, mid)
    return mean, (lo + hi) / 2


def moments(workload):
    """E[S], E[S^2] of the workloads used here."""
    kind, p = workload
    if kind == "exp":
        return p, 2 * p * p
    if kind == "bimodal":
        return (sum(q * m for q, m in p), sum(q * 2 * m * m for q, m in p))
    if kind == "lognormal":
        mu, sg = math.log(p[0]), p[1]
        return math.exp(mu + sg * sg / 2), math.exp(2 * mu + 2 * sg * sg)
    raise KeyError(kind)


def pk_mean(rho, workload):
    """Pollaczek-Khinchine: mean latency of M/G/1 FCFS."""
    es, es2 = moments(workload)
    lam = rho / es
    return es + lam * es2 / (2 * (1 - rho))


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------

def make_workload(w):
    kind, p = w
    if kind == "exp":
        return exp_workload(p)
    if kind == "bimodal":
        return classes_workload(p)
    return lognormal_workload(*p)


def cases():
    C = []
    for rho in [0.5, 0.7, 0.85, 0.95]:
        C.append(dict(name="M/M/1", servers=1, c=1, disc="fcfs", bal="random",
                      w=("exp", 10.0), rho=rho))
    for rho in [0.7, 0.85]:
        C.append(dict(name="random, 8 servers", servers=8, c=1, disc="fcfs",
                      bal="random", w=("exp", 10.0), rho=rho))
    for rho in [0.7, 0.85, 0.95]:
        C.append(dict(name="M/M/4", servers=1, c=4, disc="fcfs", bal="random",
                      w=("exp", 10.0), rho=rho))
    for rho in [0.5, 0.7, 0.85]:
        C.append(dict(name="M/G/1 bimodal", servers=1, c=1, disc="fcfs",
                      bal="random", w=("bimodal", BIMODAL), rho=rho))
    for rho in [0.5, 0.7]:
        C.append(dict(name="M/G/1 lognormal", servers=1, c=1, disc="fcfs",
                      bal="random", w=("lognormal", LOGN), rho=rho))
    for rho in [0.7, 0.85]:
        C.append(dict(name="M/M/1-PS", servers=1, c=1, disc="ps", bal="random",
                      w=("exp", 10.0), rho=rho))
        C.append(dict(name="M/G/1-PS bimodal", servers=1, c=1, disc="ps",
                      bal="random", w=("bimodal", BIMODAL), rho=rho))
    for rho in [0.7, 0.85]:
        C.append(dict(name="least_conn, 8 servers", servers=8, c=1, disc="fcfs",
                      bal="least_conn", w=("exp", 10.0), rho=rho))
    return C


def theory(case):
    """(mean, p99 or None) for exact cases; (lower, upper) bounds for JSQ."""
    name, rho, w = case["name"], case["rho"], case["w"]
    if name in ("M/M/1", "random, 8 servers"):
        s = w[1]
        return dict(mean=s / (1 - rho), p99=math.log(100) * s / (1 - rho))
    if name == "M/M/4":
        m, p = mmc(4, rho, w[1])
        return dict(mean=m, p99=p)
    if name.startswith("M/G/1-PS") or name == "M/M/1-PS":
        return dict(mean=moments(w)[0] / (1 - rho), p99=None)
    if name.startswith("M/G/1"):
        return dict(mean=pk_mean(rho, w), p99=None)
    if name.startswith("least_conn"):
        n, s = case["servers"], w[1]
        return dict(lower=mmc(n, rho, s)[0], upper=s / (1 - rho))
    raise KeyError(name)


def run(job):
    case, seed, n = job
    bks = [Backend(i, case["c"], 1.0, case["disc"]) for i in range(case["servers"])]
    wl = make_workload(case["w"])
    bal = LeastConn() if case["bal"] == "least_conn" else Random()
    rate = rate_for(case["rho"], bks, wl)
    r = Sim(bks, bal, wl, rate, n, seed=seed).run()
    return dict(case=case, seed=seed, n=n, mean=r["mean"], p99=r["p99"])


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def mean_ci(xs):
    n = len(xs)
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))
    t = {5: 2.776, 10: 2.262, 20: 2.093}.get(n, 1.96)
    return m, t * sd / math.sqrt(n)


def report(rows):
    groups = {}
    for r in rows:
        k = (r["case"]["name"], r["case"]["rho"])
        groups.setdefault(k, []).append(r)
    order = []
    for c in cases():
        k = (c["name"], c["rho"])
        if k in groups and k not in order:
            order.append(k)
    nseeds = len(next(iter(groups.values())))
    n = rows[0]["n"]

    md = ["## Simulator validation against queueing theory", "",
          f"`sim/validate.py`: the simulator run on configurations with exact answers, "
          f"{nseeds} independent seeds × {n:,} requests each, first 20 % discarded. "
          "Sim is mean ± 95 % CI over seeds; error is (sim − theory) / theory. "
          "Service times have mean 10 ms unless noted (bimodal: 90 % 2 ms / 10 % 80 ms; "
          "lognormal: median 5 ms, σ = 1).", "",
          "| model | load | metric | theory (ms) | sim (ms) | error |",
          "| --- | --- | --- | --- | --- | --- |"]
    worst, inside, total = 0.0, 0, 0
    for k in order:
        g = groups[k]
        th = theory(g[0]["case"])
        for metric in ("mean", "p99"):
            m, ci = mean_ci([r[metric] for r in g])
            if "lower" in th:
                if metric != "mean":
                    continue
                ok = th["lower"] <= m <= th["upper"]
                md.append(f"| {k[0]} | {k[1]:.2f} | mean | between {th['lower']:.2f} (M/M/8) "
                          f"and {th['upper']:.2f} (random) | {m:.2f} ± {ci:.2f} | "
                          f"{'within bounds' if ok else '**outside bounds**'} |")
                continue
            if th[metric] is None:
                continue
            err = (m - th[metric]) / th[metric]
            worst = max(worst, abs(err))
            total += 1
            inside += abs(m - th[metric]) <= ci
            md.append(f"| {k[0]} | {k[1]:.2f} | {metric} | {th[metric]:.2f} | "
                      f"{m:.2f} ± {ci:.2f} | {err * 100:+.2f} % |")
    md += ["", f"Largest error on the exact cases: {worst * 100:.2f} %. The theoretical value "
           f"lies inside the simulator's 95 % CI in {inside} of {total} comparisons.", ""]
    return md, worst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--n", type=int, default=300000)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    o = ap.parse_args()
    jobs = [(c, s, o.n) for c in cases() for s in range(1, o.seeds + 1)]
    with Pool(o.jobs) as pool:
        rows = pool.map(run, jobs, chunksize=1)
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "sim_validation.json"), "w") as f:
        json.dump(rows, f)
    md, worst = report(rows)
    with open(os.path.join(RES, "sim_validation.md"), "w") as f:
        f.write("\n".join(["# Simulator validation", ""] + md[2:]))
    print("\n".join(md))


if __name__ == "__main__":
    main()
