#!/usr/bin/env python3
"""Hypothesis sweeps H1..H6 (see ../PLAN.md). Writes ../results/sim_<h>.json
and prints markdown tables.

usage: experiments.py [h1 h2 ...] [--seeds 5] [--n 100000] [--jobs 8]
"""
import argparse
import json
import math
import os
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lbsim import (Backend, Sim, RoundRobin, LeastConn, Random, LeastTime,  # noqa
                   LeastTimePatch,
                   RandomTwoLeastTime, ServiceTimeSED, PeakEWMA, LeastWork,
                   Oracle, exp_workload, classes_workload, lognormal_workload,
                   rate_for)

RESULTS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "results")

BAL = {
    "rr": lambda: RoundRobin(),
    "least_conn": lambda: LeastConn(),
    "random_two": lambda: Random(two=True),
    "lt": lambda: LeastTime(),
    "lt_b10": lambda: LeastTime(bucket=10),
    "lt_b5": lambda: LeastTime(bucket=5),
    "lt_b1": lambda: LeastTime(bucket=1),
    "lt_rel": lambda: LeastTime(bucket=1, relative=0.25),
    "lt_inflight": lambda: LeastTime(inflight=True),
    "lt_inflight_b1": lambda: LeastTime(inflight=True, bucket=1),
    "lt_nodecay": lambda: LeastTime(decay=False),
    "lt_a01": lambda: LeastTime(alpha=0.01),
    "lt_b1_a01": lambda: LeastTime(bucket=1, alpha=0.01),
    "lt_b5_a02": lambda: LeastTime(bucket=5, alpha=0.02),
    "lt_b1_fp": lambda: LeastTime(bucket=1, precise=True),
    "lt_b1_a02_fp": lambda: LeastTime(bucket=1, alpha=0.02, precise=True),
    "lt_b1_a01_fp": lambda: LeastTime(bucket=1, alpha=0.01, precise=True),
    "lt_b1_a005_fp": lambda: LeastTime(bucket=1, alpha=0.005, precise=True),
    "lt_b1_a01_tau1s": lambda: LeastTime(bucket=1, alpha=0.01, tau=1000,
                                         precise=True),
    "lt_b1_a01_tau3s": lambda: LeastTime(bucket=1, alpha=0.01, tau=3000,
                                         precise=True),
    "lt_b1_a005_tau1s": lambda: LeastTime(bucket=1, alpha=0.005, tau=1000,
                                          precise=True),
    # staged upstream patches: fixed point alone, then bucket, then alpha/tau
    "lt_fp": lambda: LeastTime(precise=True),
    "lt_fp_a01_tau3s": lambda: LeastTime(alpha=0.01, tau=3000, precise=True),
    "lt_b5_fp": lambda: LeastTime(bucket=5, precise=True),
    "lt_b5_a01_tau3s": lambda: LeastTime(bucket=5, alpha=0.01, tau=3000,
                                         precise=True),
    "r2_lt": lambda: RandomTwoLeastTime(),
    "r2_lt_b1": lambda: RandomTwoLeastTime(bucket=1),
    "sed": lambda: ServiceTimeSED(),
    "peak_ewma": lambda: PeakEWMA(tau=10000),
    "peak_ewma_1s": lambda: PeakEWMA(tau=1000),
    "p2c_peak_ewma": lambda: PeakEWMA(tau=10000, two=True),
    "least_work": lambda: LeastWork(),
    "least_work_ls": lambda: LeastWork(learn_speed=True),
    "oracle": lambda: Oracle(),
    # exact models of patches/0001..0003 (LeastTimePatch)
    "p1": lambda: LeastTimePatch(),
    "p12_b5": lambda: LeastTimePatch(bucket=5),
    "p123_b5_s3": lambda: LeastTimePatch(bucket=5, smooth=3000),
    "p13_s3": lambda: LeastTimePatch(smooth=3000),
    "p123_b5_s3_inflight": lambda: LeastTimePatch(inflight=True, bucket=5,
                                                  smooth=3000),
}


def get_bal(name):
    """BAL entry, or "pb<bucket>_s<smooth ms|0>[_i]" for the parameter sweep."""
    if name in BAL:
        return BAL[name]()
    if name.startswith("pb"):
        parts = name[2:].split("_")
        b, s = int(parts[0]), int(parts[1][1:])
        return LeastTimePatch(bucket=b, smooth=s or None,
                              inflight="i" in parts[2:])
    raise KeyError(name)


# --------------------------------------------------------------------------
# Scenarios: name -> dict(backends=fn, workload=fn, events=fn, kw)
# --------------------------------------------------------------------------

def hetero_fast():
    # mean service 2, 6, 15 ms (all under the 20 ms bucket)
    return [Backend(0, 1, 1.0), Backend(1, 1, 1 / 3), Backend(2, 1, 2 / 15)]


def scen(name, sigma=0.0):
    if name == "fast3":          # H1: sub-20ms heterogeneous
        return dict(backends=hetero_fast, workload=lambda: exp_workload(2.0))
    if name == "slow3":          # H1 control: same ratios, 10x slower
        return dict(backends=hetero_fast, workload=lambda: exp_workload(20.0))
    if name == "fast3_homog":    # H1 regression check
        return dict(backends=lambda: [Backend(i, 1, 1.0) for i in range(3)],
                    workload=lambda: exp_workload(5.0))
    if name == "homog8":         # H2
        return dict(backends=lambda: [Backend(i, 1, 1.0) for i in range(8)],
                    workload=lambda: exp_workload(10.0))
    if name == "hetero8":        # H2 with unequal capacity
        sp = [2, 2, 1, 1, 1, 1, 0.5, 0.5]
        return dict(backends=lambda: [Backend(i, 1, s) for i, s in enumerate(sp)],
                    workload=lambda: exp_workload(10.0))
    if name.startswith("slowdown"):  # H3/H4: one peer drops to 25 % for 20 s
        disc = "ps" if name.endswith("_ps") else "fcfs"
        c = 4 if ("_c4" in name or disc == "ps") else 1
        return dict(backends=lambda: [Backend(i, c, 1.0, disc) for i in range(4)],
                    workload=lambda: exp_workload(10.0), slowdown=True)
    if name.startswith("big"):   # H5: N heterogeneous peers
        n = int(name[3:])

        def bks():
            import random
            r = random.Random(42)
            return [Backend(i, 1, r.uniform(0.5, 2.0)) for i in range(n)]
        return dict(backends=bks, workload=lambda: exp_workload(10.0))
    if name == "bimodal4":       # H6
        return dict(backends=lambda: [Backend(i, 1, 1.0) for i in range(4)],
                    workload=lambda: classes_workload([(0.9, 2.0), (0.1, 80.0)],
                                                      sigma))
    if name == "lognorm4":       # heavy-tailed service, equal capacity
        return dict(backends=lambda: [Backend(i, 1, 1.0) for i in range(4)],
                    workload=lambda: lognormal_workload(5.0, 1.0))
    if name == "lognorm_het":    # heavy-tailed service, unequal capacity
        sp = [2, 2, 1, 1, 1, 1, 0.5, 0.5]
        return dict(backends=lambda: [Backend(i, 1, s) for i, s in enumerate(sp)],
                    workload=lambda: lognormal_workload(5.0, 1.0))
    if name == "bimodal4_het":   # H6 heterogeneous capacity
        sp = [2, 1, 1, 0.5]
        return dict(backends=lambda: [Backend(i, 1, s) for i, s in enumerate(sp)],
                    workload=lambda: classes_workload([(0.9, 2.0), (0.1, 80.0)],
                                                      sigma))
    raise KeyError(name)


def run_job(job):
    sc = scen(job["scenario"], job.get("sigma", 0.0))
    bks = sc["backends"]()
    wl = sc["workload"]()
    rate = rate_for(job["util"], bks, wl)
    events = []
    windows = None
    if sc.get("slowdown"):
        dur = job["n"] / rate * 1000.0          # ms of arrivals
        t1, t2 = dur * 0.4, dur * 0.4 + 20000.0

        def slow(sim, now):
            sim.backends[0].set_speed(sim, 0.25, now)

        def fast(sim, now):
            sim.backends[0].set_speed(sim, 1.0, now)
        events = [(t1, slow), (t2, fast)]
        windows = {"before": (dur * 0.2, t1), "during": (t1, t2),
                   "after": (t2, t2 + 20000.0)}
    sim = Sim(bks, get_bal(job["balancer"]), wl, rate, job["n"],
              workers=job.get("workers", 1), shared=job.get("shared", True),
              weights=job.get("weights"), seed=job["seed"], events=events)
    res = sim.run()
    if windows:
        sim.warmup = 0.0
        res["windows"] = {k: sim.summary(v) for k, v in windows.items()}
    res.update(job)
    res["rate"] = rate
    return res


# --------------------------------------------------------------------------
# Experiment definitions
# --------------------------------------------------------------------------

UTILS = [0.5, 0.7, 0.85, 0.95]


def jobs_for(h, seeds, n):
    J = []

    def add(**kw):
        for s in range(1, seeds + 1):
            J.append(dict(seed=s, n=n, **kw))

    if h == "h1":
        bals = ["least_conn", "lt", "lt_b10", "lt_b5", "lt_b1", "lt_rel",
                "lt_inflight", "lt_inflight_b1", "lt_nodecay"]
        for sc in ["fast3", "slow3", "fast3_homog"]:
            for u in UTILS:
                for b in bals:
                    add(h=h, scenario=sc, util=u, balancer=b)
    elif h == "h2":
        for sc in ["homog8", "hetero8"]:
            for u in [0.7, 0.9]:
                for b in ["least_conn", "lt", "lt_b1", "random_two", "r2_lt_b1"]:
                    for k in [1, 2, 4, 8, 16]:
                        for shared in ([True, False] if k > 1 else [True]):
                            add(h=h, scenario=sc, util=u, balancer=b,
                                workers=k, shared=shared)
    elif h == "h3":
        for sc in ["slowdown", "slowdown_c4", "slowdown_ps"]:
            for u in [0.3, 0.7]:
                for b in ["least_conn", "lt", "lt_b1", "lt_inflight_b1", "sed",
                          "peak_ewma", "peak_ewma_1s"]:
                    add(h=h, scenario=sc, util=u, balancer=b)
    elif h == "h5":
        for sc in ["big4", "big16", "big64"]:
            for u in [0.7, 0.9]:
                for b in ["least_conn", "random_two", "lt", "lt_b1", "r2_lt",
                          "r2_lt_b1", "p2c_peak_ewma"]:
                    for k, shared in [(1, True), (8, False)]:
                        add(h=h, scenario=sc, util=u, balancer=b,
                            workers=k, shared=shared)
    elif h == "h6":
        for sc in ["bimodal4", "bimodal4_het"]:
            for u in UTILS:
                for b in ["least_conn", "lt", "lt_b1", "sed", "peak_ewma",
                          "oracle"]:
                    add(h=h, scenario=sc, util=u, balancer=b)
                for sigma in [0.0, 0.5, 1.0]:
                    b = "least_work" if sc == "bimodal4" else "least_work_ls"
                    add(h=h, scenario=sc, util=u, balancer=b, sigma=sigma)
    elif h == "alpha":
        for sc, u in [("fast3", 0.7), ("hetero8", 0.7), ("slowdown", 0.7),
                      ("bimodal4", 0.5), ("bimodal4", 0.85),
                      ("bimodal4_het", 0.7), ("big16", 0.7)]:
            for b in ["least_conn", "lt", "lt_a01", "lt_b1", "lt_b1_a01",
                      "lt_b5", "lt_b5_a02"]:
                add(h=h, scenario=sc, util=u, balancer=b)
    elif h == "ewma":
        for sc, u in [("fast3", 0.5), ("fast3", 0.85), ("slow3", 0.7),
                      ("hetero8", 0.7), ("hetero8", 0.9), ("slowdown", 0.3),
                      ("slowdown", 0.7), ("slowdown_ps", 0.7),
                      ("bimodal4", 0.5), ("bimodal4", 0.85),
                      ("bimodal4_het", 0.7), ("big16", 0.7),
                      ("fast3_homog", 0.85)]:
            for b in ["least_conn", "lt", "lt_b1", "lt_b1_a01", "lt_b1_fp",
                      "lt_b1_a02_fp", "lt_b1_a01_fp", "lt_b1_a005_fp",
                      "lt_b1_a01_tau1s", "lt_b1_a01_tau3s",
                      "lt_b1_a005_tau1s"]:
                add(h=h, scenario=sc, util=u, balancer=b)
    elif h == "pr":
        # evidence matrix for the nginx PRs: every scenario x utilization,
        # paired seeds (same arrivals and costs for every balancer)
        for sc in ["fast3", "slow3", "hetero8", "big16", "lognorm_het",
                   "bimodal4", "bimodal4_het", "slowdown", "slowdown_ps",
                   "homog8", "fast3_homog", "lognorm4"]:
            for u in UTILS:
                for b in ["rr", "least_conn", "lt", "p1", "p12_b5",
                          "p123_b5_s3", "p13_s3"]:
                    add(h=h, scenario=sc, util=u, balancer=b)
    elif h == "sweep":
        # parameter choice for bucket= and smooth=
        for sc, u in [("fast3", 0.7), ("slow3", 0.7), ("hetero8", 0.85),
                      ("lognorm_het", 0.7), ("bimodal4", 0.7),
                      ("bimodal4_het", 0.7), ("slowdown", 0.7),
                      ("homog8", 0.85)]:
            for b in [1, 2, 5, 10, 20]:
                for s in [0, 1000, 3000, 10000]:
                    add(h=h, scenario=sc, util=u, balancer=f"pb{b}_s{s}")
            add(h=h, scenario=sc, util=u, balancer="least_conn")
            add(h=h, scenario=sc, util=u, balancer="lt")
    elif h == "staged":
        for sc, u in [("fast3", 0.5), ("fast3", 0.85), ("slow3", 0.7),
                      ("hetero8", 0.7), ("hetero8", 0.9), ("slowdown", 0.7),
                      ("slowdown_ps", 0.7), ("bimodal4", 0.5),
                      ("bimodal4", 0.85), ("bimodal4_het", 0.7),
                      ("big16", 0.7), ("fast3_homog", 0.85), ("homog8", 0.85)]:
            for b in ["least_conn", "lt", "lt_fp", "lt_fp_a01_tau3s",
                      "lt_b5_fp", "lt_b5_a01_tau3s", "lt_b1_fp",
                      "lt_b1_a01_tau3s"]:
                add(h=h, scenario=sc, util=u, balancer=b)
    return J


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def stat(xs):
    m = sum(xs) / len(xs)
    if len(xs) < 2:
        return m, 0.0
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))
    return m, 1.96 * sd / math.sqrt(len(xs))


def group(results, keys, metric, sub=None):
    g = {}
    for r in results:
        src = r["windows"][sub] if sub else r
        g.setdefault(tuple(r.get(k) for k in keys), []).append(src[metric])
    return g


def table(results, row_keys, col_key, metric="p99", sub=None, fmt="{:.1f}"):
    cols = sorted({r[col_key] for r in results}, key=str)
    g = group(results, row_keys + [col_key], metric, sub)
    rows = sorted({k[:-1] for k in g}, key=lambda k: [str(x) for x in k])
    out = ["| " + " | ".join(row_keys) + " | "
           + " | ".join(f"{col_key}={c}" for c in cols) + " |",
           "|" + "---|" * (len(row_keys) + len(cols))]
    for rk in rows:
        cells = []
        for c in cols:
            xs = g.get(rk + (c,))
            if xs:
                m, ci = stat(xs)
                cells.append(fmt.format(m) + f" ±{ci:.1f}")
            else:
                cells.append("")
        out.append("| " + " | ".join(str(x) for x in rk) + " | "
                   + " | ".join(cells) + " |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hyps", nargs="*", default=["h1", "h2", "h3", "h5", "h6"])
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--n", type=int, default=100000)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    o = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    with Pool(o.jobs) as pool:
        for h in o.hyps:
            J = jobs_for(h, o.seeds, o.n)
            res = pool.map(run_job, J, chunksize=1)
            with open(os.path.join(RESULTS, f"sim_{h}.json"), "w") as f:
                json.dump(res, f)
            print(f"## {h}: {len(res)} runs\n")


if __name__ == "__main__":
    main()
