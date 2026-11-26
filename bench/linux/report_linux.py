"""Report for the real-nginx Linux runs, plus simulator-vs-real validation.

Reads results/linux_*.jsonl (bench/linux/run.py) and results/sim_pr.json.
Writes results/linux_pr.md and results/fig_linux_p99_vs_stock.svg.

Each repetition r used the same arrivals and per-request costs (loadgen
-seed r) for every variant, so ratios are paired by repetition, as in the
simulator report.

  python3 bench/linux/report_linux.py
"""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "sim"))
from report_pr import (LABEL, SCEN, RES, mean_ci, paired_ratio,  # noqa: E402
                       fmt_ratio, dotplot, load)


def disturbed(rows, key):
    """Runs the load generator could not pace: send lag p99 over 2 ms and over 3x the median
    lag of the other runs of the same cell. Some cells have a systematic lag of a few ms
    (slow3: about 7.7 ms in every run, at most 2 % of p99, identical for every variant);
    a disturbance shows up as one run far above its siblings."""
    import statistics
    cells = {}
    for r in rows:
        cells.setdefault(key(r), []).append(r["send_lag_p99"])
    med = {k: statistics.median(v) for k, v in cells.items()}
    return [r for r in rows if r["send_lag_p99"] > 2.0 and r["send_lag_p99"] > 3 * med[key(r)]]


def metric(r):
    return r["window"]["p99"] if "window" in r else r["p99"]


def main():
    rows = []
    for p in sorted(glob.glob(os.path.join(RES, "linux_*.jsonl"))):
        stage = os.path.basename(p)[6:-6]
        for line in open(p):
            if line.strip():
                r = json.loads(line)
                r["stage"] = stage
                rows.append(r)
    if not rows:
        raise SystemExit("no results/linux_*.jsonl")
    bad = disturbed(rows, lambda r: (r["scenario"], r["util"], r["workers"]))
    ids = {id(r) for r in bad}
    rows = [r for r in rows if id(r) not in ids]

    def key(r):
        cfg = "1 worker" if r["workers"] == 1 else f"{r['workers']} workers + zone"
        return (cfg, r["scenario"], r["util"])

    by = {}
    for r in rows:
        by.setdefault(key(r), {}).setdefault(r["variant"], {})[r["rep"]] = r
    variants = [v for v in LABEL if any(v in d for d in by.values())]

    lag = sorted(r["send_lag_p99"] for r in rows)
    errors = sum(r["errors"] for r in rows)
    md = ["# Real nginx results (Linux)", "",
          "nginx 1.31 master and the patched trees, `-O2`, no debug logging, one worker unless "
          "noted, in a Linux VM (Docker Desktop, linuxkit kernel, 12 vCPUs of an Apple M2 Max). "
          "CPU sets: nginx 0-3, backends 4-7, load generator 8-11.", "",
          "Backends are Go HTTP servers with one FCFS worker each that hold the request for "
          "cost/speed ms. The load generator is open loop (Poisson), with latency measured from "
          "each request's scheduled send time. It draws every request's cost from the scenario's "
          "distribution with seed = repetition and passes it in the URL, so all variants of a "
          "repetition see identical arrivals and costs. Variants run in shuffled order inside "
          "each repetition. Each run is 5 s warm-up plus 30 s measured (slow3: 90 s, "
          "slowdown: 60 s, with p99 over the 20 s slow window).", "",
          f"Load generator send lag (scheduled to actual send), p99 across runs: median "
          f"{lag[len(lag) // 2]:.2f} ms, max {lag[-1]:.2f} ms. Errors: {errors} in "
          f"{len(rows)} runs. Disturbed runs excluded (send lag p99 over 2 ms and over 3x the "
          f"median of the same cell): {len(bad)}.", ""]

    md += ["## p99 change vs stock least_time (paired by repetition, 95 % CI)", "",
           "| config | scenario | util | n | " + " | ".join(LABEL[v] for v in variants if v != "lt") + " |",
           "| --- | --- | --- | --- |" + " --- |" * (len(variants) - 1)]
    for k in sorted(by):
        d = by[k]
        if "lt" not in d:
            continue
        base = {rep: metric(r) for rep, r in d["lt"].items()}
        cells = []
        for v in variants:
            if v == "lt":
                continue
            if v not in d:
                cells.append("")
                continue
            vals = {rep: metric(r) for rep, r in d[v].items()}
            cells.append(fmt_ratio(paired_ratio(vals, base)) if len(set(vals) & set(base)) > 1 else "")
        md.append(f"| {k[0]} | {k[1]} | {k[2]} | {len(base)} | " + " | ".join(cells) + " |")
    md.append("")

    md += ["## Absolute p99 and mean latency (ms, mean ± 95 % CI over repetitions)", ""]
    for k in sorted(by):
        d = by[k]
        md += [f"### {k[1]} @ {k[2]}, {k[0]}: {SCEN.get(k[1], '')}", "",
               "| variant | p99 | mean | share by backend (%) |", "| --- | --- | --- | --- |"]
        for v in variants:
            if v not in d:
                continue
            p99 = mean_ci([metric(r) for r in d[v].values()])
            mean = mean_ci([(r["window"] if "window" in r else r)["mean"] for r in d[v].values()])
            ports = {}
            for r in d[v].values():
                for p, c in r["by_port"].items():
                    ports[p] = ports.get(p, 0) + c
            tot = sum(ports.values()) or 1
            share = "/".join(f"{100 * ports[p] / tot:.0f}" for p in sorted(ports))
            md.append(f"| {LABEL[v]} | {p99[0]:.1f} ± {p99[1]:.1f} | {mean[0]:.2f} ± {mean[1]:.2f} | {share} |")
        md.append("")

    # simulator vs real
    sim = load("pr")
    if sim:
        sb = {}
        for r in sim:
            m = r["windows"]["during"]["p99"] if r["scenario"].startswith("slowdown") else r["p99"]
            sb.setdefault((r["scenario"], r["util"], r["balancer"]), []).append((m, r["share"]))
        md += ["## Simulator vs real nginx", "",
               "Same scenario, utilization and balancer; simulator: mean over 20 seeds; real: mean "
               "over repetitions. The simulator has no network or proxy overhead (about 0.1-0.3 ms "
               "per request here), so real latencies sit slightly higher. For slowdown, shares "
               "cover the whole run: the 20 s slow window is about 2 % of a simulated run "
               "(300,000 requests) but a third of a real one (60 s), hence 25 % vs 18 % for the "
               "slowed backend.", "",
               "| scenario | util | balancer | p99 sim | p99 real | share sim (%) | share real (%) |",
               "| --- | --- | --- | --- | --- | --- | --- |"]
        for k in sorted(by):
            if k[0] != "1 worker":
                continue
            for v in variants:
                s = sb.get((k[1], k[2], v))
                if not s or v not in by[k]:
                    continue
                sp99 = sum(x[0] for x in s) / len(s)
                sh = [sum(x[1][i] for x in s) for i in range(len(s[0][1]))]
                sshare = "/".join(f"{100 * c / sum(sh):.0f}" for c in sh)
                rr = by[k][v].values()
                rp99 = sum(metric(r) for r in rr) / len(rr)
                ports = {}
                for r in rr:
                    for p, c in r["by_port"].items():
                        ports[p] = ports.get(p, 0) + c
                tot = sum(ports.values()) or 1
                rshare = "/".join(f"{100 * ports[p] / tot:.0f}" for p in sorted(ports))
                md.append(f"| {k[1]} | {k[2]} | {LABEL[v]} | {sp99:.1f} | {rp99:.1f} | {sshare} | {rshare} |")
        md.append("")

    # figure: 1 worker, util 0.85 (fallback 0.7)
    frows = []
    for k in sorted(by, key=lambda k: (k[0], list(SCEN).index(k[1]) if k[1] in SCEN else 99, k[2])):
        d = by[k]
        if "lt" not in d or k[2] not in (0.7, 0.85):
            continue
        base = {rep: metric(r) for rep, r in d["lt"].items()}
        vals = {}
        for v in ["least_conn", "p1", "p123_b5_s3"]:
            if v in d and len(d[v]) > 1:
                vals[v] = paired_ratio({rep: metric(r) for rep, r in d[v].items()}, base)
        tag = "" if k[0] == "1 worker" else " (4w+zone)"
        frows.append((f"{k[1]} @{int(k[2] * 100)}%{tag}", vals))
    if frows:
        dotplot(frows, "Real nginx p99 relative to stock least_time",
                "Linux VM, -O2 builds, 70 % and 85 % load, 5 paired repetitions · whiskers: 95 % CI",
                os.path.join(RES, "fig_linux_p99_vs_stock.svg"), left=230)
        md += ["![real nginx p99 vs stock](fig_linux_p99_vs_stock.svg)", ""]

    out = os.path.join(RES, "linux_pr.md")
    with open(out, "w") as f:
        f.write("\n".join(md))
    print(out)


if __name__ == "__main__":
    main()
