"""Report for the nginx PRs from results/sim_pr.json (and sim_sweep.json).

Writes results/sim_pr.md and SVG figures results/fig_sim_*.svg.

Comparisons are paired: for a seed s, every balancer saw the same arrivals and
costs, so the ratio p99(variant, s) / p99(stock, s) cancels most of the
seed-to-seed noise.  We report the geometric mean ratio over seeds with a 95 %
t-interval on log ratios.

  python3 report_pr.py
"""
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(os.path.dirname(HERE), "results")

LABEL = {
    "rr": "round robin",
    "least_conn": "least_conn",
    "lt": "least_time (stock)",
    "p1": "P1: fixed point",
    "p12_b5": "P1+P2: bucket=5ms",
    "p123_b5_s3": "P1+P2+P3: bucket=5ms smooth=3s",
    "p13_s3": "P1+P3: smooth=3s",
}

SCEN = {
    "fast3": "3 backends, 2/6/15 ms mean",
    "slow3": "3 backends, 20/60/150 ms mean",
    "hetero8": "8 backends, speeds 2,2,1,1,1,1,½,½; exp 10 ms",
    "big16": "16 backends, speeds U(½,2); exp 10 ms",
    "lognorm_het": "8 backends as hetero8; lognormal(5 ms, σ=1)",
    "bimodal4": "4 equal backends; 90 % 2 ms / 10 % 80 ms",
    "bimodal4_het": "4 backends, speeds 2,1,1,½; 90 % 2 ms / 10 % 80 ms",
    "slowdown": "4 equal backends, one at ¼ speed for 20 s (FCFS)",
    "slowdown_ps": "as slowdown, processor-sharing backends",
    "homog8": "8 equal backends; exp 10 ms (control)",
    "fast3_homog": "3 equal backends; exp 5 ms (control)",
    "lognorm4": "4 equal backends; lognormal(5 ms, σ=1) (control)",
}

T95 = {5: 2.776, 10: 2.262, 20: 2.093}


def t95(n):
    return T95.get(n, 1.96 + 2.4 / max(n - 1, 1))


def metric(r, sub=None):
    if sub:
        return r["windows"][sub]["p99"]
    return r["p99"]


def load(name):
    p = os.path.join(RES, f"sim_{name}.json")
    return json.load(open(p)) if os.path.exists(p) else []


def index(rows, sub_for=lambda sc: None):
    by = {}
    for r in rows:
        sub = sub_for(r["scenario"])
        by.setdefault((r["scenario"], r["util"], r["balancer"]), {})[r["seed"]] = metric(r, sub)
    return by


def mean_ci(xs):
    n = len(xs)
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1)) if n > 1 else 0
    return m, t95(n) * sd / math.sqrt(n)


def paired_ratio(a, b):
    """geometric-mean ratio a/b over common seeds, with 95 % CI."""
    seeds = sorted(set(a) & set(b))
    logs = [math.log(a[s] / b[s]) for s in seeds]
    m, ci = mean_ci(logs)
    return math.exp(m), math.exp(m - ci), math.exp(m + ci), len(seeds)


def fmt_ratio(r):
    g, lo, hi, _ = r
    return f"{(g - 1) * 100:+.0f} % [{(lo - 1) * 100:+.0f}, {(hi - 1) * 100:+.0f}]"


# --------------------------------------------------------------------------
# SVG dot plot: rows = scenario@util, x = p99 relative to stock (log scale)
# --------------------------------------------------------------------------

SERIES = [  # (balancer, color, marker)
    ("least_conn", "#eb6834", "square"),
    ("p1", "#1baf7a", "triangle"),
    ("p123_b5_s3", "#2a78d6", "circle"),
]
INK, INK2, GRID, SURFACE = "#1f1f1e", "#5f5e5a", "#e4e3df", "#fcfcfb"


def marker(kind, x, y, color):
    if kind == "circle":
        return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}" stroke="{SURFACE}" stroke-width="2"/>'
    if kind == "square":
        return (f'<rect x="{x - 4.5:.1f}" y="{y - 4.5:.1f}" width="9" height="9" rx="1.5" '
                f'fill="{color}" stroke="{SURFACE}" stroke-width="2"/>')
    pts = f"{x:.1f},{y - 6:.1f} {x + 5.5:.1f},{y + 4:.1f} {x - 5.5:.1f},{y + 4:.1f}"
    return f'<polygon points="{pts}" fill="{color}" stroke="{SURFACE}" stroke-width="2"/>'


def dotplot(rows, title, subtitle, path, lo=0.5, hi=2.2, left=130):
    """rows: list of (label, {balancer: (g, lo, hi, n)})"""
    W, right, top, rowh = 630 + left, 56, 92, 26
    H = top + rowh * len(rows) + 72
    pw = W - left - right

    def X(v):
        v = min(max(v, lo), hi)
        return left + (math.log(v) - math.log(lo)) / (math.log(hi) - math.log(lo)) * pw

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">',
         f'<rect width="{W}" height="{H}" fill="{SURFACE}"/>',
         f'<text x="16" y="28" font-size="17" font-weight="600" fill="{INK}">{title}</text>',
         f'<text x="16" y="49" font-size="12.5" fill="{INK2}">{subtitle}</text>']
    # legend
    lx = 16
    for b, c, m in SERIES:
        o.append(marker(m, lx + 6, 70, c))
        o.append(f'<text x="{lx + 16}" y="74" font-size="12.5" fill="{INK}">{LABEL[b]}</text>')
        lx += 30 + 7.2 * len(LABEL[b])
    # grid
    ticks = [t for t in [0.5, 2 / 3, 0.8, 1.0, 1.25, 1.5, 2.0] if lo <= t <= hi]
    y0, y1 = top - 6, top + rowh * len(rows)
    for t in ticks:
        x = X(t)
        o.append(f'<line x1="{x:.1f}" y1="{y0}" x2="{x:.1f}" y2="{y1}" '
                 f'stroke="{INK2 if t == 1.0 else GRID}" stroke-width="{1.5 if t == 1.0 else 1}"/>')
        lab = f"{(t - 1) * 100:+.0f} %" if t != 1.0 else "stock"
        o.append(f'<text x="{x:.1f}" y="{y1 + 18}" font-size="11.5" fill="{INK2}" '
                 f'text-anchor="middle">{lab}</text>')
    o.append(f'<text x="{left + pw / 2:.0f}" y="{y1 + 40}" font-size="12" fill="{INK2}" '
             f'text-anchor="middle">p99 latency relative to stock least_time (log scale; left is better)</text>')
    o.append(f'<text x="16" y="{y1 + 58}" font-size="11" fill="{INK2}">slowdown rows: p99 over '
             f'the 20 s slow window</text>')
    for i, (label, vals) in enumerate(rows):
        y = top + rowh * i + rowh / 2
        if i % 2 == 0:
            o.append(f'<rect x="8" y="{y - rowh / 2:.1f}" width="{W - 16}" '
                     f'height="{rowh}" fill="#f3f2ee" opacity="0.6"/>')
        o.append(f'<text x="{left - 10}" y="{y + 4:.1f}" font-size="12" fill="{INK}" '
                 f'text-anchor="end">{label}</text>')
        for k, (b, c, m) in enumerate(SERIES):
            if b not in vals:
                continue
            g, a, z, _ = vals[b]
            yy = y + (k - 1) * 6
            o.append(f'<line x1="{X(a):.1f}" y1="{yy:.1f}" x2="{X(z):.1f}" y2="{yy:.1f}" '
                     f'stroke="{c}" stroke-width="2" stroke-linecap="round"/>')
            o.append(marker(m, X(g), yy, c))
    o.append("</svg>")
    with open(path, "w") as f:
        f.write("\n".join(o))


def main():
    rows = load("pr")
    if not rows:
        raise SystemExit("results/sim_pr.json missing")
    sub_for = (lambda sc: "during" if sc.startswith("slowdown") else None)
    by = index(rows, sub_for)
    scen_order = [s for s in SCEN if any(k[0] == s for k in by)]
    utils = sorted({k[1] for k in by})
    bals = [b for b in LABEL if any(k[2] == b for k in by)]
    nseeds = max(len(v) for v in by.values())
    n_req = rows[0]["n"]

    md = ["# Simulation results for the least_time patches", "",
          f"Discrete-event simulation (`sim/lbsim.py`), {nseeds} paired seeds × {n_req:,} requests "
          "per cell, Poisson arrivals, first 20 % discarded. One nginx worker (shared state). "
          "Backends are FCFS single-server queues unless noted. `LeastTimePatch` mirrors the "
          "patched C integer arithmetic (1/64 ms fixed point, smoothing weight "
          "`min(1, max(0.01, elapsed/smooth))`).", "",
          "Ratios are geometric means over seeds of p99(variant)/p99(stock least_time) on the "
          "same arrivals and costs, with 95 % t-intervals. Negative is better. "
          "For the slowdown scenarios, p99 is measured over the 20 s slow window.", ""]

    md += ["## Scenarios", "", "| name | setup |", "| --- | --- |"]
    md += [f"| {s} | {SCEN[s]} |" for s in scen_order]
    md.append("")

    # headline: p123 and p1 vs stock, and vs least_conn
    md += ["## p99 change vs stock least_time", "",
           "| scenario | util | least_conn | P1 | P1+P2 b5 | P1+P2+P3 b5 s3 | P1+P3 s3 |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    worst = {b: (None, 0) for b in bals}
    for s in scen_order:
        for u in utils:
            base = by.get((s, u, "lt"))
            if not base:
                continue
            cells = []
            for b in ["least_conn", "p1", "p12_b5", "p123_b5_s3", "p13_s3"]:
                v = by.get((s, u, b))
                if not v:
                    cells.append("")
                    continue
                r = paired_ratio(v, base)
                cells.append(fmt_ratio(r))
                if r[0] > worst[b][1] or worst[b][0] is None:
                    worst[b] = ((s, u), r[0])
            md.append(f"| {s} | {u} | " + " | ".join(cells) + " |")
    md.append("")

    md += ["## P1+P2+P3 vs least_conn", "",
           "Stock least_time loses to least_conn on mixed-cost traffic; this checks that the "
           "patched configuration does not.", "",
           "| scenario | " + " | ".join(f"util {u}" for u in utils) + " |",
           "| --- |" + " --- |" * len(utils)]
    for s in scen_order:
        cells = []
        for u in utils:
            a, b = by.get((s, u, "p123_b5_s3")), by.get((s, u, "least_conn"))
            cells.append(fmt_ratio(paired_ratio(a, b)) if a and b else "")
        md.append(f"| {s} | " + " | ".join(cells) + " |")
    md.append("")

    md += ["## Absolute p99 (ms, mean ± 95 % CI over seeds)", ""]
    for s in scen_order:
        md += [f"### {s}: {SCEN[s]}", "",
               "| balancer | " + " | ".join(f"util {u}" for u in utils) + " |",
               "| --- |" + " --- |" * len(utils)]
        for b in bals:
            cells = []
            for u in utils:
                v = by.get((s, u, b))
                if v:
                    m, ci = mean_ci(list(v.values()))
                    cells.append(f"{m:.1f} ± {ci:.1f}")
                else:
                    cells.append("")
            md.append(f"| {LABEL[b]} | " + " | ".join(cells) + " |")
        md.append("")

    # figure: one row per scenario at util 0.7 and 0.85
    for u in [0.7, 0.85]:
        frows = []
        for s in scen_order:
            base = by.get((s, u, "lt"))
            if not base:
                continue
            vals = {b: paired_ratio(by[(s, u, b)], base)
                    for b, _, _ in SERIES if (s, u, b) in by}
            frows.append((f"{s}", vals))
        name = f"fig_sim_p99_vs_stock_u{int(u * 100)}.svg"
        dotplot(frows, f"Simulated p99 relative to stock least_time, {int(u * 100)} % utilization",
                f"{nseeds} paired seeds × {n_req:,} requests per point · whiskers: 95 % CI "
                "(mostly narrower than the markers)",
                os.path.join(RES, name))
        md += [f"![p99 vs stock at {int(u * 100)} %]({name})", ""]

    sweep = load("sweep")
    if sweep:
        sb = index(sweep, sub_for)
        sc_sw = [s for s in SCEN if any(k[0] == s for k in sb)]
        md += ["## Parameter sweep: bucket × smooth (p99 vs stock)", "",
               "Geometric mean over the sweep scenarios of the paired p99 ratio vs stock, "
               "and the worst scenario. Scenarios: " + ", ".join(
                   f"{s}@{next(k[1] for k in sb if k[0] == s)}" for s in sc_sw) + ".", "",
               "| bucket | smooth | mean change | worst scenario |", "| --- | --- | --- | --- |"]
        for b in [1, 2, 5, 10, 20]:
            for sm in [0, 1000, 3000, 10000]:
                name = f"pb{b}_s{sm}"
                logs, worst_s = [], (None, -1)
                for s in sc_sw:
                    u = next(k[1] for k in sb if k[0] == s)
                    if (s, u, name) not in sb:
                        continue
                    r = paired_ratio(sb[(s, u, name)], sb[(s, u, "lt")])
                    logs.append(math.log(r[0]))
                    if r[0] > worst_s[1]:
                        worst_s = (s, r[0])
                if not logs:
                    continue
                g = math.exp(sum(logs) / len(logs))
                md.append(f"| {b} ms | {'off' if not sm else f'{sm / 1000:g} s'} | "
                          f"{(g - 1) * 100:+.1f} % | {worst_s[0]} {(worst_s[1] - 1) * 100:+.0f} % |")
        md.append("")

    vpath = os.path.join(RES, "sim_validation.json")
    if os.path.exists(vpath):
        from validate import report as vreport
        md += vreport(json.load(open(vpath)))[0]

    out = os.path.join(RES, "sim_pr.md")
    with open(out, "w") as f:
        f.write("\n".join(md))
    print(out)


if __name__ == "__main__":
    main()
