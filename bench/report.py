"""Summarize a real-nginx results .jsonl: mean ±95% CI over seeds per cell.

usage: python3 report.py ../results/fp_real.jsonl [metric ...]
"""
import json
import math
import sys


def stat(xs):
    m = sum(xs) / len(xs)
    if len(xs) < 2:
        return m, 0.0
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))
    return m, 1.96 * sd / math.sqrt(len(xs))


def main():
    rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
    metrics = sys.argv[2:] or ["p50", "p99", "mean"]
    cells = {}
    for r in rows:
        name = r["variant"] + (" lc" if r["balancer"] == "least_conn" else "")
        cells.setdefault((r["scenario"], r["rate"]), {}).setdefault(name, []).append(r)
    for (sc, rate), byv in sorted(cells.items()):
        print(f"\n### {sc} @ {rate} rps\n")
        print("| variant | n | " + " | ".join(metrics) + " | share by port |")
        print("| --- | --- |" + " --- |" * len(metrics) + " --- |")
        for v, rs in byv.items():
            vals = []
            for m in metrics:
                mean, ci = stat([r[m] for r in rs])
                vals.append(f"{mean:.1f} ±{ci:.1f}")
            ports = {}
            for r in rs:
                for p, c in r["by_port"].items():
                    ports[p] = ports.get(p, 0) + c
            tot = sum(ports.values())
            share = "/".join(f"{100 * ports[p] / tot:.0f}" for p in sorted(ports))
            print(f"| {v} | {len(rs)} | " + " | ".join(vals) + f" | {share} |")


if __name__ == "__main__":
    main()
