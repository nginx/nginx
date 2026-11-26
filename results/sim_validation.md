# Simulator validation

`sim/validate.py`: the simulator run on configurations with exact answers, 20 independent seeds × 300,000 requests each, first 20 % discarded. Sim is mean ± 95 % CI over seeds; error is (sim − theory) / theory. Service times have mean 10 ms unless noted (bimodal: 90 % 2 ms / 10 % 80 ms; lognormal: median 5 ms, σ = 1).

| model | load | metric | theory (ms) | sim (ms) | error |
| --- | --- | --- | --- | --- | --- |
| M/M/1 | 0.50 | mean | 20.00 | 20.00 ± 0.06 | +0.01 % |
| M/M/1 | 0.50 | p99 | 92.10 | 92.32 ± 0.64 | +0.24 % |
| M/M/1 | 0.70 | mean | 33.33 | 33.32 ± 0.18 | -0.05 % |
| M/M/1 | 0.70 | p99 | 153.51 | 154.13 ± 1.70 | +0.41 % |
| M/M/1 | 0.85 | mean | 66.67 | 66.54 ± 0.72 | -0.19 % |
| M/M/1 | 0.85 | p99 | 307.01 | 307.88 ± 5.59 | +0.28 % |
| M/M/1 | 0.95 | mean | 200.00 | 199.95 ± 8.45 | -0.03 % |
| M/M/1 | 0.95 | p99 | 921.03 | 924.48 ± 81.10 | +0.37 % |
| random, 8 servers | 0.70 | mean | 33.33 | 33.23 ± 0.16 | -0.30 % |
| random, 8 servers | 0.70 | p99 | 153.51 | 153.74 ± 1.39 | +0.15 % |
| random, 8 servers | 0.85 | mean | 66.67 | 66.46 ± 0.65 | -0.31 % |
| random, 8 servers | 0.85 | p99 | 307.01 | 307.23 ± 5.01 | +0.07 % |
| M/M/4 | 0.70 | mean | 13.57 | 13.57 ± 0.04 | -0.05 % |
| M/M/4 | 0.70 | p99 | 54.93 | 55.00 ± 0.29 | +0.14 % |
| M/M/4 | 0.85 | mean | 21.49 | 21.44 ± 0.18 | -0.20 % |
| M/M/4 | 0.85 | p99 | 85.59 | 85.80 ± 1.31 | +0.24 % |
| M/M/4 | 0.95 | mean | 54.57 | 54.56 ± 2.10 | -0.02 % |
| M/M/4 | 0.95 | p99 | 235.67 | 236.31 ± 19.77 | +0.27 % |
| M/G/1 bimodal | 0.50 | mean | 75.47 | 75.84 ± 0.79 | +0.49 % |
| M/G/1 bimodal | 0.70 | mean | 163.04 | 164.24 ± 2.94 | +0.74 % |
| M/G/1 bimodal | 0.85 | mean | 381.95 | 386.87 ± 13.41 | +1.29 % |
| M/G/1 lognormal | 0.50 | mean | 19.45 | 19.43 ± 0.15 | -0.07 % |
| M/G/1 lognormal | 0.70 | mean | 34.39 | 34.42 ± 0.40 | +0.09 % |
| M/M/1-PS | 0.70 | mean | 33.33 | 33.32 ± 0.18 | -0.03 % |
| M/G/1-PS bimodal | 0.70 | mean | 32.67 | 32.87 ± 0.51 | +0.63 % |
| M/M/1-PS | 0.85 | mean | 66.67 | 66.58 ± 0.71 | -0.13 % |
| M/G/1-PS bimodal | 0.85 | mean | 65.33 | 66.07 ± 1.99 | +1.13 % |
| least_conn, 8 servers | 0.70 | mean | between 11.13 (M/M/8) and 33.33 (random) | 12.17 ± 0.03 | within bounds |
| least_conn, 8 servers | 0.85 | mean | between 14.77 (M/M/8) and 66.67 (random) | 16.84 ± 0.10 | within bounds |

Largest error on the exact cases: 1.29 %. The theoretical value lies inside the simulator's 95 % CI in 27 of 27 comparisons.
