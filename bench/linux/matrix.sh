#!/bin/sh
# Full real-nginx evidence matrix, in stages (each appends to its own file).
# Run inside the container:  sh /w/bench/linux/matrix.sh
# Keep the host otherwise idle while it runs (about 6.5 h).
set -e
R=/w/results
cd /w/bench/linux

# A: core scenarios at 70 and 85 %
python3 run.py --scenarios fast3,hetero8,bimodal4,bimodal4_het,homog8 \
  --utils 0.7,0.85 --reps 5 --out $R/linux_A.jsonl

# B: the rest
python3 run.py --scenarios fast3,hetero8 --utils 0.5 --reps 5 --out $R/linux_B.jsonl
python3 run.py --scenarios lognorm_het --utils 0.7,0.85 --reps 5 --out $R/linux_B.jsonl
python3 run.py --scenarios slow3,slowdown --utils 0.7 --reps 5 --out $R/linux_B.jsonl

# C: 4 workers sharing state through a zone, reuseport
python3 run.py --scenarios hetero8,bimodal4_het --utils 0.85 --reps 5 \
  --workers 4 --zone --out $R/linux_C.jsonl
