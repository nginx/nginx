#!/bin/sh
# Bimodal re-run of exp_fp.sh with more seeds (p99 of a 90/10 2 ms/80 ms mix is noisy).
# Run on an otherwise idle machine.
tag() { python3 -c "import json,sys; d=json.load(sys.stdin); d.update($1); print(json.dumps(d))"; }
VARIANTS="b20:least_conn b20:least_time fp_b1:least_time fp_b1_a01_t3s:least_time fp_b5_a01_t3s:least_time"
OUT=../results/fp_bimodal_real.jsonl; : > $OUT
B=""; for p in 9001 9002 9003 9004; do B="$B --backend $p:1:bimodal:2,80,0.1"; done
for rate in 205 285; do
  for seed in 1 2 3 4 5 6 7 8; do
    for v in $VARIANTS; do
      bin=${v%%:*}; bal=${v#*:}; [ "$bal" = least_time ] && bal="least_time header"
      NGINX_BIN=../build/bin/nginx-$bin python3 run_scenario.py --balancer "$bal" $B \
        --rate $rate --duration 30 --seed $seed \
        | tag "dict(scenario='bimodal4', variant='$bin', rate=$rate, seed=$seed)" >> $OUT
    done
  done
done
