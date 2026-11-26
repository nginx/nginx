#!/bin/sh
# Real-nginx A/B of the fixed-point EWMA prototype against stock least_time.
# Variants are built by build/mkvariant.sh (see build/bin/).
tag() { python3 -c "import json,sys; d=json.load(sys.stdin); d.update($1); print(json.dumps(d))"; }
VARIANTS="b20:least_conn b20:least_time fp_b20:least_time fp_b1:least_time fp_b1_a01_t3s:least_time"

run() { # out scenario backends rates duration
  out=$1; sc=$2; B=$3; rates=$4; dur=$5
  for rate in $rates; do
    for seed in 1 2 3; do
      for v in $VARIANTS; do
        bin=${v%%:*}; bal=${v#*:}; [ "$bal" = least_time ] && bal="least_time header"
        NGINX_BIN=../build/bin/nginx-$bin python3 run_scenario.py --balancer "$bal" $B \
          --rate $rate --duration $dur --seed $seed \
          | tag "dict(scenario='$sc', variant='$bin', rate=$rate, seed=$seed)" >> $out
      done
    done
  done
}

OUT=../results/fp_real.jsonl; : > $OUT
run $OUT fast3 "--backend 9001:1:exp:2 --backend 9002:1:exp:6 --backend 9003:1:exp:15" "250 450" 20
B=""; for p in 9001 9002 9003 9004; do B="$B --backend $p:1:bimodal:2,80,0.1"; done
run $OUT bimodal4 "$B" "205 285" 30
