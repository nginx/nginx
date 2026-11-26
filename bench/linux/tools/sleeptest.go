// sleeptest: how late do time.Sleep wake-ups arrive on this host?
package main

import (
	"fmt"
	"sort"
	"time"
)

func main() {
	for _, d := range []time.Duration{100 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 10 * time.Millisecond} {
		var over []float64
		for i := 0; i < 300; i++ {
			t := time.Now()
			time.Sleep(d)
			over = append(over, float64(time.Since(t)-d)/1e3)
			time.Sleep(time.Duration(i%7) * time.Millisecond)
		}
		sort.Float64s(over)
		fmt.Printf("sleep %v: overshoot p50 %.0fus p90 %.0fus p99 %.0fus\n", d, over[150], over[270], over[297])
	}
}
