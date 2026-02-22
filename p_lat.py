import re
import numpy as np

latencies = []
wakeup = {}

wakeup_re = re.compile(
    r'\s+(\d+\.\d+):\s+sched:sched_wakeup:\s+.+:(\d+)\s+\['
)

switch_re = re.compile(
    r'\s+(\d+\.\d+):\s+sched:sched_switch:.*==>\s+.+:(\d+)\s+\['
)

with open("perf_script.txt") as f:
    for line in f:
        w = wakeup_re.search(line)
        if w:
            ts = float(w.group(1))
            pid = int(w.group(2))
            wakeup[pid] = ts * 1e9
            continue

        s = switch_re.search(line)
        if s:
            ts = float(s.group(1))
            pid = int(s.group(2))
            ts_ns = ts * 1e9

            if pid in wakeup:
                latencies.append(ts_ns - wakeup[pid])
                del wakeup[pid]

latencies = np.array(latencies)

if len(latencies) == 0:
    print("Still zero matches — check wakeup regex.")
else:
    print("Captured:", len(latencies), "latencies")
    print("perf avg (us):", latencies.mean() / 1000)

