import re
import numpy as np

latencies = []
wait_queue = {}

wakeup_re = re.compile(
    r'.*\s(\d+\.\d+):\s+sched:sched_wakeup:\s+(.*?):(\d+)\s+\['
)

switch_re = re.compile(
    r'.*\s(\d+\.\d+):\s+sched:sched_switch:\s+(.*?):(\d+)\s+\[.*?\]\s+([A-Z\+]+)\s+==>\s+(.*?):(\d+)\s+\['
)

with open("perf_script.txt") as f:
    for line in f:
        # --- wakeup ---
        w = wakeup_re.search(line)
        if w:
            ts = float(w.group(1))
            comm = w.group(2)
            pid = int(w.group(3))

            if "workload" in comm:
                wait_queue[pid] = ts * 1e9
            continue

        # --- sched switch ---
        s = switch_re.search(line)
        if s:
            ts = float(s.group(1))
            prev_comm = s.group(2)
            prev_pid = int(s.group(3))
            prev_state = s.group(4)
            next_comm = s.group(5)
            next_pid = int(s.group(6))
            ts_ns = ts * 1e9

            # preemption
            if "workload" in prev_comm and "R" in prev_state:
                wait_queue[prev_pid] = ts_ns

            # scheduled to run
            if "workload" in next_comm:
                if next_pid in wait_queue:
                    latencies.append(ts_ns - wait_queue[next_pid])
                    del wait_queue[next_pid]

latencies = np.array(latencies)

if len(latencies) == 0:
    print("Still zero matches — check input file")
else:
    print(f"Captured: {len(latencies)} runqueue wait events")
    print(f"Runqueue Latency avg (us): {latencies.mean()/1000:.3f}")
