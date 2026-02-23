import re
import numpy as np

latencies = []

# Dictionary to track when a process entered the runqueue (ready but waiting)
# Key: PID, Value: Timestamp (ns)
wait_queue = {}

# Matches: 2416.810728: sched:sched_wakeup: workload:3164 [120]...
wakeup_re = re.compile(
    r'\s+(\d+\.\d+):\s+sched:sched_wakeup:\s+(.*?):(\d+)\s+\['
)

# Matches: 2416.810728: sched:sched_switch: workload:3164 [120] R ==> swapper/0:0 [120]...
switch_re = re.compile(
    r'\s+(\d+\.\d+):\s+sched:sched_switch:\s+(.*?):(\d+)\s+\[.*?\]\s+([A-Z\+]+)\s+==>\s+(.*?):(\d+)\s+\['
)

with open("perf_script.txt") as f:
    for line in f:
        # 1. Check for wakeups (sleeping -> ready to run)
        w = wakeup_re.search(line)
        if w:
            ts = float(w.group(1))
            comm = w.group(2)
            pid = int(w.group(3))
            
            # If workload wakes up, record the time it entered the queue
            if "workload" in comm:
                wait_queue[pid] = ts * 1e9
            continue

        # 2. Check for context switches
        s = switch_re.search(line)
        if s:
            ts = float(s.group(1))
            prev_comm = s.group(2)
            prev_pid = int(s.group(3))
            prev_state = s.group(4)  # Captures the state, e.g., 'R', 'S', 'D'
            next_comm = s.group(5)
            next_pid = int(s.group(6))
            ts_ns = ts * 1e9

            # A. PREEMPTION: Did 'workload' get paused while still Runnable? (Running -> Waiting)
            if "workload" in prev_comm and "R" in prev_state:
                wait_queue[prev_pid] = ts_ns
            
            # B. EXECUTION: Did 'workload' finally get the CPU? (Waiting -> Running)
            if "workload" in next_comm:
                if next_pid in wait_queue:
                    # Calculate how long it waited in the queue
                    latencies.append(ts_ns - wait_queue[next_pid])
                    del wait_queue[next_pid]

latencies = np.array(latencies)

if len(latencies) == 0:
    print("Zero matches. Please ensure 'perf_script.txt' contains the RAW trace from `perf script`.")
else:
    print(f"Captured: {len(latencies)} runqueue wait events for 'workload'")
    print(f"Runqueue Latency avg (us): {latencies.mean() / 1000:.3f}")
