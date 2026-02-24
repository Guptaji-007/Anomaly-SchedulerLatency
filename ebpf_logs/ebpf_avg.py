import re
import numpy as np

latencies = []

pattern = re.compile(r'latency ([\d\.]+) us')

with open("ebpf_latency.txt") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            latencies.append(float(m.group(1)))

latencies = np.array(latencies)

print("Captured:", len(latencies))
print("eBPF avg (us):", latencies.mean())
