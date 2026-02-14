import numpy as np

latencies = []
wakeup = {}

with open("ebpf_raw.log") as f:
    for line in f:
        ts, pid, typ = line.split()
        ts = int(ts)
        pid = int(pid)
        typ = int(typ)

        if typ == 0:
            wakeup[pid] = ts

        elif typ == 1:
            if pid in wakeup:
                latencies.append(ts - wakeup[pid])
                del wakeup[pid]

latencies = np.array(latencies)

np.savetxt("ebpf_latencies.txt", latencies, fmt="%d")

print("eBPF avg (us):", latencies.mean()/1000)
