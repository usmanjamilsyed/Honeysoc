"""Extra offline analysis of the HoneySOC hash chain (reuses simulate.py, no network/Redis).

1. Tamper sweep: modify each of the 100 events in turn and record whether verify() fails.
2. Reorder sweep: swap each adjacent pair and record whether verify() fails.
3. Full-rewrite case: an attacker edits an event AND recomputes all later hashes.
   verify() alone accepts this; comparing the head hash with an independently
   stored trusted checkpoint detects it.
4. Benchmark repeats: 10,000-event hash-chain throughput over several runs.

Writes CSV/JSON and figures into results/.
"""
import hashlib
import json
import statistics
import time
from copy import deepcopy
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from simulate import GENESIS, digest, verify

OUT = Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)
N = 100


def build(n=N):
    chain, prev = [], GENESIS
    for i in range(n):
        ev = {"event_id": i, "attack_type": "SQL_Injection", "attacker_ip": "192.0.2.10", "timestamp": i}
        h = digest(ev, prev)
        chain.append({"event": ev, "previous_hash": prev, "hash": h})
        prev = h
    return chain


def rewrite_from(chain, idx, new_type="modified"):
    c = deepcopy(chain)
    c[idx]["event"]["attack_type"] = new_type
    prev = c[idx]["previous_hash"]
    for b in c[idx:]:
        b["previous_hash"] = prev
        b["hash"] = digest(b["event"], prev)
        prev = b["hash"]
    return c


chain = build()
trusted_head = chain[-1]["hash"]

# 1 tamper sweep
tamper = []
for i in range(N):
    t = deepcopy(chain)
    t[i]["event"]["attack_type"] = "modified"
    tamper.append({"position": i, "detected": not verify(t)})
# 2 reorder sweep
reorder = []
for i in range(N - 1):
    r = deepcopy(chain)
    r[i], r[i + 1] = r[i + 1], r[i]
    reorder.append({"position": i, "detected": not verify(r)})
# 3 full rewrite
rewrite = []
for i in range(N):
    w = rewrite_from(chain, i)
    rewrite.append({"position": i,
                    "verify_alone_detects": not verify(w),
                    "checkpoint_detects": w[-1]["hash"] != trusted_head})

# 4 benchmark repeats
def bench(n=10000):
    prev, log = GENESIS, {"event_id": 0, "attack_type": "SQL_Injection", "attacker_ip": "192.168.1.100",
                          "timestamp": "2026-06-28T12:00:00Z"}
    s = time.perf_counter()
    for i in range(n):
        log["event_id"] = i
        prev = hashlib.sha256((json.dumps(log, sort_keys=True) + prev).encode()).hexdigest()
    return n / (time.perf_counter() - s)

runs = [bench() for _ in range(10)]
summary = {
    "events": N,
    "tamper_detected": f"{sum(x['detected'] for x in tamper)}/{N}",
    "reorder_detected": f"{sum(x['detected'] for x in reorder)}/{N-1}",
    "full_rewrite_detected_by_verify_alone": f"{sum(x['verify_alone_detects'] for x in rewrite)}/{N}",
    "full_rewrite_detected_by_trusted_checkpoint": f"{sum(x['checkpoint_detects'] for x in rewrite)}/{N}",
    "benchmark_runs": len(runs),
    "throughput_eps_mean": round(statistics.mean(runs), 1),
    "throughput_eps_std": round(statistics.stdev(runs), 1),
    "throughput_eps_min": round(min(runs), 1),
    "throughput_eps_max": round(max(runs), 1),
}
(OUT / "chain_analysis_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))

import csv
with open(OUT / "benchmark_runs.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["run", "events_per_second"])
    for i, v in enumerate(runs, 1):
        w.writerow([i, round(v, 1)])

# figures
labels = ["Tamper\n(1 event edited)", "Reorder\n(adjacent swap)", "Full rewrite\nverify() only", "Full rewrite\ntrusted checkpoint"]
vals = [100 * sum(x["detected"] for x in tamper) / N,
        100 * sum(x["detected"] for x in reorder) / (N - 1),
        100 * sum(x["verify_alone_detects"] for x in rewrite) / N,
        100 * sum(x["checkpoint_detects"] for x in rewrite) / N]
plt.figure(figsize=(7, 4))
bars = plt.bar(labels, vals, color=["#2ca02c", "#2ca02c", "#d62728", "#2ca02c"])
for b, v in zip(bars, vals):
    plt.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.0f}%", ha="center")
plt.ylim(0, 115); plt.ylabel("Detection rate (%)")
plt.title("HoneySOC hash chain: attack detection (100-event chain)")
plt.tight_layout(); plt.savefig(OUT / "chain_detection_rates.png", dpi=150); plt.close()

plt.figure(figsize=(6, 4))
plt.plot(range(1, len(runs) + 1), runs, "o-")
plt.axhline(statistics.mean(runs), ls="--", color="gray", label=f"mean {statistics.mean(runs):,.0f} EPS")
plt.xlabel("Run"); plt.ylabel("Events per second"); plt.ylim(bottom=0)
plt.title("Hash-chain throughput (10,000 events/run)"); plt.legend(); plt.grid(alpha=.3)
plt.tight_layout(); plt.savefig(OUT / "benchmark_throughput.png", dpi=150); plt.close()
