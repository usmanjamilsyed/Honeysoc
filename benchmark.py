import time
import json
import hashlib

print("Starting HoneySOC Performance Benchmark...")
logs_to_process = 10000

# A standard honeypot log payload
dummy_log = {
    "event_id": 99, 
    "attack_type": "SQL_Injection", 
    "attacker_ip": "192.168.1.100",
    "timestamp": "2026-06-28T12:00:00Z"
}

# The Genesis Block
previous_hash = hashlib.sha256(b"HoneySOC_Genesis_Block").hexdigest()

# Start the high-speed timer
start_time = time.time()

# Push 10,000 logs through the cryptographic chain
for i in range(logs_to_process):
    dummy_log["event_id"] = i
    log_string = json.dumps(dummy_log, sort_keys=True)
    chain_data = log_string + previous_hash
    current_hash = hashlib.sha256(chain_data.encode('utf-8')).hexdigest()
    previous_hash = current_hash

# Stop the timer
end_time = time.time()

# Calculate the scientific metrics
total_time = end_time - start_time
eps = logs_to_process / total_time
latency_ms = (total_time / logs_to_process) * 1000

print(f"\n--- ACADEMIC BENCHMARK RESULTS ---")
print(f"Total Logs Processed : {logs_to_process:,}")
print(f"Total Time Taken     : {total_time:.4f} seconds")
print(f"Throughput (EPS)     : {eps:,.2f} Events Per Second")
print(f"Avg Latency per Log  : {latency_ms:.4f} milliseconds")
