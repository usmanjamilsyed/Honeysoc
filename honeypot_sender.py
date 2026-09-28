import redis
import time
import json

from redis_config import create_client

r = create_client()

print("Honeypot Started. Streaming logs to HoneySOC...")

# Simulating high-speed attacks hitting your honeypot
for i in range(1, 101):
    log_entry = {
        "event_id": i,
        "attack_type": "SQL_Injection",
        "attacker_ip": f"192.168.1.{i}",
        "timestamp": time.time()
    }
    # Push log into the Redis queue named 'soc_queue'
    r.lpush('soc_queue', json.dumps(log_entry))
    print(f"Sent Log {i}")
    time.sleep(0.1) # Simulating fast attacks
