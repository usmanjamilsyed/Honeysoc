import redis
import json
import hashlib

from redis_config import create_client

r = create_client()

print("HoneySOC Secure Engine Online. Initializing Hash Chain...")

# The Genesis Hash (The starting point for our cryptographic chain)
previous_hash = hashlib.sha256(b"HoneySOC_Genesis_Block").hexdigest()

while True:
    try:
        # Pull logs from the queue
        log_data = r.brpop('soc_queue', timeout=5)
        
        if log_data:
            queue_name, data = log_data
            parsed_log = json.loads(data.decode('utf-8'))
            
            # --- CRYPTOGRAPHIC HASH CHAIN LOGIC ---
            # 1. Combine current log data with the PREVIOUS hash
            log_string = json.dumps(parsed_log, sort_keys=True)
            chain_data = log_string + previous_hash
            
            # 2. Generate the NEW hash for this specific log
            current_hash = hashlib.sha256(chain_data.encode('utf-8')).hexdigest()
            
            # 3. Display the locked log
            print(f"\n[+] LATCHED: {parsed_log['attack_type']} from {parsed_log['attacker_ip']}")
            print(f"    [-] Prev Link : {previous_hash[:20]}...")
            print(f"    [-] Curr Link : {current_hash[:20]}...")
            
            # 4. Update the previous hash for the next loop (The Chain effect)
            previous_hash = current_hash
            
        else:
            print("Queue is empty, waiting for new attacks...")
            
    except KeyboardInterrupt:
        print("\nEngine stopped by user.")
        break
