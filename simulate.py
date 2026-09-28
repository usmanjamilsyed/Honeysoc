"""Offline demonstration of the supplied HoneySOC hash-chain algorithm."""
import hashlib
import json
from copy import deepcopy

GENESIS = hashlib.sha256(b"HoneySOC_Genesis_Block").hexdigest()


def digest(event, previous):
    return hashlib.sha256((json.dumps(event, sort_keys=True) + previous).encode()).hexdigest()


def verify(chain):
    previous = GENESIS
    for block in chain:
        if block["previous_hash"] != previous:
            return False
        if block["hash"] != digest(block["event"], previous):
            return False
        previous = block["hash"]
    return True


def main():
    chain = []
    previous = GENESIS
    for i in range(100):
        event = {"event_id": i, "attack_type": "SQL_Injection", "attacker_ip": "192.0.2.10", "timestamp": i}
        current = digest(event, previous)
        chain.append({"event": event, "previous_hash": previous, "hash": current})
        previous = current
    original_valid = verify(chain)
    tampered = deepcopy(chain)
    tampered[50]["event"]["attack_type"] = "modified"
    tampering_detected = not verify(tampered)
    reordered = deepcopy(chain)
    reordered[10], reordered[11] = reordered[11], reordered[10]
    reordering_detected = not verify(reordered)
    assert original_valid and tampering_detected and reordering_detected
    print(json.dumps({"events": len(chain), "original_valid": original_valid,
                      "tampering_detected": tampering_detected,
                      "reordering_detected": reordering_detected}, indent=2))


if __name__ == "__main__":
    main()
